/*
 * Copyright (c) 2014-2015, The Regents of the University of California
 * Copyright (c) 2015-2016 Immunant Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the University of California nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "OS.h"
#include "TrapInfo.h"

#include <stdint.h>
#include <stdarg.h>
#include <utility>

#ifndef SR_FUNCTION_PRESERVE_ALIGN
#define SR_FUNCTION_PRESERVE_ALIGN 2
#endif

#pragma pack(1) // TODO: MSVC-only; use gcc equivalent on Linux
struct RANDO_SECTION Function {
    os::BytePointer undiv_start, div_start;
    size_t size, shuffle_index;
    bool skip_copy;

    ptrdiff_t div_delta() const {
        return div_start - undiv_start;
    }

    os::BytePointer inline undiv_end() const {
        return undiv_start + size;
    }

    os::BytePointer inline div_end() const {
        return div_start + size;
    }

    bool undiv_contains(os::BytePointer addr) const {
        return addr >= undiv_start && addr < undiv_end();
    }

    bool div_contains(os::BytePointer addr) const {
        return addr >= div_start && addr < div_end();
    }

    os::BytePointer post_div_address(os::BytePointer addr, bool allow_overflow = false) const {
        RANDO_ASSERT(allow_overflow || undiv_contains(addr));
        return (addr + div_delta());
    }
};

class RANDO_SECTION ExecSectionProcessor {
public:
    ExecSectionProcessor(const os::Module &mod,
                         const os::Module::Section &exec_section,
                         TrapInfo &trap_info,
                         bool in_place)
                         : m_module(mod), m_exec_section(exec_section),
                           m_trap_info(trap_info), m_in_place(in_place) {
        os::API::DebugPrintf<1>("Found exec section @%p[%u]\n",
                                m_exec_section.start().to_ptr(), m_exec_section.size());
        skip_shuffle = getenv("SELFRANDO_skip_shuffle") != nullptr;
        if (skip_shuffle) {
            os::API::DebugPrintf<1>("Selfrando: warning: applying identity transformation. No real protection!\n");
        }
    }

    void Run() {
        // FIXME: in non-profiling runs, GetTime shouldn't cost any CPU cycles
        auto t1 = os::API::GetTime();
        CountFunctions();
        auto t2 = os::API::GetTime();
        BuildFunctions();
        // Optimization: if only one function, skip shuffling
        if (m_num_funcs > 1) {
            auto t3 = os::API::GetTime();
            SortFunctions();
            auto t4 = os::API::GetTime();
            ShuffleFunctions();
            auto t5 = os::API::GetTime();
            ShuffleCode();
        }
        auto t6 = os::API::GetTime();
        FixupRelocations();
        auto t7 = os::API::GetTime();
        ProcessTrapRelocations();
        auto t8 = os::API::GetTime();
        FixupExports();
        auto t9 = os::API::GetTime();
#if 0 // FIXME
#define PRINT_TIME(func, from, to)  DebugPrintf<1>("Module@%p time " #func ":%lldus\n", m_module, os::API::TimeDeltaMicroSec((from), (to)))
        PRINT_TIME(CountFunctions,   t1, t2);
        PRINT_TIME(BuildFunctions,   t2, t3);
        PRINT_TIME(SortFunctions,    t3, t4);
        PRINT_TIME(ShuffleFunctions, t4, t5);
        PRINT_TIME(ShuffleCode,      t5, t6);
        PRINT_TIME(FixupRelocations, t6, t7);
        PRINT_TIME(ProcessTrapRelocations, t7, t8);
        PRINT_TIME(FixupExports,     t8, t9);
        PRINT_TIME(Total,            t1, t9);
#undef PRINT_TIME
#endif

        // Cleanup
        // TODO: this should be in a separate function
        if (m_in_place) {
            // We're doing in-place randomization, so release the copy
            os::API::MemUnmap(m_exec_copy, m_exec_section.size(), true);
        } else {
            // Not in-place, so we need to keep the copy, so map it as executable
            os::API::MemProtect(m_exec_copy, m_exec_section.size(), os::PagePermissions::RX);
            os::API::DebugPrintf<1>("Divcode@%p\n", m_exec_copy);
        }
        os::API::MemFree(m_functions);
        os::API::MemFree(m_shuffled_order);
        m_module.LFEnd();
    }

private:
    const os::Module &m_module;
    const os::Module::Section &m_exec_section;
    TrapInfo &m_trap_info;
    bool m_in_place;

    os::BytePointer m_exec_copy;

    size_t m_num_funcs;
    bool m_func_at_start;
    Function *m_functions;
    size_t *m_shuffled_order;

    bool skip_shuffle;

    Function *FindFunction(os::BytePointer);

    void CountFunctions();
    void BuildFunctions();
    void SortFunctions();
    void ShuffleFunctions();
    void ShuffleCode();
    void FixupRelocations();
    void ProcessTrapRelocations();
    void FixupExports();

    static void AdjustRelocation(os::Module::Relocation &reloc,
                                 void *callback_arg);

    // Whether to put a pseudo-function at offset 0 in the section (at its start)
    bool needs_start_function() {
        return !m_func_at_start && m_in_place;
    }
};

void ExecSectionProcessor::CountFunctions() {
    m_num_funcs = 0;
    m_func_at_start = false;
    for (auto trap_entry : m_trap_info) {
        auto entry_addr = m_module.address_from_trap(trap_entry.base_address());
        if (m_exec_section.contains_addr(entry_addr)) {
            for (auto sym : trap_entry.symbols()) {
                if (m_module.address_from_trap(sym.address) == m_exec_section.start())
                    m_func_at_start = true;
                m_num_funcs++;
            }
        }
    }
    // If no TRaP function starts at the beginning of the section, we add our own pseudo-function
    // spanning from the beginning of the section to the first proper TRaP function
    if (needs_start_function())
        m_num_funcs++;
    os::API::DebugPrintf<1>("Trap functions: %d\n", m_num_funcs);
}

void ExecSectionProcessor::BuildFunctions() {
    m_functions = reinterpret_cast<Function*>(os::API::MemAlloc(m_num_funcs * sizeof(Function), true));
    auto func_idx = 0;
    for (auto trap_entry : m_trap_info) {
        auto entry_addr = m_module.address_from_trap(trap_entry.base_address());
        if (m_exec_section.contains_addr(entry_addr)) {
            for (auto sym : trap_entry.symbols()) {
                auto start_addr = m_module.address_from_trap(sym.address).to_ptr();
                if (m_trap_info.addn_info().should_be_ignored((void*) sym.address)) {
                    os::API::DebugPrintf<3>("Ignoring padding function at %p\n", start_addr);
                    m_functions[func_idx].skip_copy = true;
                } else {
                    m_functions[func_idx].skip_copy = false;
                }
                m_functions[func_idx].undiv_start = start_addr;
                if (m_trap_info.header()->symbol_sizes()) {
                    RANDO_ASSERT(sym.size > 0);
                    m_functions[func_idx].size = sym.size;
                }
                func_idx++;
            }
        }
    }
    if (needs_start_function()) {
        RANDO_ASSERT(!m_trap_info.header()->symbol_sizes());
        m_functions[func_idx++].undiv_start = m_exec_section.start().to_ptr();
    }
    RANDO_ASSERT(func_idx == m_num_funcs);
}

template<typename T>
static inline RANDO_SECTION int CompareIntegers(T a, T b) {
  return (a < b) ? -1 : ((a == b) ? 0 : 1);
}

static RANDO_SECTION int CompareFunctions(const void *a, const void *b) {
    auto fa = reinterpret_cast<const Function*>(a);
    auto fb = reinterpret_cast<const Function*>(b);
    return CompareIntegers(fa->undiv_start, fb->undiv_start);
}

void ExecSectionProcessor::SortFunctions() {
    // Sort by undiversified addresses
    // FIXME: use our own qsort function, or force use of NTDLL!qsort
    if (m_trap_info.header()->needs_sort())
        os::API::QuickSort(m_functions, m_num_funcs, sizeof(Function), CompareFunctions);
    if (!m_trap_info.header()->symbol_sizes()) {
        auto exec_end = m_exec_section.end().to_ptr();
        for (size_t i = 0; i < m_num_funcs; i++) {
            auto next_start = (i == (m_num_funcs - 1)) ? exec_end : m_functions[i + 1].undiv_start;
            m_functions[i].size = next_start - m_functions[i].undiv_start;
        }
    }
}

void ExecSectionProcessor::ShuffleFunctions() {
    // Shuffle the order of the functions, using a Fisher-Yates shuffle
    m_shuffled_order = reinterpret_cast<size_t*>(os::API::MemAlloc(m_num_funcs * sizeof(size_t)));
    for (size_t i = 0; i < m_num_funcs; i++)
        m_shuffled_order[i] = i;
    for (size_t i = 0; i < m_num_funcs - 1; i++) {
        // Pick shuffled_order[i] at random from the remaining elements
        auto j = os::API::GetRandom(m_num_funcs - i);
        if (skip_shuffle) j = 0;
        if (j == 0) {
            m_functions[m_shuffled_order[i]].shuffle_index = i;
            continue;
        }
        // Swap [i] with [i + j]
        auto t = m_shuffled_order[i + j];
        m_shuffled_order[i + j] = m_shuffled_order[i];
        m_shuffled_order[i] = t; // Past this point, t stays in shuffled_order[i]
        m_functions[t].shuffle_index = i;
    }
}

static inline RANDO_SECTION void PatchInTrampoline(os::BytePointer at, os::BytePointer to) {
    // We add the MOV EDI, EDI here to support hot-patching
    // FIXME: only really need this on Windows
    *at++ = 0x8B; // MOV EDI, EDI
    *at++ = 0xFF;
    *at++ = 0xE9; // JMP <pcrel>
    auto call_delta_ptr = reinterpret_cast<int32_t*>(at);
    *call_delta_ptr = static_cast<int32_t>(to - (at + 4));
}

void ExecSectionProcessor::ShuffleCode() {
    // Copy the code to a backup
    // FIXME: randomize the base address manually
    auto orig_code = m_exec_section.start().to_ptr();
    m_exec_copy = reinterpret_cast<os::BytePointer>(os::API::MemMap(nullptr, m_exec_section.size(), os::PagePermissions::RW, true));
    auto copy_delta = m_exec_copy - orig_code;
    auto curr_addr = m_exec_copy;
    for (size_t i = 0; i < m_num_funcs; i++) {
        auto si = m_shuffled_order[i];
        auto &func = m_functions[si];
        if (func.skip_copy) continue;
        // TODO: handle 5-NOP padding between consecutive functions
        while ((size_t) curr_addr % SR_FUNCTION_PRESERVE_ALIGN !=
                (size_t) func.undiv_start % SR_FUNCTION_PRESERVE_ALIGN) {
            *curr_addr = 0x90;
            curr_addr++;
        }
        func.div_start = curr_addr;
        os::API::DebugPrintf<3>("Moving %p[%d]=>%p@%p\n",
            func.undiv_start, func.size,
            func.div_start - copy_delta, func.div_start);
        m_module.LFWriteRandomizationRecord(func.undiv_start,
                                            func.div_start - copy_delta, (uint32_t) func.size);
        os::API::MemCpy(curr_addr, func.undiv_start, func.size);
        curr_addr += func.size;
        RANDO_ASSERT(curr_addr - m_exec_copy <= m_exec_section.size());
    }
    if (m_in_place) {
        os::API::MemCpy(orig_code, m_exec_copy, m_exec_section.size());
        os::API::DebugPrintf<3>("Copying code back %p[%u]=>%p\n",
                                m_exec_copy, m_exec_section.size(), orig_code);
        // Revert the div_start addresses to the original section
        for (size_t i = 0; i < m_num_funcs; i++)
            m_functions[i].div_start -= copy_delta;
    } else {
        for (size_t i = 0; i < m_num_funcs; i++) {
            auto &func = m_functions[i];
            if (func.size < 7) {
                os::API::DebugPrintf<2>("Smallfunc@%p[%d]\n", func.undiv_start, func.size);
                continue;
            }
            // FIXME: this could create a race condition
            // FIXME: probably better to do this as the final step
            size_t ofs = 0;
            // TODO: optimize this to use memset()
            for (size_t ofs = 0; ofs < func.size; ofs++)
                func.undiv_start[ofs] = 0xCC; // INT 3 (trap)
            // We skip this for functions whose addresses aren't taken
            if (!m_trap_info.header()->has_data_refs())
                PatchInTrampoline(func.undiv_start, func.div_start);
        }
        if (m_trap_info.header()->has_data_refs()) {
            for (auto trap_entry : m_trap_info) {
                auto entry_addr = m_module.address_from_trap(trap_entry.base_address());
                if (m_exec_section.contains_addr(entry_addr)) {
                    for (auto ref : trap_entry.data_refs()) {
                        auto ref_addr = m_module.address_from_trap(ref).to_ptr();
                        auto ref_func = FindFunction(ref_addr);
                        if (ref_func->undiv_contains(ref_addr))
                            PatchInTrampoline(ref_addr, ref_addr + ref_func->div_delta());
                    }
                }
            }
        }
    }
}

// Binary search function that finds function containing given address
Function *ExecSectionProcessor::FindFunction(os::BytePointer addr) {
    // return null if no function contains addr
    if (addr < m_functions[0].undiv_start || addr >= m_functions[m_num_funcs-1].undiv_end())
        return nullptr;
    size_t lo = 0, hi = m_num_funcs - 1;
    while (lo < hi) {
        auto mid = lo + ((hi - lo) >> 1);
        if (addr >= m_functions[mid + 1].undiv_start) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return &m_functions[lo];
}

// TODO(performance): would be nice to turn reloc_type into a template parameter
// FIXME: this also needs a refactoring into ArchX86 (to support ArchARM later or others)
void ExecSectionProcessor::AdjustRelocation(os::Module::Relocation &reloc,
                                            void *callback_arg) {
    auto esp = reinterpret_cast<ExecSectionProcessor*>(callback_arg);
    bool at_exec = false;
    auto at_ptr = reloc.get_source_ptr();
    static_assert(sizeof(*at_ptr) == 1, "Byte size not 8 bits");
    // Update the "at" address if it falls inside a diversified function
    if (esp->m_exec_section.contains_addr(reloc.get_source_address())) {
        auto func_at = esp->FindFunction(at_ptr);
        at_ptr = func_at->post_div_address(at_ptr);
        at_exec = true;
        reloc.set_source_ptr(at_ptr);
    }
    // Get target address
    os::BytePointer target_ptr = reloc.get_target_ptr();
    os::API::DebugPrintf<5>("Reloc[%2d]@%p/%p=>%p\n", reloc.get_type(),
                            reloc.get_original_source_address().to_ptr(),
                            at_ptr, target_ptr);
    // Check if either source or target addresses fall inside our section
    // If not, then we really don't care about this relocation
    // TODO: we could do better: relocation could be inside exec_section
    // but outside a diversified function; we could also ignore that one
    if (!at_exec && !esp->m_exec_section.contains_addr(target_ptr))
        return;
    // Compute new target address
    auto target_func = esp->FindFunction(target_ptr);
    if (reloc.get_addend() > 0 && target_func) {
        auto target_sym = esp->FindFunction(target_ptr - reloc.get_addend());
        if (target_sym && target_func != target_sym) {
            target_ptr = target_sym->post_div_address(target_ptr, /*allow_overflow*/ true);
            os::API::DebugPrintf<5>(" -> overflow (%p[%d] != %p[%d]); => %p\n",
                                    target_func->undiv_start, target_func->size,
                                    target_sym->undiv_start, target_sym->size, target_ptr);
            reloc.set_target_ptr(target_ptr);
            return;
        }
    }
    target_ptr = target_func ? target_func->post_div_address(target_ptr) : target_ptr;
    // os::API::DebugPrintf<5>("\x1b[A\t\t\t\t\t==>%p\n", target_ptr);
    // Update the relocation entry
    reloc.set_target_ptr(target_ptr);
}

void ExecSectionProcessor::FixupRelocations() {
    if (m_trap_info.header()->has_got_data()) {
        // FIXME(performance): this is pretty slow (profile confirms it)
        m_module.ForAllRelocations(m_trap_info.addn_info().got_start_end(), AdjustRelocation, this);
    } else {
        // FIXME(performance): this is pretty slow (profile confirms it)
        m_module.ForAllRelocations(AdjustRelocation, this);
    }
}

void ExecSectionProcessor::ProcessTrapRelocations() {
    if (m_trap_info.header()->has_nonexec_relocs()) {
        auto nonexec_relocs = m_trap_info.addn_info().nonexec_relocations();
        for (auto trap_reloc : nonexec_relocs) {
            auto reloc = os::Module::Relocation(m_module, trap_reloc, /* exec */ false);
            AdjustRelocation(reloc, this);
        }
    }
    for (auto trap_entry : m_trap_info) {
        auto relocs = trap_entry.relocations();
        for (auto trap_reloc : relocs) {
            auto reloc = os::Module::Relocation(m_module, trap_reloc, /* exec */ true);
            AdjustRelocation(reloc, this);
        }
    }
}

void ExecSectionProcessor::FixupExports() {
    // FIXME: these should either be in regular relocs, or in Trap info
    auto export_section = m_module.export_section();
    if (export_section.empty())
        return;

    // Fixup trampolines in .xptramp section (if included)
    auto export_start = export_section.start().to_ptr();
    auto export_end = export_section.end().to_ptr();
    for (auto export_ptr = export_start; export_ptr < export_end;)
        os::Module::Relocation::fixup_export_trampoline(&export_ptr,
                                                        m_module,
                                                        AdjustRelocation,
                                                        this);
}

static RANDO_SECTION void RandomizeExecSection(const os::Module &mod,
                                               const os::Module::Section &sec,
                                               TrapInfo &trap_info,
                                               bool in_place, void *arg) {
    ExecSectionProcessor esp(mod, sec, trap_info, in_place);
    esp.Run();
}

static RANDO_SECTION void RandomizeModule(os::Module &mod2, void *arg) {
    mod2.ForAllExecSections(false, RandomizeExecSection, nullptr);
}

extern "C"
RANDO_SECTION void _TRaP_RandoMain(os::Module::Handle asm_module) {
    os::API::Init();
    os::Module mod(asm_module);
    // For every section in the current program...
    mod.ForAllExecSections(true, RandomizeExecSection, nullptr);
    os::Module::ForAllModules(RandomizeModule, nullptr);
    // FIXME: we could make .rndtext non-executable here
    os::API::Finish();
}
