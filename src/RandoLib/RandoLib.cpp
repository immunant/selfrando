/*
 * Copyright (c) 2014-2015, The Regents of the University of California
 * Copyright (c) 2015-2017 Immunant Inc.
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

#include <OS.h>
#include <RandoLib.h>
#include <TrapInfo.h>

#include <stdint.h>
#include <stdarg.h>

// Binary search function that finds function containing given address
// TODO: move this to a separate .cpp file???
Function *FunctionList::FindFunction(os::BytePointer addr) {
    // return null if no function contains addr
    if (addr < functions[0].undiv_start ||
        addr >= functions[num_funcs-1].undiv_end())
        return nullptr;
    size_t lo = 0, hi = num_funcs - 1;
    while (lo < hi) {
        auto mid = lo + ((hi - lo) >> 1);
        if (addr >= functions[mid + 1].undiv_start) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return &functions[lo];
}

#if RANDOLIB_MEASURE_TIME
class RANDO_SECTION FunctionCallTimer {
public:
    FunctionCallTimer() : m_start_time(os::API::GetTime()) { }

    void print_duration(const char *call_name) {
        auto end_time = os::API::GetTime();
        auto duration = os::API::TimeDeltaMicroSec(m_start_time, end_time);
        os::API::DebugPrintf<1>("Step %s time:%lldus\n", call_name, duration);
    }

private:
    os::Time m_start_time;
};
#define TIME_FUNCTION_CALL(func, ...)    do { FunctionCallTimer tk; func(__VA_ARGS__); tk.print_duration( #func );  } while (0)
#else
#define TIME_FUNCTION_CALL(func, ...)    do { func(__VA_ARGS__);  } while (0)
#endif

class RANDO_SECTION ExecSectionProcessor {
public:
    ExecSectionProcessor(const os::Module &mod,
                         const os::Module::Section &exec_section,
                         TrapInfo &trap_info,
                         bool in_place)
                         : m_module(mod), m_exec_section(exec_section),
                           m_trap_info(trap_info), m_in_place(in_place),
                           m_exec_copy(nullptr), m_exec_code_size(0),
                           m_shuffled_order(nullptr) {
        os::API::DebugPrintf<1>("Found exec section @%p[%u]\n",
                                m_exec_section.start().to_ptr(), m_exec_section.size());
    }

    void Run() {
        for (auto trap_entry : m_trap_info)
            trap_entry.dump();

        TIME_FUNCTION_CALL(CountFunctions);
        TIME_FUNCTION_CALL(BuildFunctions);
        // Optimization: if only one function, skip shuffling
        if (m_functions.num_funcs > 1) {
            TIME_FUNCTION_CALL(SortFunctions);
            TIME_FUNCTION_CALL(RemoveEmptyFunctions);
            TIME_FUNCTION_CALL(CoverGaps);
            TIME_FUNCTION_CALL(ShuffleFunctions);
            TIME_FUNCTION_CALL(LayoutCode);
            TIME_FUNCTION_CALL(ShuffleCode);
        }
        TIME_FUNCTION_CALL(FixupRelocations);
        TIME_FUNCTION_CALL(ProcessTrapRelocations);
        TIME_FUNCTION_CALL(FixupExports);

#if RANDOLIB_WRITE_LAYOUTS
        m_module.write_layout_file(&m_functions, m_shuffled_order);
#endif

        // Cleanup
        // TODO: this should be in a separate function
        if (m_exec_copy != nullptr) {
            if (m_in_place) {
                // We're doing in-place randomization, so release the copy
                os::API::MemUnmap(m_exec_copy, m_exec_code_size, true);
            } else {
                // Not in-place, so we need to keep the copy, so map it as executable
                os::API::MemProtect(m_exec_copy, m_exec_code_size, os::PagePermissions::RX);
            }
        }
        if (m_shuffled_order != nullptr)
            os::API::MemFree(m_shuffled_order);
        m_functions.free();
    }

private:
    const os::Module &m_module;
    const os::Module::Section &m_exec_section;
    TrapInfo &m_trap_info;
    bool m_in_place;

    os::BytePointer m_exec_copy;
    size_t m_exec_code_size;

    FunctionList m_functions;
    size_t *m_shuffled_order;

    template<typename FunctionPredicate>
    void IterateTrapFunctions(FunctionPredicate);

    template<typename GapPredicate>
    void IterateFunctionGaps(GapPredicate);

    void CountFunctions();
    void BuildFunctions();
    void SortFunctions();
    void CoverGaps();
    void RemoveEmptyFunctions();
    void ShuffleFunctions();
    void LayoutCode();
    void ShuffleCode();
    void FixupRelocations();
    void ProcessTrapRelocations();
    void FixupExports();

    static void AdjustRelocation(os::Module::Relocation &reloc,
                                 void *callback_arg);

};

template<typename FunctionPredicate>
RANDO_ALWAYS_INLINE
void ExecSectionProcessor::IterateTrapFunctions(FunctionPredicate pred) {
    for (auto trap_entry : m_trap_info) {
        auto entry_addr = m_module.address_from_trap(trap_entry.base_address());
        if (m_exec_section.contains_addr(entry_addr)) {
            for (auto sym : trap_entry.symbols()) {
                auto start_addr = m_module.address_from_trap(sym.address).to_ptr();
#if RANDOLIB_IS_ARM
                if ((uint32_t) start_addr & 1 == 1) {
                    // This is a thumb function that actually starts one byte earlier
                    start_addr--;
                }
#endif
                Function new_func = {};
                new_func.undiv_start = start_addr;
                new_func.skip_copy = false;
                new_func.from_trap = true;
                if (m_trap_info.header()->has_symbol_p2align()) {
                    new_func.undiv_alignment = sym.alignment;
                } else {
                    new_func.undiv_alignment = os::API::kFunctionAlignment;
                }
                if (m_trap_info.header()->has_symbol_size()) {
                    RANDO_ASSERT(sym.size > 0);
                    new_func.has_size = true;
                    new_func.size = sym.size;
                }
                pred(new_func);
            }
            if (m_trap_info.header()->has_record_padding() && trap_entry.padding_size() > 0) {
                Function new_func = {};
                // Add the padding as skip_copy
                new_func.skip_copy = true;
                new_func.is_padding = true;
                new_func.undiv_start =
                    m_module.address_from_trap(trap_entry.padding_address()).to_ptr();
                new_func.undiv_alignment = 1;
                new_func.has_size = true;
                new_func.size = trap_entry.padding_size();
                pred(new_func);
            }
        }
    }
}

void ExecSectionProcessor::CountFunctions() {
    m_functions.num_funcs = 0;
    IterateTrapFunctions([this] (const Function &new_func) {
        m_functions.num_funcs++;
        return true;
    });
    os::API::DebugPrintf<1>("Trap functions: %d\n", m_functions.num_funcs);
}

void ExecSectionProcessor::BuildFunctions() {
    m_functions.allocate();
    size_t func_idx = 0;
    IterateTrapFunctions([this, &func_idx] (const Function &new_func) {
        m_functions.functions[func_idx++] = new_func;
        return true;
    });
    RANDO_ASSERT(func_idx == m_functions.num_funcs);
}

template<typename T>
static inline RANDO_SECTION int CompareIntegers(T a, T b) {
  return (a < b) ? -1 : ((a == b) ? 0 : 1);
}

static RANDO_SECTION int CompareFunctions(const void *a, const void *b) {
    auto fa = reinterpret_cast<const Function*>(a);
    auto fb = reinterpret_cast<const Function*>(b);
    // Special case: put skip_copy before non-skip_copy,
    // so we can correctly compute the sizes
    if (fa->undiv_start == fb->undiv_start)
        return CompareIntegers(fa->sort_rank(), fb->sort_rank());
    return CompareIntegers(fa->undiv_start, fb->undiv_start);
}

void ExecSectionProcessor::SortFunctions() {
    // Sort by undiversified addresses
    // FIXME: use our own qsort function, or force use of NTDLL!qsort
    if (m_trap_info.header()->needs_sort())
        os::API::QuickSort(m_functions.functions, m_functions.num_funcs, sizeof(Function), CompareFunctions);
    // Build sizes for functions
    auto exec_end = m_exec_section.end().to_ptr();
    for (size_t i = 0; i < m_functions.num_funcs; i++) {
        if (m_functions[i].has_size)
            continue;
        auto next_start = (i == (m_functions.num_funcs - 1)) ? exec_end : m_functions[i + 1].undiv_start;
        m_functions[i].has_size = true;
        m_functions[i].size = next_start - m_functions[i].undiv_start;
    }
}

void ExecSectionProcessor::RemoveEmptyFunctions() {
    size_t cnt = 0;
    for (size_t i = 0; i < m_functions.num_funcs; i++) {
        RANDO_ASSERT(m_functions[i].has_size);
        if (m_functions[i].size == 0)
            continue;
        if (cnt < i)
            m_functions[cnt] = m_functions[i];
        cnt++;
    }
    os::API::DebugPrintf<1>("Removed %d empty functions\n",
                            m_functions.num_funcs - cnt);
    m_functions.num_funcs = cnt;
}

template<typename GapPredicate>
RANDO_ALWAYS_INLINE
void ExecSectionProcessor::IterateFunctionGaps(GapPredicate pred) {
    auto last_addr = m_exec_section.start().to_ptr();
    for (size_t i = 0; i < m_functions.num_funcs; i++) {
        if (m_functions[i].is_gap)
            return; // We're currently adding gaps, and we reached the first one
        RANDO_ASSERT(m_functions[i].undiv_start >= last_addr);
        if (m_functions[i].undiv_start > last_addr)
            pred(last_addr, m_functions[i].undiv_start);
        last_addr = m_functions[i].undiv_end();
    }
    auto exec_end = m_exec_section.end().to_ptr();
    RANDO_ASSERT(exec_end >= last_addr);
    if (exec_end > last_addr)
        pred(last_addr, exec_end);
}

void ExecSectionProcessor::CoverGaps() {
    // We only care about gaps in in-place mode, we can ignore them otherwise
    // FIXME: maybe we do???
    if (!m_in_place)
        return;

    size_t num_gaps = 0;
    IterateFunctionGaps([this, &num_gaps] (os::BytePointer gap_start, os::BytePointer gap_end) {
        RANDO_ASSERT(gap_start < gap_end);
        num_gaps++;
        os::API::DebugPrintf<10>("Found gap:%p-%p\n", gap_start, gap_end);
    });
    if (num_gaps == 0)
        return;

    os::API::DebugPrintf<2>("Trap gaps: %d\n", num_gaps);
    m_functions.extend(num_gaps);
    size_t gap_idx = m_functions.num_funcs - num_gaps;
    IterateFunctionGaps([this, &gap_idx] (os::BytePointer gap_start, os::BytePointer gap_end) {
        m_functions[gap_idx].undiv_start = gap_start;
        m_functions[gap_idx].size = gap_end - gap_start;
        m_functions[gap_idx].undiv_alignment = 1;
        m_functions[gap_idx].is_gap = true;
        m_functions[gap_idx].has_size = true;
        gap_idx++;
    });
    RANDO_ASSERT(gap_idx == m_functions.num_funcs);
    // We need to re-sort the functions after adding the gaps at the end
    os::API::QuickSort(m_functions.functions, m_functions.num_funcs, sizeof(Function), CompareFunctions);
}

void ExecSectionProcessor::ShuffleFunctions() {
    bool skip_shuffle = os::API::GetEnv("SELFRANDO_skip_shuffle") != nullptr;
    // FIXME: it would be nice to only disable shuffling
    // when the variable is set to "1" or "true"
    if (skip_shuffle) {
        os::API::DebugPrintf<1>("Selfrando: warning: applying identity transformation. No real protection!\n");
    }

    // Shuffle the order of the functions, using a Fisher-Yates shuffle
    m_shuffled_order = reinterpret_cast<size_t*>(os::API::MemAlloc(m_functions.num_funcs * sizeof(size_t)));
    for (size_t i = 0; i < m_functions.num_funcs; i++)
        m_shuffled_order[i] = i;
    for (size_t i = 0; i < m_functions.num_funcs - 1; i++) {
        // Pick shuffled_order[i] at random from the remaining elements
        auto j = skip_shuffle ? 0 : os::API::GetRandom(m_functions.num_funcs - i);
        if (j == 0) {
            continue;
        }
        // Swap [i] with [i + j]
        auto t = m_shuffled_order[i + j];
        m_shuffled_order[i + j] = m_shuffled_order[i];
        m_shuffled_order[i] = t; // Past this point, t stays in shuffled_order[i]
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

void ExecSectionProcessor::LayoutCode() {
    auto orig_code = m_exec_section.start().to_ptr();
    auto curr_addr = orig_code;
    for (size_t i = 0; i < m_functions.num_funcs; i++) {
        auto si = m_shuffled_order[i];
        auto &func = m_functions[si];
        if (func.skip_copy) continue;

        // Align functions to either a multiple of kFunctionAlignment
        // or the same modulo as the undiversified code
        // (depending on kPreserveFunctionOffset)
        // TODO: handle 5-NOP padding between consecutive functions
        RANDO_ASSERT(func.undiv_alignment > 0);
        auto  old_ofs = (func.undiv_start - orig_code) & (func.undiv_alignment - 1);
        auto curr_ofs = (curr_addr - orig_code) & (func.undiv_alignment - 1);
        auto want_ofs = os::API::kPreserveFunctionOffset ? old_ofs : 0;
        if (curr_ofs != want_ofs) {
            func.alignment_padding = (func.undiv_alignment + want_ofs - curr_ofs) & (func.undiv_alignment - 1);
            curr_addr += func.alignment_padding;
        } else {
            func.alignment_padding = 0;
        }
        // TODO: also add in Windows-specific hot-patch trampolines
        func.div_start = curr_addr;
        curr_addr += func.size;
    }
    m_exec_code_size = curr_addr - orig_code;
    os::API::DebugPrintf<1>("Divcode size:%d\n", m_exec_code_size);

    // If we don't have enough room, we can't randomize in-place
    if (m_exec_code_size > m_exec_section.size()) {
        os::API::DebugPrintf<1>("Cannot randomize in place!\n");
        m_in_place = false;
    }
#if RANDOLIB_FORCE_INPLACE
    RANDO_ASSERT(m_in_place);
#endif
}

void ExecSectionProcessor::ShuffleCode() {
    // Copy the code to a backup
    // FIXME: randomize the base address manually
    auto orig_code = m_exec_section.start().to_ptr();
    if (m_in_place) {
        // If we're randomizing in-place, we don't care
        // where the copy is in memory, since we release
        // it shortly anyway
        auto copy_addr = os::API::MemMap(nullptr, m_exec_code_size,
                                         os::PagePermissions::RW, true);
        m_exec_copy = reinterpret_cast<os::BytePointer>(copy_addr);
    }
    else {
        do {
            // Pick a random address within 2GB of the original code
            // (this is required for 32-bit PC-relative relocations)
            auto start_ptr = orig_code + m_exec_section.size() + (os::kPageSize - 1);
            auto start_page = reinterpret_cast<uintptr_t>(start_ptr) >> os::kPageShift;
            // The copy is within (2GB - the size of the section), so that
            // a jump from the start of m_exec_data can reach
            // the end of m_exec_copy without overflowing
            auto max_copy_delta = (2U << 30) - m_exec_section.size();
            auto copy_page = start_page + os::API::GetRandom(max_copy_delta >> os::kPageShift);
            auto hint_addr = reinterpret_cast<void*>(copy_page << os::kPageShift);
            auto copy_addr = os::API::MemMap(hint_addr, m_exec_code_size,
                                             os::PagePermissions::RW, true);
            m_exec_copy = reinterpret_cast<os::BytePointer>(copy_addr);
        } while (m_exec_copy == nullptr);
    }
    os::API::DebugPrintf<1>("Divcode@%p\n", m_exec_copy);

    auto copy_delta = m_exec_copy - orig_code;
    for (size_t i = 0; i < m_functions.num_funcs; i++) {
        auto si = m_shuffled_order[i];
        auto &func = m_functions[si];
        if (func.skip_copy) continue;

        // TODO: also add in Windows-specific function hot-patch trampolines
        os::API::DebugPrintf<3>("Moving %p[%d]=>%p@%p\n",
            func.undiv_start, func.size,
            func.div_start, func.div_start + copy_delta);
        func.div_start += copy_delta;
        if (func.alignment_padding > 0)
            os::API::InsertNOPs(func.div_start - func.alignment_padding,
                                func.alignment_padding);
        os::API::MemCpy(func.div_start, func.undiv_start, func.size);
    }
    if (m_in_place) {
        os::API::DebugPrintf<3>("Copying code back %p[%u]=>%p\n",
                                m_exec_copy, m_exec_code_size, orig_code);
        os::API::MemCpy(orig_code, m_exec_copy, m_exec_code_size);
        // TODO: zero out the space left over
        // Revert the div_start addresses to the original section
        for (size_t i = 0; i < m_functions.num_funcs; i++)
            m_functions[i].div_start -= copy_delta;
    } else {
        for (size_t i = 0; i < m_functions.num_funcs; i++) {
#ifdef WIN32 // For now, we only replace the original code with CC's on Windows
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
#endif
        }
        if (m_trap_info.header()->has_data_refs()) {
            for (auto trap_entry : m_trap_info) {
                auto entry_addr = m_module.address_from_trap(trap_entry.base_address());
                if (m_exec_section.contains_addr(entry_addr)) {
                    for (auto ref : trap_entry.data_refs()) {
                        auto ref_addr = m_module.address_from_trap(ref).to_ptr();
                        auto ref_func = m_functions.FindFunction(ref_addr);
                        if (ref_func->undiv_contains(ref_addr))
                            PatchInTrampoline(ref_addr, ref_addr + ref_func->div_delta());
                    }
                }
            }
        }
    }
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
        auto func_at = esp->m_functions.FindFunction(at_ptr);
        at_ptr = func_at->post_div_address(at_ptr);
        at_exec = true;
        reloc.set_source_ptr(at_ptr);
    }
    // Get target address
    os::BytePointer target_ptr = reloc.get_target_ptr();
    os::API::DebugPrintf<5>("Reloc type %u @ %p/%p - orig contents: %x/%p => target: %p \n", reloc.get_type(),
                            reloc.get_original_source_address().to_ptr(),
                            at_ptr, *reinterpret_cast<uint32_t*>(at_ptr),
                            *reinterpret_cast<uintptr_t*>(at_ptr), target_ptr);
    // Check if either source or target addresses fall inside our section
    // If not, then we really don't care about this relocation
    // TODO: we could do better: relocation could be inside exec_section
    // but outside a diversified function; we could also ignore that one
    if (!at_exec && !esp->m_exec_section.contains_addr(target_ptr))
        return;
    // Compute new target address
    auto target_func = esp->m_functions.FindFunction(target_ptr);
    target_ptr = target_func ? target_func->post_div_address(target_ptr) : target_ptr;
    // Update the relocation entry
    os::API::DebugPrintf<6>("  setting => %p\n", target_ptr);
    reloc.set_target_ptr(target_ptr);
}

void ExecSectionProcessor::FixupRelocations() {
    // FIXME(performance): this is pretty slow (profile confirms it)
    m_module.ForAllRelocations(&m_functions, AdjustRelocation, this);
}

void ExecSectionProcessor::ProcessTrapRelocations() {
    if (m_trap_info.header()->has_nonexec_relocs()) {
        auto nonexec_relocs = m_trap_info.addn_info().nonexec_relocations();
        for (auto trap_reloc : nonexec_relocs) {
            auto reloc = os::Module::Relocation(m_module, trap_reloc);
            AdjustRelocation(reloc, this);
        }
    }
    for (auto trap_entry : m_trap_info) {
        auto relocs = trap_entry.relocations();
        for (auto trap_reloc : relocs) {
            auto reloc = os::Module::Relocation(m_module, trap_reloc);
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

RANDO_MAIN_FUNCTION() {
    os::API::Init();
    os::Module mod(asm_module);
    // For every section in the current program...
    mod.ForAllExecSections(true, RandomizeExecSection, nullptr);
    os::Module::ForAllModules(RandomizeModule, nullptr);
    // FIXME: we could make .rndtext non-executable here
    os::API::Finish();
}
