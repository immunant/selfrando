/*
 * Copyright (c) 2014-2015, The Regents of the University of California
 * Copyright (c) 2015-2019 RunSafe Security Inc.
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
Function *FunctionList::find_function(os::BytePointer addr) const {
    if (num_elems == 0)
        return nullptr;

    size_t lo = 0, hi = num_elems - 1;
    // return null if no function contains addr
    if (addr <  elems[lo].undiv_start ||
        addr >= elems[hi].undiv_end())
        return nullptr;
    while (lo <= hi) {
        auto mid = lo + ((hi - lo) >> 1);
        if (elems[mid].undiv_contains(addr)) {
            return &elems[mid];
        } else if (addr < elems[mid].undiv_start) {
            RANDO_ASSERT(mid > 0); // Due to the checks above, we should never get here with mid == 0
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return nullptr;
}

template<>
RANDO_SECTION void FunctionList::adjust_relocation(os::Module::Relocation *reloc) const {
    auto source_ptr = reloc->get_source_ptr();
    static_assert(sizeof(*source_ptr) == 1, "Byte size not 8 bits");
    // Update the "source" address if it falls inside a diversified function
    auto source_func = find_function(source_ptr);
    if (source_func != nullptr) {
        source_ptr = source_func->post_div_address(source_ptr);
        reloc->set_source_ptr(source_ptr);
    }

    // Get target address
    os::BytePointer target_ptr = reloc->get_target_ptr();
    os::API::debug_printf<5>("Reloc type %u @ %p/%p - orig contents: %x/%p => target: %p \n",
                             reloc->get_type(),
                             reloc->get_original_source_ptr(),
                             source_ptr, *reinterpret_cast<uint32_t*>(source_ptr),
                             *reinterpret_cast<uintptr_t*>(source_ptr), target_ptr);
    // Compute new target address
    auto target_func = find_function(target_ptr);
    // Check if either source or target addresses fall inside a moved function
    // If not, then we really don't care about this relocation
    if (source_func == nullptr && target_func == nullptr)
        return;
    if (target_func != nullptr)
        target_ptr = target_func->post_div_address(target_ptr);
    // Update the relocation entry
    os::API::debug_printf<6>("  setting => %p\n", target_ptr);
    reloc->set_target_ptr(target_ptr);
}

#if RANDOLIB_MEASURE_TIME
class RANDO_SECTION FunctionCallTimer {
public:
    FunctionCallTimer() : m_start_time(os::API::time()) { }

    void print_duration(const char *call_name) {
        auto end_time = os::API::time();
        auto duration = os::API::usec_between(m_start_time, end_time);
        os::API::debug_printf<1>("Step %s time:%dus\n", call_name, static_cast<int>(duration));
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
        os::API::debug_printf<1>("Found exec section @%p[%u]\n",
                                 m_exec_section.start().to_ptr(), m_exec_section.size());
    }

    void run() {
#if 0
        for (auto trap_entry : m_trap_info)
            trap_entry.dump();
#endif

        TIME_FUNCTION_CALL(count_functions);
        TIME_FUNCTION_CALL(build_functions);
        // Optimization: if only one function, skip shuffling
        if (m_functions.num_elems > 1) {
            TIME_FUNCTION_CALL(sort_functions);
            TIME_FUNCTION_CALL(compute_function_sizes);
            TIME_FUNCTION_CALL(trim_gaps);
            TIME_FUNCTION_CALL(remove_empty_functions);
            TIME_FUNCTION_CALL(shuffle_functions);
            TIME_FUNCTION_CALL(layout_code);
            TIME_FUNCTION_CALL(shuffle_code);
        }
        TIME_FUNCTION_CALL(fixup_relocations);
        TIME_FUNCTION_CALL(process_trap_relocations);
        TIME_FUNCTION_CALL(fixup_exports);
#if RANDOLIB_WRITE_LAYOUTS > 0
        TIME_FUNCTION_CALL(write_layout_file);
#endif

        // Cleanup
        // TODO: this should be in a separate function
        if (m_exec_copy != nullptr) {
            if (m_in_place) {
                // We're doing in-place randomization, so release the copy
                os::API::munmap(m_exec_copy, m_exec_code_size, true);
            } else {
                // Not in-place, so we need to keep the copy, so map it as executable
                os::API::mprotect(m_exec_copy, m_exec_code_size, os::PagePermissions::RX);
            }
        }
        if (m_shuffled_order != nullptr)
            os::API::mem_free(m_shuffled_order);
        m_functions.clear();
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

    void count_functions();
    void build_functions();
    void sort_functions();
    void compute_function_sizes();
    void remove_empty_functions();
    void trim_gaps();
    void shuffle_functions();
    void layout_code();
    void shuffle_code();
    void fixup_relocations();
    void process_trap_relocations();
    void fixup_exports();
#if RANDOLIB_WRITE_LAYOUTS > 0
    void write_layout_file();
#endif
};

template<typename FunctionPredicate>
RANDO_ALWAYS_INLINE
void ExecSectionProcessor::IterateTrapFunctions(FunctionPredicate pred) {
    for (auto trap_entry : m_trap_info) {
        auto entry_addr = os::Module::Address::from_trap(m_module, trap_entry.address);
        if (m_exec_section.contains_addr(entry_addr)) {
            for (auto sym : trap_entry.symbols()) {
                auto start_addr = os::Module::Address::from_trap(m_module, sym.address).to_ptr();
#if RANDOLIB_IS_ARM
                if (((uint32_t) start_addr & 1) == 1) {
                    // This is a thumb function that actually starts one byte earlier
                    start_addr--;
                }
#endif
                Function new_func = {};
                new_func.undiv_start = start_addr;
                new_func.skip_copy = false;
                new_func.from_trap = true;
                if (m_trap_info.header()->has_symbol_p2align()) {
                    RANDO_ASSERT(sym.p2align < 64); // 6-bit bitfield
                    new_func.undiv_p2align = sym.p2align;
                } else {
                    new_func.undiv_p2align = os::API::kFunctionP2Align;
                }
                if (m_trap_info.header()->has_symbol_size()) {
                    RANDO_ASSERT(sym.size > 0);
                    new_func.has_size = true;
                    new_func.size = os::API::assert_cast<size_t>(sym.size);

                    // Add a gap function for what comes after this sized symbol
                    Function gap_func = {};
                    gap_func.undiv_start = new_func.undiv_end();
                    gap_func.undiv_p2align = 0;
                    gap_func.skip_copy = false;
                    gap_func.from_trap = false;
                    gap_func.is_padding = false;
                    gap_func.is_gap = true;
                    gap_func.has_size = false;
                    pred(gap_func);
                }
                pred(new_func);
            }
            if (m_trap_info.header()->has_record_padding() && trap_entry.padding_size > 0) {
                Function new_func = {};
                // Add the padding as skip_copy
                new_func.skip_copy = true;
                new_func.is_padding = true;
                new_func.undiv_start =
                    os::Module::Address::from_trap(m_module, trap_entry.padding_address()).to_ptr();
                new_func.undiv_p2align = 0;
                new_func.has_size = true;
                new_func.size = os::API::assert_cast<size_t>(trap_entry.padding_size);
                pred(new_func);

                // Add a gap function for what comes after the padding
                Function gap_func = {};
                gap_func.undiv_start = new_func.undiv_end();
                gap_func.undiv_p2align = 0;
                gap_func.skip_copy = false;
                gap_func.from_trap = false;
                gap_func.is_padding = false;
                gap_func.is_gap = true;
                gap_func.has_size = false;
                pred(gap_func);
            }
        }
    }
}

void ExecSectionProcessor::count_functions() {
    size_t count = 0;
    IterateTrapFunctions([this, &count] (const Function &new_func) {
        count++;
        return true;
    });
    os::API::debug_printf<1>("Trap functions: %d\n", count);
    m_functions.reserve(count);
}

void ExecSectionProcessor::build_functions() {
    IterateTrapFunctions([this] (const Function &new_func) {
        m_functions.append(new_func);
        return true;
    });
}

template<typename T>
static inline RANDO_SECTION int compare_int(T a, T b) {
  return (a < b) ? -1 : ((a == b) ? 0 : 1);
}

static RANDO_SECTION int compare_functions(const void *a, const void *b) {
    auto fa = reinterpret_cast<const Function*>(a);
    auto fb = reinterpret_cast<const Function*>(b);
    if (fa->undiv_start == fb->undiv_start)
        return compare_int(fa->sort_rank(), fb->sort_rank());
    return compare_int(fa->undiv_start, fb->undiv_start);
}

void ExecSectionProcessor::sort_functions() {
    // Sort by undiversified addresses
    // FIXME: use our own qsort function, or force use of NTDLL!qsort
    if (m_trap_info.header()->needs_sort())
        m_functions.sort(compare_functions);
}

void ExecSectionProcessor::compute_function_sizes() {
    // Build sizes for functions
    auto exec_end = m_exec_section.end().to_ptr();
    for (size_t i = 0; i < m_functions.num_elems; i++) {
        if (m_functions[i].has_size)
            continue;
        auto next_start = (i == (m_functions.num_elems - 1)) ? exec_end : m_functions[i + 1].undiv_start;
        m_functions[i].has_size = true;
        m_functions[i].size = next_start - m_functions[i].undiv_start;
    }
}

void ExecSectionProcessor::remove_empty_functions() {
    auto orig_num_funcs = m_functions.num_elems;
    m_functions.remove_if([this] (size_t idx) {
        RANDO_ASSERT(m_functions[idx].has_size);
        return m_functions[idx].size == 0;
    });
    os::API::debug_printf<2>("Removed %d empty functions\n",
                             orig_num_funcs - m_functions.num_elems);
}

void ExecSectionProcessor::trim_gaps() {
    // Trim all NOPs (0x90 and 0xCCs) at the beginning of gap functions
    for (size_t i = 0; i < m_functions.num_elems; i++) {
        if (!m_functions[i].is_gap)
            continue;
        while (m_functions[i].size > 0 && os::API::is_one_byte_nop(m_functions[i].undiv_start)) {
            m_functions[i].undiv_start++;
            m_functions[i].size--;
        }
    }
}

void ExecSectionProcessor::shuffle_functions() {
    bool skip_shuffle = os::API::getenv("SELFRANDO_skip_shuffle") != nullptr;
    // FIXME: it would be nice to only disable shuffling
    // when the variable is set to "1" or "true"
    if (skip_shuffle) {
        os::API::debug_printf<1>("Selfrando: warning: applying identity transformation. No real protection!\n");
    }

    // Shuffle the order of the functions, using a Fisher-Yates shuffle
    m_shuffled_order = reinterpret_cast<size_t*>(os::API::mem_alloc(m_functions.num_elems * sizeof(size_t)));
    for (size_t i = 0; i < m_functions.num_elems; i++)
        m_shuffled_order[i] = i;
    for (size_t i = 0; i < m_functions.num_elems - 1; i++) {
        // Pick shuffled_order[i] at random from the remaining elements
        auto j = skip_shuffle ? 0 : os::API::random(m_functions.num_elems - i);
        if (j > 0) {
            os::API::swap(m_shuffled_order[i], m_shuffled_order[i + j]);
        }
    }
}

static inline RANDO_SECTION void patch_trampoline(os::BytePointer at, os::BytePointer to) {
    // We add the MOV EDI, EDI here to support hot-patching
    // FIXME: only really need this on Windows
    *at++ = 0x8B; // MOV EDI, EDI
    *at++ = 0xFF;
    *at++ = 0xE9; // JMP <pcrel>
    auto call_delta_ptr = reinterpret_cast<int32_t*>(at);
    *call_delta_ptr = os::API::assert_cast<int32_t>(to - (at + 4));
}

void ExecSectionProcessor::layout_code() {
    auto orig_code = m_exec_section.start().to_ptr();
    auto curr_addr = orig_code;
    for (size_t i = 0; i < m_functions.num_elems; i++) {
        auto si = m_shuffled_order[i];
        auto &func = m_functions[si];
        if (func.skip_copy) continue;

        // Align functions to either a multiple of kFunctionAlignment
        // or the same modulo as the undiversified code
        // (depending on kPreserveFunctionOffset)
        // TODO: handle 5-NOP padding between consecutive functions
        size_t align_mask = (static_cast<size_t>(1) << func.undiv_p2align) - 1;
        auto  old_ofs = (func.undiv_start - orig_code) & align_mask;
        auto curr_ofs = (curr_addr - orig_code) & align_mask;
        auto want_ofs = os::API::kPreserveFunctionOffset ? old_ofs : 0;
        if (curr_ofs != want_ofs) {
            auto padding = ((align_mask + 1) + want_ofs - curr_ofs) & align_mask;
            curr_addr += padding;
        }
        // TODO: also add in Windows-specific hot-patch trampolines
        func.div_start = curr_addr;
        curr_addr += func.size;
    }
    m_exec_code_size = curr_addr - orig_code;
    os::API::debug_printf<1>("Divcode size:%d\n", m_exec_code_size);

    // If we don't have enough room, we can't randomize in-place
    if (m_exec_code_size > m_exec_section.size()) {
        os::API::debug_printf<1>("Cannot randomize in place!\n");
        m_in_place = false;
    }
#if RANDOLIB_FORCE_INPLACE
    RANDO_ASSERT(m_in_place);
#endif
}

void ExecSectionProcessor::shuffle_code() {
    // Copy the code to a backup
    // FIXME: randomize the base address manually
    auto orig_code = m_exec_section.start().to_ptr();
    if (m_in_place) {
        // If we're randomizing in-place, we don't care
        // where the copy is in memory, since we release
        // it shortly anyway
        auto copy_addr = os::API::mmap(nullptr, m_exec_code_size,
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
            auto copy_page = start_page + os::API::random(max_copy_delta >> os::kPageShift);
            auto hint_addr = reinterpret_cast<void*>(copy_page << os::kPageShift);
            auto copy_addr = os::API::mmap(hint_addr, m_exec_code_size,
                                              os::PagePermissions::RW, true);
            m_exec_copy = reinterpret_cast<os::BytePointer>(copy_addr);
        } while (m_exec_copy == nullptr);
    }
    os::API::debug_printf<1>("Divcode@%p\n", m_exec_copy);

    auto copy_delta = m_exec_copy - orig_code;
    auto last_addr = m_exec_copy;
    for (size_t i = 0; i < m_functions.num_elems; i++) {
        auto si = m_shuffled_order[i];
        auto &func = m_functions[si];
        if (func.skip_copy) continue;

        // TODO: also add in Windows-specific function hot-patch trampolines
        os::API::debug_printf<3>("Moving %p[%d]=>%p@%p\n",
                                 func.undiv_start, func.size,
                                 func.div_start, func.div_start + copy_delta);
        func.div_start += copy_delta;
        if (func.div_start > last_addr) {
            // There is a gap between the last function and this one,
            // so we fill the gap with NOP instructions
            auto padding = func.div_start - last_addr;
            os::API::insert_nops(last_addr, padding);
        } else {
            RANDO_ASSERT(func.div_start == last_addr);
        }
        os::API::memcpy(func.div_start, func.undiv_start, func.size);
        last_addr = func.div_end();
    }
    if (m_in_place) {
        os::API::debug_printf<3>("Copying code back %p[%u]=>%p\n",
                                 m_exec_copy, m_exec_code_size, orig_code);
        os::API::memcpy(orig_code, m_exec_copy, m_exec_code_size);
        if (m_exec_code_size < m_exec_section.size()) {
            // We have space left over, clear it out
            size_t left_over = m_exec_section.size() - m_exec_code_size;
            os::API::memset(orig_code + m_exec_code_size, 0xCC, left_over);
        }
        // Revert the div_start addresses to the original section
        for (size_t i = 0; i < m_functions.num_elems; i++)
            m_functions[i].div_start -= copy_delta;
    } else {
        for (size_t i = 0; i < m_functions.num_elems; i++) {
#ifdef WIN32 // For now, we only replace the original code with CC's on Windows
            auto &func = m_functions[i];
            if (func.size < 7) {
                os::API::debug_printf<2>("Smallfunc@%p[%d]\n", func.undiv_start, func.size);
                continue;
            }
            // FIXME: this could create a race condition
            // FIXME: probably better to do this as the final step
            os::API::memset(func.undiv_start, 0xCC, func.size);
            // We skip this for functions whose addresses aren't taken
            if (!m_trap_info.header()->has_data_refs())
                patch_trampoline(func.undiv_start, func.div_start);
#endif
        }
        if (m_trap_info.header()->has_data_refs()) {
            for (auto trap_entry : m_trap_info) {
                auto entry_addr = os::Module::Address::from_trap(m_module, trap_entry.address);
                if (m_exec_section.contains_addr(entry_addr)) {
                    for (auto ref : trap_entry.data_refs()) {
                        auto ref_addr = os::Module::Address::from_trap(m_module, ref).to_ptr();
                        auto ref_func = m_functions.find_function(ref_addr);
                        if (ref_func != nullptr && ref_func->undiv_contains(ref_addr))
                            patch_trampoline(ref_addr, ref_addr + ref_func->div_delta());
                    }
                }
            }
        }
    }
}

void ExecSectionProcessor::fixup_relocations() {
    // FIXME(performance): this is pretty slow (profile confirms it)
    m_module.for_all_relocations(&m_functions);
}

void ExecSectionProcessor::process_trap_relocations() {
    m_trap_info.for_all_relocations([this] (const trap_reloc_t &trap_reloc) {
        auto reloc = os::Module::Relocation(m_module, trap_reloc);
        m_functions.adjust_relocation(&reloc);
    });
}

void ExecSectionProcessor::fixup_exports() {
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
                                                        &m_functions);
}

#if RANDOLIB_WRITE_LAYOUTS > 0
void ExecSectionProcessor::write_layout_file() {
#if RANDOLIB_WRITE_LAYOUTS == 1
    if (os::API::getenv("SELFRANDO_write_layout_file") == nullptr)
        return;
#endif

    auto fd = os::API::open_layout_file(true);
    if (fd == os::kInvalidFile) {
        os::API::debug_printf<1>("Error opening layout file!\n");
        return;
    }

    uint32_t version = 0x00000101;
    uint32_t seed = 0; // FIXME: we write a fake seed for now
    os::BytePointer func_base = m_functions.elems[0].undiv_start;
    os::BytePointer func_end = m_functions.elems[m_functions.num_elems - 1].undiv_end();
    ptrdiff_t func_size = func_end - func_base;
    const char *module_name = m_module.get_module_name();
    nullptr_t np = nullptr;
    os::API::write_file(fd, &version, sizeof(version));
    os::API::write_file(fd, &seed, sizeof(seed));
    os::API::write_file(fd, &func_base, sizeof(func_base)); // FIXME: fake file_base
    os::API::write_file(fd, &func_base, sizeof(func_base));
    os::API::write_file(fd, &func_size, sizeof(func_size));
    os::API::write_file(fd, module_name, strlen(module_name) + 1);
    for (size_t i = 0; i < m_functions.num_elems; i++) {
        auto si = m_shuffled_order[i];
        auto &func = m_functions.elems[si];
        if (func.skip_copy)
            continue;

        uint32_t size32 = static_cast<uint32_t>(func.size);
        os::API::write_file(fd, &func.undiv_start, sizeof(func.undiv_start));
        os::API::write_file(fd, &func.div_start, sizeof(func.div_start));
        os::API::write_file(fd, &size32, sizeof(size32));
    }
    os::API::write_file(fd, &np, sizeof(np));
    os::API::close_file(fd);
}
#endif

static RANDO_SECTION void randomize_exec_section(const os::Module &mod,
                                                 const os::Module::Section &sec,
                                                 TrapInfo &trap_info,
                                                 bool in_place, void *arg) {
    ExecSectionProcessor esp(mod, sec, trap_info, in_place);
    esp.run();
}

static RANDO_SECTION void randomize_module(os::Module &mod2, void *arg) {
    mod2.for_all_exec_sections(false, randomize_exec_section, nullptr);
}

RANDO_MAIN_FUNCTION() {
    os::API::init();
    {
        // os::Module needs to be in a deep scope,
        // so that its destructor gets called before os::API::Finish
        os::Module mod(asm_module);
        // For every section in the current program...
        mod.for_all_exec_sections(true, randomize_exec_section, nullptr);
        os::Module::for_all_modules(randomize_module, nullptr);
        // FIXME: we could make .rndtext non-executable here
    }
    os::API::finish();
}
