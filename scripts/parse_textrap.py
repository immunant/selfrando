#
# Copyright (c) 2014-2015, The Regents of the University of California
# Copyright (c) 2015-2019 RunSafe Security Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the University of California nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import os
import sys
import struct
import subprocess
import platform

# default to the host word size, overridden when dealing with ELF files
word_size = struct.calcsize("P") * 8

# set for ELF files
target_arch = None

trap_address = None
trap_data, trap_data_len = '', 0
got_plt_address = 0
if platform.system() == 'Windows':
    import pefile
    infile = pefile.PE(sys.argv[1])
    trap_list = [sec for sec in infile.sections if sec.Name[:6] == ".txtrp"]
    if len(trap_list) == 0:
        print "PE file does not contain a .txtrp section"
        sys.exit(1)

    trap_sec = trap_list[0]
    trap_data = trap_sec.get_data()
    trap_data_len = min(trap_sec.SizeOfRawData, trap_sec.Misc_VirtualSize)
    #print repr(trap_sec.get_data())
    
    if infile.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        word_size = 64

    reloc_has_extra_symbol = lambda reloc_type : False
    reloc_has_extra_addend = lambda reloc_type : False

elif platform.system() == 'Linux':
    readelf_path = 'readelf'
    if 'SELFRANDO_BINUTILS_PREFIX' in os.environ:
        readelf_path = os.environ['SELFRANDO_BINUTILS_PREFIX'] + 'readelf'

    for line in subprocess.check_output([readelf_path, '-h', sys.argv[1]]).splitlines():
        if 'ELF32' in line:
            word_size = 32
        if 'ELF64' in line:
            word_size = 64

        if 'Machine:' in line:
            target_arch = line.split()[1]

    for line in subprocess.check_output([readelf_path, '-x', '.txtrp', sys.argv[1]]).splitlines():
        if line.startswith('  0x'):
            trap_data += (line[13:48].replace(' ', '').decode('hex'))
            if trap_address is None:
                trap_address = int(line[2:12], 16)
    # We need the address of .got.plt
    for line in subprocess.check_output([readelf_path, '-d', sys.argv[1]]).splitlines():
        line_elems = line.split()
        if len(line_elems) >= 3 and line_elems[1] == "(PLTGOT)":
            got_plt_address = int(line_elems[2], 16)
            print ".got.plt@%08x" % got_plt_address

    trap_data_len = len(trap_data)

    if target_arch == 'ARM':
        reloc_has_extra_symbol = lambda reloc_type : reloc_type in [
                43, 44, 45, 46, 47, 48, 49, 50]
        reloc_has_extra_addend = lambda reloc_type : reloc_type in [
                3, 24, 25, 26, 41, 42, 96,
                43, 44, 45, 46, 47, 48, 49, 50]
    elif target_arch == 'AArch64':
        reloc_has_extra_symbol = lambda reloc_type : reloc_type in [
                275, 276, 277, 278, 284, 285, 286, 299]
        reloc_has_extra_addend = lambda reloc_type : reloc_type in [
                260, 261,
                275, 276, 277, 278, 284, 285, 286, 299]
    elif target_arch == 'Intel': # Should actually be "Intel 80386"
        reloc_has_extra_symbol = lambda reloc_type : False
        reloc_has_extra_addend = lambda reloc_type : reloc_type in [2, 4, 10]
    else:
        reloc_has_extra_symbol = lambda reloc_type : False
        reloc_has_extra_addend = lambda reloc_type : reloc_type in [
                2, 3, 4, 9, 19, 20, 24, 26, 27, 28, 29, 30, 34, 35, 41, 42] # FIXME

    #Un-comment this to write out the section to a file
    #text_file = open(sys.argv[1] + '.sec', "w")
    #text_file.write(trap_data)
    #text_file.close()

header = struct.unpack('<I', trap_data[0:4])[0]
version = header & 0xFF
flags = header>>8
have_sym_size = (flags & 0x04) != 0
record_relo = (flags & 0x10) != 0
have_nonexec_relo = (flags & 0x20) != 0
record_padding = (flags & 0x40) != 0
pcrel_addr = (flags & 0x80) != 0
have_sym_alignment = (flags & 0x100) != 0
have_pointer_size = (flags & 0x200) != 0
baserel_addr = (flags & 0x400) != 0
trap_data_pos = 4

if trap_address is not None:
    print ".txtrp@%08x" % trap_address
print 'word size: ' + str(word_size)
print "Header: %08x Version: %02x Flags: %06x" % (header, version, flags)

def get_trap_value(format):
    global trap_data, trap_data_pos, word_size

    return_pcrel = False
    if format == '@P' and (pcrel_addr or baserel_addr):
        return_pcrel = True
        format = '=l' if word_size == 32 else '=q'
    elif format == '@P' and word_size == 32:
        format = '=L'
    elif format == '@P' and word_size == 64:
        format = '=Q'
    # We hijack '@S' here for signed ptrdiff_t
    elif format == '@S' and word_size == 32:
        format = '=l'
    elif format == '@S' and word_size == 64:
        format = '=q'

    size = struct.calcsize(format)
    value_raw = trap_data[trap_data_pos:trap_data_pos+size]
    value = struct.unpack(format, value_raw)[0]
    if return_pcrel:
        if baserel_addr:
            # We use GOTOFF relocs for most arches
            value += got_plt_address
        else:
            value += trap_address + trap_data_pos
    trap_data_pos += size
    return value

def get_trap_uleb128():
    uleb_byte = get_trap_value('<B')
    uleb_shift = 0
    uleb = (uleb_byte & 0x7F)
    while (uleb_byte & 0x80) != 0:
        uleb_byte = get_trap_value('<B')
        uleb_shift += 7
        uleb |= ((uleb_byte & 0x7F) << uleb_shift)
    return uleb

def get_trap_sleb128():
    sleb_byte = get_trap_value('<B')
    sleb_shift = 7
    sleb = (sleb_byte & 0x7F)
    while (sleb_byte & 0x80) != 0:
        sleb_byte = get_trap_value('<B')
        sleb |= ((sleb_byte & 0x7F) << sleb_shift)
        sleb_shift += 7

    if (sleb & (1 << (sleb_shift - 1))) != 0:
        sleb -= 1 << sleb_shift
    return sleb


# Non-exec relocation information follows the header
if have_nonexec_relo:
    rel_addr = 0
    while True:
        delta = get_trap_uleb128()
        rel_type  = get_trap_uleb128()
        if delta == 0 and rel_type == 0:
            break

        rel_symbol, rel_addend = 0, 0
        if reloc_has_extra_symbol(rel_type):
            rel_symbol = get_trap_value('@P')
        if reloc_has_extra_addend(rel_type):
            rel_addend = get_trap_sleb128()

        rel_addr += delta
        print "Rel[%d]@%x=%x+%d" % (rel_type, rel_addr, rel_symbol, rel_addend)

if have_pointer_size:
    word_size = get_trap_uleb128()
    print 'trap word size: %d' % word_size

addr_list = []
addr_set = set()
sym_set = set()
while trap_data_pos < trap_data_len:
    sec_addr = get_trap_value('@P')
    first_sym = True
    sym_ofs = 0
    while True:
        delta = get_trap_uleb128()
        size = 0
        alignment = 0
        if have_sym_size:
            size = get_trap_uleb128()
        if have_sym_alignment:
            alignment = get_trap_uleb128()

        if delta == 0 and size == 0 and alignment == 0 and not first_sym:
            break

        if first_sym:
            first_sym = False
            sec_addr -= delta
            addr_list.append(sec_addr)
            addr_set.add(sec_addr)
            print "Address: %08x(sec+%d)" % (sec_addr, delta)

        sym_ofs += delta
        sym_addr = sec_addr + sym_ofs
        sym_set.add(sym_addr)
        print "  Sym@%x/%x[%x] align:2^%d" % (sym_ofs, sym_addr, size, alignment)

    if record_relo:
        rel_ofs = 0
        while True:
            delta = get_trap_uleb128()
            rel_type = get_trap_uleb128()
            if delta == 0 and rel_type == 0:
                break

            rel_symbol, rel_addend = 0, 0
            if reloc_has_extra_symbol(rel_type):
                rel_symbol = get_trap_value('@P')
            if reloc_has_extra_addend(rel_type):
                rel_addend = get_trap_sleb128()

            rel_ofs += delta
            print "  Rel[%d]@%x/%x=%x+%d" % (rel_type, rel_ofs, sec_addr + rel_ofs,
                                             rel_symbol, rel_addend)

    if record_padding:
        padding_offset = get_trap_uleb128()
        padding_size = get_trap_uleb128()
        print "  Padding[%d]@%x/%x" % (padding_size, padding_offset, sec_addr+padding_offset)

print "Addresses:%d/%d" % (len(addr_set), len(addr_list))
print "Syms:%d" % len(sym_set)

