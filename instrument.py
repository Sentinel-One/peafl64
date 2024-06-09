#
# Copyright (C) 2022 Gal Kristal, Dina Teper
# Copyright (C) 2022 SentinelOne, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import bisect
import json
import logging
import math
import os
import random
from struct import unpack
from typing import Optional, List, Tuple, Dict, Union, Literal

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

import pefile
import seh
from seh import ExInfo, UnwindInfo
from drt import (DRTException, IMAGE_DYNAMIC_RELOCATION_TABLE, IMAGE_DYNAMIC_RELOCATION, IMAGE_BASE_RELOCATION,
                 DYNAMIC_RELOC_TABLE_OFFSET_FIELD_OFFSET, IMAGE_FUNCTION_OVERRIDE_HEADER, IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION, 
                 IMAGE_BDD_DYNAMIC_RELOCATION, IMAGE_BDD_INFO)
from pefile import PE, SectionStructure, RelocationData, BaseRelocationData, RELOCATION_TYPE
from utils import (pack_64bit, pack_32bit, pack_16bit, unpack_32bit, unpack_64bit, is_value_32bit, bdata_replace,
                   data_replace, delete_if_exists, in_range, get_closest_or_equal, dword, is_exe, is_driver,
                   remove_dos_stub, remove_certificate, fix_checksum, is_pe_32bit, SortedSections)
from consts import MAGIC_NAME_MARKER, RELOC_SEC_NAME, ALT_MAGIC_NAME_MARKERS

# Initialize a disassembler object
g_csd = Cs(CS_ARCH_X86, CS_MODE_64)
g_csd.detail = True

pe: pefile.PE
pe_sorted_sections: SortedSections

# Useful lambdas
# not PE dependent
get_updated_addr_bytes = lambda rva: pack_32bit(update_addr(rva))

# pe dependent
align_section = lambda v: int(
    math.ceil(v / float(pe.OPTIONAL_HEADER.SectionAlignment))) * pe.OPTIONAL_HEADER.SectionAlignment
align_file = lambda v: int(math.ceil(v / float(pe.OPTIONAL_HEADER.FileAlignment))) * pe.OPTIONAL_HEADER.FileAlignment
va2ofs = lambda v: pe.get_offset_from_rva(v - pe.OPTIONAL_HEADER.ImageBase)
rva2ofs = lambda v: pe.get_offset_from_rva(v)
ofs2rva = lambda v: pe.get_rva_from_offset(v)
ofs2va = lambda v: pe.get_rva_from_offset(v) + pe.OPTIONAL_HEADER.ImageBase
rva2va = lambda v: v + pe.OPTIONAL_HEADER.ImageBase
va2rva = lambda v: v - pe.OPTIONAL_HEADER.ImageBase
get_sec_by_name = lambda v: [s for s in pe.sections if s.Name.startswith(v)][0]
get_sec_by_ofs = lambda v: pe_sorted_sections.get_sec_by_offset(v)

# Because the VirtualSize of a section can be a lot larger than its RawSize
# we need to know if we get the section according to its Virtual or Raw size
# Usually, it's used for addresses in data sections
get_sec_by_ofs_va = lambda v: pe_sorted_sections.get_sec_by_offset(v, is_virtual_offset=True)
get_sec_by_rva = lambda v: pe.get_section_by_rva(v)
get_sec_by_va = lambda v: pe.get_section_by_rva(v - pe.OPTIONAL_HEADER.ImageBase)


class RelativeInstruction:
    def __init__(self, target: int, instr_bytes: str, operand_len: int, total_len: int):
        self.target = target
        # In hex string
        self.instr_bytes = instr_bytes
        # The number of bytes used to represent the target address, offset, disposition, etc
        self.operand_len = operand_len
        self.total_len = total_len

    def __str__(self):
        return str([hex(self.target), self.instr_bytes, self.operand_len, self.total_len])


class Code:
    def __init__(self, virtual_address: int, expand: bytes, align: bytes, shellcode: bytes, total_len: int, is_bb_start: bool = False):
        self.virtual_address = virtual_address
        # New bytes we add for relative instruction expansion
        self.expand = expand
        self.align = align
        self.shellcode = shellcode
        self.total_len = total_len
        self.is_bb_start = is_bb_start

    def __str__(self):
        return str([hex(self.virtual_address), self.expand, self.align, self.shellcode, self.total_len])


class Address:
    def __init__(self, addr: int, code_len: int):
        self.post_injection_addr = addr
        self.code_len = code_len

    def __str__(self):
        return str([hex(self.post_injection_addr), self.code_len])


def ntoskrnl_update_KiServiceTable() -> None:
    """
    Uses a heuristic to find and fix the KiServiceTable in a Windows Kernel binary.
    Currently only relevant for Windows 10 versions.
    @return:
    """
    global pe

    # The KiServiceTable resides in .rdata section
    rsec = get_sec_by_name(b'.rdata')
    start_addr = rsec.get_VirtualAddress_adj()
    rsec_start_offset = rsec.get_PointerToRawData_adj()
    rsec_data = rsec.get_data()

    # Use NtWaitForSingleObject as a constant marker for Windows 10 versions
    # Reference: https://j00ru.vexillium.org/syscalls/nt/64/
    marker_function_rva = [sym for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols if sym.name == b'NtWaitForSingleObject'][0].address
    marker_offset = 4

    # Align section size to DWORD
    i = len(rsec_data) - (len(rsec_data) % 4)
    kiservicetable_offset = None
    while i >= 4:
        i -= 4
        rva = unpack('<I', rsec_data[i:i + 4])[0]
        if rva == marker_function_rva:
            kiservicetable_addr = start_addr + i - (4 * marker_offset)
            kiservicetable_offset = i - (4 * marker_offset)
            logging.info(f"KiServiceTable at rva: {hex(kiservicetable_addr)}")
            break
    else: # Didn't reach the break
        return

    # We assume here that KiServiceTable isn't larger than 0x1000 bytes
    # Also we assume that the first signed int smaller than 0x1000 can't be an RVA to a function,
    # but only the KiServiceLimit we look for
    for i in range(kiservicetable_offset, kiservicetable_offset + 0x1000, 4):
        limit = unpack('<i', rsec_data[i:i + 4])[0]
        if limit <= 0x1000:
            kiservicelimit = limit
            kiservicelimit_addr = start_addr + i
            logging.info(f"Found KiServiceLimit at rva: {hex(kiservicelimit_addr)} ({hex(kiservicelimit)})")
            break
    else:  # no break
        return

    # Finally patch the KiServiceTable
    for i in range(kiservicetable_offset, kiservicetable_offset + (kiservicelimit-1)*4, 4):
        rva = unpack('<I', rsec_data[i:i + 4])[0]
        rsec.raw = data_replace(rsec.raw, rsec_start_offset + i, get_updated_addr_bytes(rva))


def new_section_name(section: SectionStructure, marker: bytes = MAGIC_NAME_MARKER) -> bytes:
    """
    The function creates a name for the new section, marking it with marker.
    Max section name length is 8, the marker randomization is meant to prevent duplicates in cases where there are two
    sections with names such as ABCDEFG1 and ABCDEFG2 (both will become ABCDEFG^). It WILL NOT WORK when there are more
    than 8 executable sections named like this, but we find it highly unlikely.
    If this is the case for your binary, you can add additional markers to the list in consts.py
    """
    name = section.Name.strip(b'\x00')
    section_names = [section.Name.strip(b'\x00') for section in pe.sections]
    new_name = name[:7] + marker

    if new_name not in section_names:
        return new_name
    else:
        return new_section_name(section, random.choice(ALT_MAGIC_NAME_MARKERS))


def clear_stub_and_certificate() -> str:
    """
    Removes the DOS stub from the PE header and the certificate.
    :return: The updated file's path
    """
    global pe
    new_name = pe.path
    # remove certificate if needed
    security_dir = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_SECURITY')
    if security_dir.VirtualAddress:
        new_name = remove_certificate(new_name)
        logging.debug('removed certificate')

    # remove stub
    if '.no_stub' not in pe.path:
        # leave space for section table
        new_name = remove_dos_stub(new_name)
        logging.debug('cleared DOS stub')

    return new_name


def inject_code(addr: int, injections: Dict[int, Code], shellcode: bytes = b'', expand: bytes = b'', is_bb_start: bool = False) -> None:
    """
    Creates an injection struct for an address and inserts it into the injections dict.
    :param addr: Address to inject to
    :param injections: A dict that holds info about all the injections.
    :param shellcode: Shellcode to inject
    :param expand: New bytes to add for relative instruction expansion (e.g. short jmp to far jmp)
    :param is_bb_start: Is this an injection of a start of a basic block
    :return:
    """
    # expand is a partial operand for expanding from short jump to long jump
    addr_offset_in_file = va2ofs(addr)
    section = get_sec_by_va(addr)
    if not is_exe(section):
        raise ValueError(f"Tried to inject code into non-executable section, at address: {hex(addr)}")

    # instrument with word-aligned
    align = b''
    if expand == b'':
        shellcode += b'\x90' * (len(shellcode) % 2)
    else:
        align = b'\x90' * (len(expand) % 2)

    if addr_offset_in_file in injections:
        inj_struct = injections[addr_offset_in_file]
        inj_struct.expand = expand
        inj_struct.align = align
        # multiple injection is allowed
        inj_struct.shellcode = shellcode + inj_struct.shellcode
        inj_struct.total_len = len(inj_struct.shellcode + inj_struct.expand + inj_struct.align)
    else:
        injections[addr_offset_in_file] = Code(addr, expand, align, shellcode, len(expand + shellcode + align), is_bb_start)
        # for optimization
        if not hasattr(section, 'addr_set'):
            section.addr_set = []
        bisect.insort(section.addr_set, addr_offset_in_file)


def build_address_map(injections: Dict[int, Code], section: Optional[SectionStructure] = None) -> None:
    """
    Builds addr_map for all sections or for a given section.
    This helps to calculate addresses in duplicated sections.
    :param injections: Dictionary of physical offsets in the file of basic blocks to instrument
    :param section: A section to build addr_map for.
    :return:
    """
    # for optimization
    if section is None:
        sec_list = sorted(pe.sections, key=lambda s: s.PointerToRawData)
    else:
        sec_list = [section]

    for section in sec_list:
        if hasattr(section, 'addr_map'):
            diff = 0
            # Count how much bytes added until each injection point
            for injected_addr in section.addr_set:
                code_struct = injections[injected_addr]
                total_len = code_struct.total_len
                section.addr_map[injected_addr] = Address(injected_addr + diff + len(code_struct.expand),
                                                          total_len - len(code_struct.expand))
                diff += total_len


def get_last_section(option: Literal['rva', 'fa', 'tbl', 'all']) -> Union[Tuple[int, int, int], int]:
    """
    Get information about the structure of the PE's sections.
    The option "rva" gives the highest relative virtual address in the file.
    The option "fa" gives the highest file offset used by a section data.
    The option "tbl" gives the highest file offset used by a section header.
    The option "all" returns all three in the following order: rva, fa, tbl
    :param option: 'rva', 'fa', 'tbl', or 'all'
    :return: (int, int, int) for all, int otherwise
    """
    rva = 0  # relative virtual address
    fa = 0  # file offset
    tbl = 0  # section headers file offset
    for sec in pe.sections:
        rva = max(rva, sec.VirtualAddress + sec.Misc_VirtualSize)
        fa = max(fa, sec.PointerToRawData + sec.SizeOfRawData)
        tbl = max(tbl, sec.get_file_offset() + sec.sizeof())
    logging.debug(f'[get_last_section] {sec.Name} {hex(rva)} {hex(fa)} {hex(tbl)}')
    if option == 'all':
        return align_section(rva), align_file(fa), tbl
    elif option == 'rva':
        return align_section(rva)
    elif option == 'fa':
        return align_file(fa)
    elif option == 'tbl':
        return tbl
    else:  # unknown option
        raise ValueError(f'Unknown option {option} for get_last_section')


def calc_bytes_added(file_offset: int, is_target: bool = False) -> int:
    """
    Get the number of bytes added by our instrumentation and operand expansions from the start of the address's section
    up to it.
    This calculates it for executable sections.
    :param file_offset: File offset of an address to get the diff to
    :param is_target: Is the address a target of an instruction or is it the address of the instruction
    :return: int
    """
    section = get_sec_by_ofs_va(file_offset) if is_target else get_sec_by_ofs(file_offset)
    diff = 0
    # Data sections are not changed by instrumentation
    if not is_exe(section):
        return 0

    if hasattr(section, 'addr_map') and file_offset in section.addr_map:
        diff = section.addr_map[file_offset].post_injection_addr - file_offset
    else:
        closest_inj_point = get_closest_or_equal(section.addr_set, file_offset)
        if closest_inj_point:
            diff = section.addr_map[closest_inj_point].post_injection_addr - closest_inj_point + section.addr_map[
                closest_inj_point].code_len
    return diff


def get_updated_dynamic_relocs(injections: Dict[int, Code]):
    """
    Get the updated dynamic relocation entries.
    :param injections: The dict of injections, that we use to check if a relocation is on a start 
                       of a basic block
    :return: None if the PE has no dynamic relocations, otherwise: 
             Dictionary of symbols to list of updated type offsets for regular dynamic relocations
             Also dict of function override data
    """
    global pe
    try:
        drt = IMAGE_DYNAMIC_RELOCATION_TABLE.from_pe(pe)
    except DRTException:
        return None

    func_override_relocs = {}
    updated_dyn_relocs = {}

    for dynamic_reloc in drt.dynamic_relocations:
        updated_rvas = []
        func_override_fixup_rvas = []

        # Symbol 7 means function override
        if dynamic_reloc.symbol == 7:
            for func_override in dynamic_reloc.function_override_header.func_override_info:
                func_override_rva_list = [update_addr(rva) for rva in func_override.rva_list]
                for base_reloc in func_override.base_relocations:
                    for rva, offset_type in base_reloc.type_offsets:
                        file_offset = rva2ofs(rva)
                        # In cases where we have a dynamic relocation in a start of basic block, we need to skip the shellcode we inserted
                        # so that we relocate the correct instruction
                        skip_bytes = len(injections[file_offset].shellcode) if file_offset in injections and injections[file_offset].is_bb_start else 0
                        func_override_fixup_rvas.append((update_addr(rva) + skip_bytes, offset_type))
            func_override.original_rva = update_addr(func_override.original_rva)
            func_override_relocs[dynamic_reloc.function_override_header] = {func_override: (func_override_rva_list, func_override_fixup_rvas)}
        else: 
            for base_reloc in dynamic_reloc.base_relocations:
                for rva, offset_type in base_reloc.type_offsets:
                        file_offset = rva2ofs(rva)
                        # In cases where we have a dynamic relocation in a start of basic block, we need to skip the shellcode we inserted
                        # so that we relocate the correct instruction
                        skip_bytes = len(injections[file_offset].shellcode) if file_offset in injections and injections[file_offset].is_bb_start else 0
                        updated_rvas.append((update_addr(rva) + skip_bytes, offset_type))
            updated_dyn_relocs[dynamic_reloc.symbol] = updated_rvas

    return updated_dyn_relocs, func_override_relocs


def new_reloc_entry(addr: int, entry_type: int) -> RelocationData:
    """
    Create a new Relocation entry to use with the PE.
    :param addr: Relocation's address (RVA)
    :param entry_type: Relocation type
    :return: RelocationData struct
    """
    entry = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_ENTRY_format__)
    assert (0 <= entry_type <= 10), 'invalid type'
    setattr(entry, 'Data', (addr & 0xFFF) + (entry_type << 12))
    entry.set_file_offset(0)
    return pefile.RelocationData(struct=entry, type=entry_type, base_rva=addr & ~0xFFF, rva=addr)


def add_to_reloc(updated_relocs: List[BaseRelocationData], addr_list: List[int], entry_types: List[int]) -> None:
    """
    Takes a list of relocations and a list of their types and prepares the needed
    relocation structs for the PE.
    addr_list and entry_types are lists where elements at the same index correspond -
    eg. entry_type[i] is the entry type of addr[i]
    :param updated_relocs: List of updated relocation records
    :param addr_list: List of addresses that need relocations
    :param entry_types: List of relocation types
    :return:
    """
    # creating a mapping between the blocks VAs and their indexes in updated_reloc
    reloc_va_dict = {block.struct.VirtualAddress: i for i, block in enumerate(updated_relocs)}
    last_reloc_index = len(updated_relocs) - 1

    for addr, entry_type in zip(addr_list, entry_types):
        block_index = reloc_va_dict.get(addr & ~0xFFF, None)
        if block_index is not None:
            reloc_block = updated_relocs[block_index]
            # insert new entry into existed base reloc
            reloc_block.entries.append(new_reloc_entry(addr, entry_type))
            reloc_block.struct.SizeOfBlock += 2
        else:
            # new entry
            relocation_struct = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__)
            setattr(relocation_struct, 'VirtualAddress', addr & ~0xFFF)
            setattr(relocation_struct, 'SizeOfBlock', 8 + 2)
            relocation_struct.set_file_offset(0)

            # insert new base reloc
            entries = [new_reloc_entry(addr, entry_type)]
            updated_relocs.append(BaseRelocationData(struct=relocation_struct, entries=entries))
            last_reloc_index += 1
            reloc_va_dict[relocation_struct.VirtualAddress] = last_reloc_index


def create_updated_dvrt(dynamic_reloc_mapping) -> bytearray:
    """
    Creates a new Dynamic Value Relocation Table (also called DVRT) that's based on the mapping we've got.
    Then it dumps that DRT into a bytearray.
    :param dynamic_reloc_mapping: Dictionary of symbols to list of updated type offsets (RVAs)
    :return: A packed updated Dynamic Relocation Table
    """
    dynamic_relocs = []
    for symbol, type_offsets in dynamic_reloc_mapping[0].items():
        pages = {}
        base_relocs = []

        # RVAs were updated and that maybe caused them to move a page
        # Here we rebuild it
        for rva, offset_type in type_offsets:
            page = rva & ~0xFFF
            if page not in pages:
                pages[page] = []
            pages[page].append((rva,offset_type))

        for page, page_offsets in pages.items():
            base_relocs.append(IMAGE_BASE_RELOCATION.from_data(page, page_offsets, is_word_sized=symbol!=3))

        dynamic_relocs.append(IMAGE_DYNAMIC_RELOCATION.from_data(symbol, base_relocations=base_relocs, function_override_header=None))
    
    for fo_header, data in dynamic_reloc_mapping[1].items():
        fo_relocs: List[IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION] = []
        for fo, values in data.items():
            rva_list, fixup_rvas = values[0], values[1]
            fo.rva_list = rva_list
            pages = {}
            base_relocs = []

            # RVAs were updated and that maybe caused them to move a page
            # Here we rebuild it
            for rva, offset_type in fixup_rvas:
                page = rva & ~0xFFF
                if page not in pages:
                    pages[page] = []
                pages[page].append((rva,offset_type))

            for page, page_offsets in pages.items():
                base_relocs.append(IMAGE_BASE_RELOCATION.from_data(page, page_offsets, is_word_sized=True))

            fo_relocs.append(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION.from_data(fo.original_rva, fo.bdd_offset, fo.rva_list, base_relocs))

        new_fo_header = IMAGE_FUNCTION_OVERRIDE_HEADER.from_data(fo_relocs, fo_header.bdd_info)
        dynamic_relocs.append(IMAGE_DYNAMIC_RELOCATION.from_data(symbol=7, base_relocations=[], function_override_header=new_fo_header))

    drt = IMAGE_DYNAMIC_RELOCATION_TABLE.from_data(dynamic_relocs)
    return drt.dump()


def build_reloc_section(updated_reloc: List[BaseRelocationData], updated_dynamic_reloc,
                        is_verbose: bool) -> bytearray:
    """
    Finalizes the contents of the relocations section with the new relocations.
    :param updated_reloc: List of all the relocations
    :param updated_dynamic_reloc: Dictionary of symbols to list of updated type offsets for dynamic relocations
                                  And dict of function override relocation data
    :param is_verbose: For debugging purposes
    :return: The data of the updated relocation section
    """
    # IMAGE_REL_BASED_ABSOLUTE        No operation relocation. Used for padding.
    # IMAGE_REL_BASED_HIGHLOW         Add the delta between the ImageBase and the allocated memory block to the 32 bits
    #                                 found at the offset.
    updated_reloc.sort(key=lambda x: x.struct.VirtualAddress)

    # append IMAGE_REL_BASED_ABSOLUTE for padding
    for reloc_block in updated_reloc:
        if (reloc_block.struct.SizeOfBlock / 2) % 2:
            reloc_block.entries.append(new_reloc_entry(0, 0))
            reloc_block.struct.SizeOfBlock += 2

    if is_verbose:
        logging.debug('[debug_reloc]')
        for base_reloc in updated_reloc:
            logging.debug('\n'.join(base_reloc.struct.dump()))
            for reloc in base_reloc.entries:
                logging.debug('%08Xh %s' % (reloc.rva, RELOCATION_TYPE[reloc.type][16:]))

    # handle regular relocations
    reloc_section = get_sec_by_name(RELOC_SEC_NAME)
    updated_reloc_raw = bytearray(b'')
    for base_reloc in updated_reloc:
        updated_reloc_raw += pack_32bit(base_reloc.struct.VirtualAddress) + pack_32bit(base_reloc.struct.SizeOfBlock)
        for entry in base_reloc.entries:
            updated_reloc_raw += pack_16bit(entry.struct.Data)

    directory = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_BASERELOC')
    directory.Size = len(updated_reloc_raw)
    directory.VirtualAddress = reloc_section.VirtualAddress

    # Handle the dynamic relocation table that also resides in the .reloc section
    if updated_dynamic_reloc is not None:
        drt_raw = create_updated_dvrt(dynamic_reloc_mapping=updated_dynamic_reloc)
        load_config_base_offset = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.get_file_offset()
        load_config_sec = get_sec_by_ofs(load_config_base_offset)
        # The new drt starts after the normal relocations end
        load_config_sec.raw = data_replace(load_config_sec.raw, load_config_base_offset +
                                           DYNAMIC_RELOC_TABLE_OFFSET_FIELD_OFFSET, pack_32bit(len(updated_reloc_raw)))

        # This is the 1-based .reloc section offset
        load_config_sec.raw = data_replace(load_config_sec.raw, load_config_base_offset +
                                           DYNAMIC_RELOC_TABLE_OFFSET_FIELD_OFFSET + 4, pack_16bit(len(pe.sections)))
        updated_reloc_raw += drt_raw

    # padding
    updated_reloc_raw += bytearray(b'\x00') * (pe.OPTIONAL_HEADER.FileAlignment - len(updated_reloc_raw) %
                                               pe.OPTIONAL_HEADER.FileAlignment)
    reloc_section.Misc_VirtualSize = reloc_section.SizeOfRawData = len(updated_reloc_raw)
    return updated_reloc_raw


def update_reloc_raw(relocation_type: int, section_raw: bytes, offset: int, idata: List) -> bytes:
    """
    Update relocations so they relate to the new instrumented section of ours instead of the original section
    :param relocation_type: Relocation type
    :param section_raw: section.raw
    :param offset: the offset of the relocation in the section's data
    :param idata: List of segment start and end addresses in .idata segment
    :return: modified section.raw
    """
    global pe
    if relocation_type not in (pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64'],
                               pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']):
        raise ValueError(f"Relocation type not supported: {relocation_type}")

    is_32_bit = relocation_type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']
    addr = unpack_32bit(section_raw[offset:offset + 4]) if is_32_bit else unpack_64bit(section_raw[offset:offset + 8])

    section = get_sec_by_va(addr)
    if is_exe(section) and not in_range(va2ofs(addr), idata):
        logging.debug(f'[update_reloc_raw] {hex(addr)}')
        updated_addr = rva2va(update_addr(va2rva(addr)))
        updated_addr = pack_32bit(updated_addr) if is_32_bit else pack_64bit(updated_addr)
        return data_replace(section_raw, offset, updated_addr)
    else:
        return section_raw


def update_and_verify_section_table(reloc: Optional[pefile.SectionStructure] = None) -> None:
    """
    Verifies the alignment of the new sections in PE.
    Adds a new relocation section to the end, if provided.
    :param reloc: New relocation section
    :return: none
    """
    global pe, pe_sorted_sections
    if reloc:
        reloc_rva, reloc_fa, reloc_tbl = get_last_section('all')
        reloc.VirtualAddress = reloc_rva
        reloc.PointerToRawData = reloc_fa
        reloc.set_file_offset(reloc_tbl)

        # Now .reloc is at the end of the sections
        pe.sections.append(reloc)
        pe_sorted_sections.extend(reloc)

    # confirm all sections have to stick together, don't overlap or separate
    rva = 0
    fa = 0
    for section in pe.sections:
        if rva != 0 and fa != 0:
            # Makes sure all the sections are correctly built and aligned
            if rva != section.VirtualAddress or (section.PointerToRawData != 0 and fa != section.PointerToRawData):
                raise RuntimeError("Something went wrong while building the new sections")
            prev_section.next_section_virtual_address = section.VirtualAddress
        prev_section = section
        rva = align_section(section.VirtualAddress + section.Misc_VirtualSize)
        fa = align_file(section.PointerToRawData + section.SizeOfRawData)
    section.next_section_virtual_address = section.VirtualAddress + section.Misc_VirtualSize


def is_data_instruction(hex_instruction: str, target: int, code_loc: set[int]) -> bool:
    """
    Tries to decide whether an operation is for moving/loading data or executable code.
    Data instructions will mostly occur on data from non-executable sections, which might be larger in
    virtual size than their raw size. This information is relevant for finding the correct section that
    the operation is pointing to.

    If the operation is jmp/call/etc then it's for executable code.
    If the target is the start of a function/basic-block than it's also "executable".
    Otherwise, it's "data instruction".

    :param hex_instruction: hex string of an assembly instruction
    :param target: The target of the instruction
    :param code_loc: set of function addresses in the PE
    :return: bool
    """

    # Intel MPX
    if hex_instruction.startswith('f2'):
        hex_instruction = hex_instruction[2:]

    # jmps/calls/loop/etc
    if hex_instruction in ('e2', 'e3', 'eb', 'e9', 'e8') or hex_instruction[0] == '7' or hex_instruction[:3] == '0f8':
        return False

    # TODO: is that enough?
    if not is_exe(get_sec_by_va(target)):
        return True

    # If the target is a start of a function I want to treat it as it's related to execution
    if target in code_loc:
        return False

    # TODO: This is test logic
    # 64 bit call/jmp/etc
    ins = next(g_csd.disasm(bytes.fromhex(hex_instruction), 0))
    if ins.mnemonic.startswith(('loop', 'jmp', 'call', 'lea', 'mov')):
        return False

    return True


def get_relative_diff(from_fa: int, to_fa: int, is_data: bool = False) -> int:
    """
    Calculate the distance between the source and target after instrumentation.
    :param from_fa: Address of the instruction
    :param to_fa: Address of the target
    :param is_data: Is the target address a data section
    :return: The distance
    """
    global pe
    from_fa_ofs = va2ofs(from_fa)
    to_fa_ofs = va2ofs(to_fa)
    from_s = get_sec_by_ofs(from_fa_ofs)
    # The target of a call/jump/whatever can point to virtual address so parsing should be done accordingly
    # Try to infer if that's call/jmp/loop instruction, then it's more likely we shouldn't treat the target as va
    to_s = get_sec_by_ofs_va(to_fa_ofs) if is_data else get_sec_by_ofs(to_fa_ofs)

    # the most basic case - diff between addresses and bytes added by instrumentation to origin
    diff = to_fa - from_fa - calc_bytes_added(from_fa_ofs)
    # adding bytes added to target, will be zero if the target is a data section
    diff += calc_bytes_added(to_fa_ofs, is_target=is_data)
    # we advanced from_s.sec_diff so we deduct it
    diff -= from_s.sec_diff
    # the target advanced to_s.sec_diff so we add it.
    # if source and target are in the same section, they cancel each other out
    # if we found no target, we assume it's data and it didn't move
    diff += to_s.sec_diff if is_exe(to_s) else 0
    # if the source instruction got longer
    if from_fa_ofs in from_s.addr_map:
        diff -= from_s.addr_map[from_fa_ofs].code_len
    return diff


def update_instruction(instr: str, operand_len: int, target_addr: int) -> str:
    """
    Check if an operand needs to be changed to work with the new target address/offset.
    If so, return the updated instruction.
    :param instr: Hex string of the instruction
    :param operand_len: The len of the operand (e.g. from "jne 0x40" it's the len of the "jne" bytes)
    :param target_addr: The new target address
    :return: The updated instruction
    """
    if -0x80 <= target_addr < 0x80 and operand_len == 1:
        return instr + chr(target_addr & 0xFF).encode('latin-1').hex()
    else:
        return expand_instr(instr, target_addr)


def update_rip_relative_instr(instruction: str, value: int) -> str:
    """
    Update the target address (or offset) of a rip-relative instruction
    :param instruction: Hex string of the instruction
    :param value: The new target address of the operand (usually as an offset)
    :return: The modified instruction
    """
    ins = next(g_csd.disasm(bytes.fromhex(instruction), 0))
    # verify it's a rip-relative instruction
    assert len(ins.operands) > 0, 'rip-relative parsing error - no operands'
    assert any(
        i.type == X86_OP_MEM and i.value.mem.base == X86_REG_RIP for i in ins.operands), 'Not rip-relative instruction'
    # Capstone does not support modifying instructions so we'll do it manually
    # Usually we should do ins.disp_offset + ins.disp_size but capstone ignore extra zero bytes
    # so I hardcode it to 4
    modified_ins_bytes = ins.bytes[:ins.disp_offset] + pack_32bit(value) + ins.bytes[ins.disp_offset + 4:]
    # Verify it by disassembling it again
    modified_ins = next(g_csd.disasm(modified_ins_bytes, 0))
    assert any(i.type == X86_OP_MEM and i.value.mem.base == X86_REG_RIP for i in
               modified_ins.operands), 'Rebuilt instruction went wrong: %s' % modified_ins_bytes.hex()
    mod_ins_as_hex = modified_ins_bytes.hex()
    assert len(mod_ins_as_hex) == len(instruction), 'Instruction size changed while updating rip-relative instruction'
    return mod_ins_as_hex


def expand_instr(instruction: str, target_addr: int) -> str:
    """
    Operand expansion is needed if we injected code between the jump and its target, and the short jmp is no longer
    big enough to hold the new offset to the target.
    For x64 bit rip-relative instructions there's no need to expand but only to update the target to the new offset
    :param instruction: Hex string of the operand
    :param target_addr: The new target address of the operand (usually as on offset)
    :return: The modified instruction
    """
    if not is_value_32bit(target_addr):
        raise ValueError('Target address is out of range')

    # intel MPX
    # This parsing also captures instructions like "movsd xmm1, qword ptr [rip + x]"
    original_instruction = instruction
    mpx = ''
    if instruction.startswith('f2'):
        mpx = 'f2'
        instruction = instruction[2:]

    if instruction == 'e2':  # loop rel8
        assert mpx == '', 'Unsupported instruction ' + instruction
        return f'4975{dword(target_addr)}'  # dec ecx ; jnz label
    elif instruction == 'e3':  # jecxz rel8
        assert mpx == '', 'Unsupported instruction ' + instruction
        return f'85c974{dword(target_addr)}'  # test ecx, ecx ; jz label
    elif instruction == 'eb':  # jmp rel8
        return f'{mpx}e9{dword(target_addr)}'
    elif instruction == 'e9':  # jmp rel32
        return f'{mpx}e9{dword(target_addr)}'
    elif instruction == 'e8':  # call
        return f'{mpx}e8{dword(target_addr)}'
    elif instruction[0] == '7':  # jxx rel8
        return f'{mpx}0f8{instruction[-1]}{dword(target_addr)}'
    elif instruction[:3] == '0f8':  # jxx rel32
        return f'{mpx}{instruction}{dword(target_addr)}'
    else:
        # Sometimes we only call this function to get the new length of the expanded instruction.
        # When it's rip-relative, the length never changes, so we optimize this case
        if target_addr == 0:
            return f'{original_instruction}'

        # Assume this is rip-relative opcode, otherwise it crashes in an asset within update_rip_relative_instr()
        logging.debug(f'expand_instr: assuming rip-relative: {original_instruction} {hex(target_addr)}')
        return update_rip_relative_instr(original_instruction, target_addr)


def update_addr(rva: int) -> int:
    """
    Translate an address from an original section to the new instrumented section.
    :param rva: address that is RVA
    :return: int
    """
    offset, section = rva2ofs(rva), get_sec_by_rva(rva)
    if hasattr(section, 'sec_diff'):
        return rva + section.sec_diff + calc_bytes_added(offset)
    else:
        return rva


def duplicate_section(original_section: SectionStructure, enlarge: int, name: Optional[bytes] = None,
                      size: int = 0) -> SectionStructure:
    """
    Duplicate a given section and prepare it for instrumentation.
    :param original_section: The section to duplicate.
    :param enlarge: In what factor to enlarge the section.
    :param name: New section name.
    :param size: The new section size.
    :return: The new section.
    """
    global pe, pe_sorted_sections
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    # Copy the inner structures in a smart way to the new section
    new_section.__unpack__(original_section.__pack__())
    if name:
        new_section.Name = name
    else:
        new_section.Name = (new_section_name(original_section)).ljust(8, b'\x00')
    setattr(original_section, 'duplicated_section_name', new_section.Name)
    rva, fa, tbl = get_last_section('all')
    new_section.VirtualAddress = rva
    new_section.PointerToRawData = fa
    section_size = size if size else max(original_section.SizeOfRawData, original_section.Misc_VirtualSize) * enlarge
    new_section.Misc_VirtualSize = align_section(section_size)
    new_section.SizeOfRawData = align_file(section_size)
    new_section.set_file_offset(tbl)
    new_section.next_section_virtual_address = new_section.VirtualAddress + new_section.Misc_VirtualSize
    if new_section.get_file_offset() + new_section.sizeof() > pe.OPTIONAL_HEADER.SizeOfHeaders:
        raise NotImplementedError("File contains too many sections for us to instrument")
    pe.__structures__.append(new_section)
    pe.sections.append(new_section)
    pe_sorted_sections.extend(new_section)
    logging.info('Added section {}'.format(new_section.Name.strip(b'\x00').decode('utf-8')))
    logging.debug(str(new_section))
    return new_section


def build_raw_attr_for_executable_sections() -> None:
    """
    Adds a 'raw' field to the original sections that's in the the following structure: 32bit_file_start_address,
      (start-4) null bytes, and then the original section data
    """
    for section in pe.sections:
        if is_exe(section) and hasattr(section, 'is_original'):
            section_start = section.PointerToRawData
            section_end = section_start + section.SizeOfRawData
            build_raw_attr(section)
            name = section.Name.strip(b'\x00')
            logging.debug(f'{name} @ {hex(section_start)}~{hex(section_end)}')


def update_load_config_tbl(table_offset: int, entry_count: int, align: int = 4):
    """
    Generically update load configuration tables.
    The table is just a list of RVAs so we update them to point to our instrumented sections.
    :param table_offset: Load Configuration table offset
    :param entry_count: Number of entries in the table
    :param align: Table alignment (per the documentation)
    :return: bytes
    """
    new_table_rva = update_addr(table_offset - pe.OPTIONAL_HEADER.ImageBase)
    ofs, section = rva2ofs(new_table_rva), get_sec_by_rva(new_table_rva)
    # If we have 'raw' attr we work on it
    if hasattr(section, 'raw'):
        for n in range(entry_count):
            obj_offset = ofs + n * align
            section.raw = data_replace(section.raw, obj_offset,
                                       pack_32bit(update_addr(unpack_32bit(section.raw[obj_offset:obj_offset + 4]))))
    # Otherwise, just work directly on the file
    else:
        pe_set_dword = pe.set_dword_at_offset
        pe_get_dword = pe.get_dword_from_offset
        for n in range(entry_count):
            obj_offset = ofs + n * align
            pe_set_dword(obj_offset, update_addr(pe_get_dword(obj_offset)))


def update_exception_record(exc: seh.ExInfo, file_offset: int, rsec: SectionStructure) -> None:
    """
    Updates an exception record with the correct addresses post instrumentation.
    :param exc: Exception record
    :param file_offset: The file offset from where it was parsed
    :param rsec: The section (usually .rdata) where the exception's UnwindInfo resides
    :return: None
    """
    # Here I use pe.set_dword_at_* because it works on .pdata section which shouldn't have a 'raw' attribute
    # so that's the way to edit it
    # Otherwise it's .rdata
    if b'.pdata' in get_sec_by_ofs(file_offset).Name:
        pe.set_dword_at_offset(file_offset, update_addr(exc.begin_addr))
        pe.set_dword_at_offset(file_offset + 4, update_addr(exc.end_addr))
        pe.set_dword_at_offset(file_offset + 8, exc.unwind_info_addr)
    else:
        rsec.raw = data_replace(rsec.raw, file_offset, get_updated_addr_bytes(exc.begin_addr))
        rsec.raw = data_replace(rsec.raw, file_offset + 4, get_updated_addr_bytes(exc.end_addr))

    if exc.unwind_info.exception_handler:
        # We could use here pe.set_dword_at_* but we'll use the section.raw because all of our modifications
        # are using it
        rsec.raw = data_replace(rsec.raw, rva2ofs(exc.unwind_info.exception_handler_addr),
                                get_updated_addr_bytes(exc.unwind_info.exception_handler))

        scope_list_start_rva = exc.unwind_info.scope_tbl_start_rva
        for scope_entry in exc.unwind_info.scope_list:
            rsec.raw = data_replace(rsec.raw, rva2ofs(scope_list_start_rva),
                                    get_updated_addr_bytes(scope_entry.begin) + get_updated_addr_bytes(scope_entry.end))

            # Which means it's actually a function pointer
            if scope_entry.handler not in {0, 1, -1}:
                rsec.raw = data_replace(rsec.raw, rva2ofs(scope_list_start_rva + 8),
                                        get_updated_addr_bytes(scope_entry.handler))
            rsec.raw = data_replace(rsec.raw, rva2ofs(scope_list_start_rva + 12),
                                    get_updated_addr_bytes(scope_entry.target))

            # Size of SCOPE_ENTRY
            scope_list_start_rva += 16


def update_exception_records(c_handler_addr: int, cpp_handler_addr: int, gshandlercheck_seh_addr: int) -> None:
    """
    The exception records in x64 binaries point to code blocks and handler functions.
    All these code references need to be fixed to point to our new instrumented functions.
    :param c_handler_addr: address of c exception handler func
    :param cpp_handler_addr: address of c++ exception handler func
    :returns: None
    """
    psection = get_sec_by_name(b'.pdata')

    # Initialize the c_handler and gs_handler addresses because each handler needs a different treatment
    # Right now we only take care of c_specific_handler
    seh.g_c_handler = c_handler_addr - pe.OPTIONAL_HEADER.ImageBase if c_handler_addr else 0
    seh.g_cpp_handler = cpp_handler_addr - pe.OPTIONAL_HEADER.ImageBase if cpp_handler_addr else 0
    seh.g_gshandlercheck_seh_handler = gshandlercheck_seh_addr - pe.OPTIONAL_HEADER.ImageBase if gshandlercheck_seh_addr else 0
    if psection:
        pdata = psection.get_data()
        exc_info_dict = {}
        while len(pdata) >= 12:
            begin_addr, end_addr, unwind_info_addr = unpack('<III', pdata[:12])
            if begin_addr == 0:
                break
            exc_info_dict[begin_addr] = ExInfo(begin_addr=begin_addr, end_addr=end_addr,
                                               unwind_info_addr=unwind_info_addr,
                                               unwind_info=UnwindInfo(pe, unwind_info_addr))
            pdata = pdata[12:]

        psec_start_offset = pe.adjust_FileAlignment(psection.PointerToRawData, pe.OPTIONAL_HEADER.FileAlignment)

        # UNWIND_INFO is found in .rdata
        rsec = get_sec_by_name(b'.rdata')

        # It might happen if he didn't have relocations in it
        if not hasattr(rsec, 'raw'):
            build_raw_attr(rsec)

        # The exception table in .pdata is sorted by the function's start address, in an ascending order
        exception_mapping = {update_addr(begin_addr): begin_addr for begin_addr in exc_info_dict}
        for updated_begin_addr in sorted(exception_mapping):
            exc = exc_info_dict[exception_mapping[updated_begin_addr]]
            update_exception_record(exc, psec_start_offset, rsec)

            # Recursively go through each chained exception (we'll probably edit the same function more than once
            # but that's okay)
            while exc.unwind_info.chained_exception:
                chained_exc_rva = exc.unwind_info.chained_exception_addr
                exc = exc.unwind_info.chained_exception
                update_exception_record(exc, rva2ofs(chained_exc_rva), rsec)

            psec_start_offset += 12


def handle_relocations(idata: List) -> List[BaseRelocationData]:
    """
    Update each relocation record to point to the instrumented code
    :param idata: List of segment start and end addresses in .idata segment
    :return: List of relocation records
    """
    updated_relocs: List[BaseRelocationData] = []
    reloc_addrs: List[int] = []
    reloc_types: List[int] = []
    relocation_type_absolute = RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']
    for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
        for reloc in base_reloc.entries:
            if reloc.type == relocation_type_absolute:
                continue

            offset, sec = rva2ofs(reloc.rva), get_sec_by_rva(reloc.rva)
            if is_exe(sec) and not in_range(offset, idata):
                # assume that all relocation are data here
                diff = calc_bytes_added(offset)
                logging.debug(
                    f'[update reloc] {reloc.rva}8Xh {RELOCATION_TYPE[reloc.type][16:]}, diff = {hex(diff)}')
                reloc_addrs.append(reloc.rva + sec.sec_diff + diff)
                reloc_types.append(reloc.type)

                # We keep the original relocations for edge cases we didn't handle
                # This might be unnecessary if we prefer to crash on these cases
                reloc_addrs.append(reloc.rva)
                reloc_types.append(reloc.type)
                sec.raw = update_reloc_raw(reloc.type, sec.raw, offset, idata)
            else:
                logging.debug(f'[update reloc] {reloc.rva}8Xh {RELOCATION_TYPE[reloc.type][16:]}')
                reloc_addrs.append(reloc.rva)
                reloc_types.append(reloc.type)
                if not hasattr(sec, 'raw'):
                    build_raw_attr(sec)
                sec.raw = update_reloc_raw(reloc.type, sec.raw, offset, idata)
    add_to_reloc(updated_relocs, reloc_addrs, reloc_types)
    return updated_relocs


def create_relocs_for_cov_section(updated_relocs: List[BaseRelocationData], args, injections: Dict[int, Code]) -> None:
    """
    Create relocation entry for each reference to .cov section in our instrumentation stubs.
    This will make the OS loader to fix our .cov references for us in case of ASLR.
    :param updated_relocs: List of relocation records
    :param args: run arguments
    :param injections: Dictionary of physical offsets in the file of basic blocks to instrument
    :return: None
    """
    global pe
    reloc_type = pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW'] if is_pe_32bit(pe) else pefile.RELOCATION_TYPE[
        'IMAGE_REL_BASED_DIR64']
    afl_area_ptr = get_sec_by_name(b'.cov').VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
    afl_prev_loc = afl_area_ptr + 0x10000
    if args.callback:
        addr_update_list = [afl_area_ptr + 0x10000 + 0x10, afl_area_ptr + 0x10000 + 0x20]
    elif args.filter:
        addr_update_list = [afl_area_ptr + 0x10000 + 0x10, afl_prev_loc, afl_area_ptr, afl_prev_loc]
    elif args.thread_filter:
        addr_update_list = [afl_area_ptr + 0x10000 + 0x30, afl_prev_loc, afl_area_ptr, afl_prev_loc]
    else:  # single and multi
        addr_update_list = [afl_prev_loc, afl_area_ptr, afl_prev_loc]

    reloc_addrs = []
    reloc_types = []
    snip_len = args.snip_len
    sc_magic_offsets = args.sc_magic_offsets
    for offset in sorted(injections):
        if injections[offset].total_len < snip_len:
            continue
        asm_magics = [i + len(injections[offset].expand + injections[offset].align) for i in sc_magic_offsets]
        addr = update_addr(ofs2rva(offset)) - len(injections[offset].expand)
        for i, magic in enumerate(asm_magics):
            new_bytes = pack_32bit(addr_update_list[i]) if is_pe_32bit(pe) else pack_64bit(addr_update_list[i])
            injections[offset].shellcode = bdata_replace(injections[offset].shellcode, args.sc_magic_offsets[i],
                                                         new_bytes)
            reloc_addrs.append(addr + magic)
            reloc_types.append(reloc_type)

    if args.thread_filter:
        addr_update_list = [afl_area_ptr + 0x10000 + 0x30, afl_area_ptr + 0x10000 + 0x30]
        offset = va2ofs(args.thread_entry)
        asm_magics = [i + len(injections[offset].expand + injections[offset].align) for i in args.init_sc_magic_offsets]
        addr = update_addr(ofs2rva(offset)) - len(injections[offset].expand)
        for i, magic in enumerate(asm_magics):
            new_bytes = pack_32bit(addr_update_list[i]) if is_pe_32bit(pe) else pack_64bit(addr_update_list[i])
            injections[offset].shellcode = data_replace(injections[offset].shellcode, args.init_sc_magic_offsets[i],
                                                        new_bytes)
            reloc_addrs.append(addr + magic)
            reloc_types.append(reloc_type)
    add_to_reloc(updated_relocs, reloc_addrs, reloc_types)


def prepare_new_sections(args, injections: Dict[int, Code]) -> None:
    """
    Duplicate executable sections and prepare the .cov section that will hold the fuzzing bitmap.
    :param args: Runtime arguments
    :param injections: Dictionary of physical offsets in the file of basic blocks to instrument
    :return:
    """
    global pe
    for orig_sec in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        # We're only interested in duplicating code sections
        if is_exe(orig_sec) and orig_sec.SizeOfRawData != 0:
            # empty inject is for triggering the data update later
            if not hasattr(orig_sec, 'addr_set'):
                inject_code(orig_sec.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase, injections)
            sec = duplicate_section(orig_sec, args.enlarge)
            # sec_diff will hold the distance between the original section to the new duplicated section
            setattr(orig_sec, 'sec_diff', sec.VirtualAddress - orig_sec.VirtualAddress)
            # addr_map will hold a summary of addresses to inject code to, and the number of bytes that were added
            # up until that address, from previous instrumentations
            setattr(orig_sec, 'addr_map', {})

    # We take the .data section as a template for our coverage section (.cov)
    # If it's a driver - we need the section to be NonPaged so we can access it from any IRQL
    # Theoretically we can create the section from scratch but that's for a later version
    data_sec = get_sec_by_name(b'.data')
    assert not (is_driver(pe.path) and not data_sec.Characteristics & pefile.SECTION_CHARACTERISTICS[
        'IMAGE_SCN_MEM_NOT_PAGED']), 'Missing .data section with NonPaged characteristic'
    duplicate_section(data_sec, args.enlarge, name=b'.cov', size=0x10fff)


def expand_relative_instructions(relatives_dict: Dict[int, List], injections: Dict[int, Code]) -> Dict[
    int, RelativeInstruction]:
    """
    Process all the relative instructions that were found by IDA parsing.
    :param relatives_dict: A dict of instruction_address:instruction_info_struct.
    :param injections: A dict of all the injections.
    :return: Dict of relative instruction's changes
    """
    # Save the list of addresses that are jumped over
    jmp_map: Dict[int, List[int]] = {}
    relative_instr_dict: Dict[int, RelativeInstruction] = {rel_instr_addr: RelativeInstruction(*rel_struct)
                                                           for rel_instr_addr, rel_struct in relatives_dict.items()}

    for rel_instr_addr in sorted(relative_instr_dict):
        if relative_instr_dict[rel_instr_addr].operand_len == 1:  # short jmp only because only that is expanded
            target_addr = relative_instr_dict[rel_instr_addr].target
            order = -1 if rel_instr_addr > target_addr else 1  # whether the jmp is forward or backwards
            for addr in range(rel_instr_addr, target_addr + order, order):
                if order == 1 and (addr == rel_instr_addr or addr == target_addr):
                    continue
                if addr in jmp_map:
                    jmp_map[addr].append(rel_instr_addr)
                else:
                    jmp_map[addr] = [rel_instr_addr]

    # expand_set saves the unique addresses of jmps that need to be adjusted
    expand_set = set()
    for code_struct in injections.values():
        if code_struct.virtual_address in jmp_map:  # Check if we plan to inject code in the middle of a jmp
            expand_set.update(jmp_map[code_struct.virtual_address])  # If so, save the address of the affected jmp

    # Find all addresses that we expand and are also in the jmp_map
    intersected_addrs = [jmp_map[addr] for addr in expand_set if addr in jmp_map]

    # Flatten the list of lists and update expand_set with the contents of jmp_map
    expand_set.update([addr for jmps in intersected_addrs for addr in jmps])
    for rel_instr_addr in expand_set:
        cmd_len = relative_instr_dict[rel_instr_addr].total_len
        # Divide into 2 because expand_instr returns the hex repr of the expanded command
        num_new_bytes = len(expand_instr(relative_instr_dict[rel_instr_addr].instr_bytes, 0)) // 2 - cmd_len
        # the expanded byte is stored in the next instruction
        inject_code(rel_instr_addr + cmd_len, injections, expand=b'\x00' * num_new_bytes)
    logging.info('Expanded %d of %d branches ' % (len(expand_set), len(relative_instr_dict)))
    return relative_instr_dict


def update_relative_instructions(code_loc: set[int], injections: Dict[int, Code],
                                 relative_instr_dict: Dict[int, RelativeInstruction]) -> None:
    """
    Go through each relative instruction taken from IDA's output and update the instruction's target
    to point to its new location.
    :param code_loc: set of addresses of beginnings of functions
    :param injections: Dictionary of physical offsets in the file of basic blocks to instrument
    :param relative_instr_dict: Dictionary of relative instructions to change
    :return:
    """
    for rel_instr_addr in sorted(relative_instr_dict):
        rel_struct = relative_instr_dict[rel_instr_addr]
        from_ofs = rel_instr_addr
        to_ofs = rel_struct.target
        new_ofs = get_relative_diff(from_ofs, to_ofs,
                                    is_data=is_data_instruction(rel_struct.instr_bytes, to_ofs, code_loc))
        logging.debug(f'[update relative] {hex(rel_instr_addr)} {hex(rel_struct.target)} {hex(to_ofs)} {hex(new_ofs)}')
        cmd_len = rel_struct.total_len
        next_ofs = va2ofs(rel_instr_addr + cmd_len)
        expand_len = len(injections[next_ofs].expand) if next_ofs in injections else 0
        instr = bytes.fromhex(update_instruction(rel_struct.instr_bytes, rel_struct.operand_len + expand_len,
                                                 new_ofs - (cmd_len + expand_len)))
        assert len(instr) == cmd_len + expand_len, "Got unexpected length of expanded instruction"
        if instr[cmd_len:] != b'' and next_ofs in injections:  # update expand
            injections[next_ofs].expand = instr[cmd_len:]
        section = get_sec_by_ofs(va2ofs(from_ofs))
        logging.debug(f'[update relative DEBUG] {hex(from_ofs)}' + ":".join("{:02x}".format(c) for c in instr))
        section.raw = data_replace(section.raw, va2ofs(from_ofs), instr[:cmd_len])


def update_export_table() -> None:
    """
    Update exports in the export table to point to the new instrumented sections.
    :return: None
    """
    global pe
    for export_symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exported_symbol_section = get_sec_by_rva(export_symbol.address)
        if not is_exe(exported_symbol_section):
            continue
        exported_symbol_section = get_sec_by_ofs(export_symbol.address_offset)
        if not hasattr(exported_symbol_section, 'raw'):
            build_raw_attr(exported_symbol_section)
        exported_symbol_section.raw = data_replace(exported_symbol_section.raw, export_symbol.address_offset,
                                                   pack_32bit(update_addr(export_symbol.address)))


def build_raw_attr(section: SectionStructure) -> None:
    """
    Builds the 'raw' attribute for a section that we use to build instrumented sections.
    :param section: The section to build it for
    :return:
    """
    setattr(section, 'raw', bytearray(pack_32bit(section.PointerToRawData) + b'\x00' * (section.PointerToRawData - 4) +
                                      section.get_data()))


def create_append_and_mapping_for_sec(orig_section: SectionStructure, injections: Dict[int, Code],
                                      mapping_dict: Dict[int, int], pe_size: int) -> Tuple[bytearray, str, int]:
    """
    Create the raw data for the new section and the mapping of the new section to the old section.
    :param orig_section: original section before instrumentation
    :param injections: Injections dictionary
    :param mapping_dict: Mapping dictionary
    :param pe_size: size of pefile
    :return: bytearray of raw data, mapping for IDA and the index of the last instrumentation
    """
    append = bytearray(b'')
    mapping_lines = []
    old_idx = orig_section.PointerToRawData
    for idx in orig_section.addr_set:
        # this puts everything together: orig_section.raw[old_idx:idx] == all the data until a
        # (modified short to long jmp), exp == data needed to expand short to long jmp, align is align,
        # code == instrument stub
        append += orig_section.raw[old_idx:idx] + injections[idx].expand + injections[idx].align + injections[
            idx].shellcode
        latest_offset = pe_size + len(append) - injections[idx].total_len + len(injections[
                                                                                    idx].expand)
        latest_offset_section = get_sec_by_ofs(latest_offset)
        logging.debug(f'[merge] idx ={hex(idx)} {hex(latest_offset)}')
        old_ofs = idx - orig_section.PointerToRawData + orig_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        new_ofs = latest_offset - latest_offset_section.PointerToRawData + latest_offset_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        mapping_dict[old_ofs] = new_ofs
        mapping_lines.append(f"{hex(old_ofs)}\t{hex(new_ofs)}\n")
        old_idx = idx
    return append, ''.join(mapping_lines), old_idx


def update_directory_entry(dir_name: str) -> Optional[pefile.Structure]:
    """
    Get's a directory entry name and if it exists, update its address to the instrumented one.
    :param dir_name: Directory name
    :return: The directory structure, if it has contents.
    """
    directory = pe.get_directory_by_name(dir_name)
    # If there's no content, then the virtual address is zero
    if directory.VirtualAddress:
        sec = get_sec_by_rva(directory.VirtualAddress)
        if is_exe(sec):
            directory.VirtualAddress = update_addr(directory.VirtualAddress)
        return directory


def process_pe(ida: Dict, args, injections: Dict[int, Code]) -> Tuple[int, bytearray]:
    """
    The main logic of the instrumentation.
    :param ida: IDA analysis results dict
    :param args: Runtime arguments
    :param injections: Injections dict
    :return: Tuple of the original relocation section size, and the data to add to the end of the PE
    """
    global pe, pe_sorted_sections

    # update section table
    # add new section entry, size of new section is affected by args.enlarge
    if RELOC_SEC_NAME not in pe.sections[-1].Name:
        raise RuntimeError('Expected relocation section (.reloc) at the end of the file but found none')
    if pe.get_length() != get_last_section('fa'):
        raise ValueError('Unexpected data was found after the end of the last section in the file')
    relocs = [i for i, j in enumerate(pe.sections) if RELOC_SEC_NAME in j.Name]
    if relocs:
        reloc = pe.sections.pop(relocs[0])
        pe_sorted_sections.remove(reloc)
        reloc_section_size = reloc.SizeOfRawData
    else:
        reloc = None
        reloc_section_size = 0

    logging.info('Preparing new sections')
    prepare_new_sections(args, injections)
    update_and_verify_section_table(reloc)

    logging.info('Expanding relative jumps')
    relative_instr_dict = expand_relative_instructions(ida['relative'], injections)

    logging.info('Building address map')
    build_address_map(injections)

    logging.info('Updating relative instructions')
    update_relative_instructions(ida['code_loc'], injections, relative_instr_dict)

    logging.info('Updating relocations...')
    updated_reloc = handle_relocations(ida['idata'])

    # add and update reloc from injected
    if hasattr(args, 'pe_afl') and not args.nop:
        create_relocs_for_cov_section(updated_reloc, args, injections)

    updated_dynamic_relocs = get_updated_dynamic_relocs(injections)
    append_reloc = build_reloc_section(updated_reloc, updated_dynamic_relocs, args.verbose)

    logging.info('Updating Export table')
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        update_export_table()

    # Updates for info at Load Configuration:
    # On x86 we update SEHHandlerTable, but on x64 it's not found
    # We update the CFG table - GuardCFFunctionTable
    # Addresses of CFG functions (_icall*) are taken care of by the relocation table
    logging.info("Updating load config")
    load_config_dir = update_directory_entry('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG')
    if load_config_dir and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size > 0x60:
        extra = (pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags & 0xF0000000) >> 28
        update_load_config_tbl(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable,
                               pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount,
                               align=extra + 4)
    # update TLS directory
    update_directory_entry('IMAGE_DIRECTORY_ENTRY_TLS')

    # Update the exception records in .pdata in x64 binaries
    logging.info("Updating exception records")
    update_exception_records(ida['c_handler'], ida['cpp_handler'], ida['gshandlercheck_seh'])

    # TODO: add identification
    # Testing if it's ntoskrnl and ready for KiServiceTable patching
    try:
        ntoskrnl_export_marker = [sym for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols if sym.name == b'NtWaitForSingleObject']
    except AttributeError:
        pass
    else:
        if len(ntoskrnl_export_marker) > 0:
            logging.info("Updating KiServiceTable")
            ntoskrnl_update_KiServiceTable()

    logging.info("Updating the PE headers")
    update_pe_headers(args)

    logging.info('Finalizing...')
    mapping_dict = {}
    append = bytearray(b'')
    mapping_txt = ''
    pe_size = pe.get_length() - reloc_section_size
    # Get only original executable sections (only they have the attribute "addr_set")
    orig_sections = [sec for sec in sorted(pe.sections, key=lambda s: s.PointerToRawData) if hasattr(sec, 'addr_set')]

    logging.info("Creating instrumented code")
    for section_idx, orig_section in enumerate(orig_sections):
        new_sec = get_sec_by_name(orig_section.duplicated_section_name)
        sec_append, sec_mapping_txt, idx = create_append_and_mapping_for_sec(orig_section, injections, mapping_dict,
                                                                             pe_size)
        mapping_txt += sec_mapping_txt
        append += sec_append
        append += orig_section.raw[idx:]
        new_sec_end = new_sec.PointerToRawData + new_sec.SizeOfRawData

        if len(append) + pe_size > new_sec_end:
            raise RuntimeError(f'Injection got too large, use -l {args.enlarge + 1} and try again')
        assert section_idx == len(orig_sections) - 1 or new_sec_end == get_sec_by_name(orig_sections[section_idx + 1].duplicated_section_name).PointerToRawData, 'Some space is unexpected'

        append += b'\x00' * (new_sec_end - len(append) - pe_size)
        delattr(orig_section, 'raw')

    if hasattr(args, 'pe_afl'):
        append += b'\x00' * 0x11000  # reserved for __afl_area_ptr and __afl_prev_loc
        if args.callback or args.filter:
            append = data_replace(append, len(append) - 0x1000 + 0x10, pack_32bit(0xffffffff))

    # log mapping to file, it can be used in IDA directly
    logging.info(f"Writing address mapping to {args.ida_dump.replace('dump', 'mapping')}")
    with open(args.ida_dump.replace('dump', 'mapping'), 'w+') as ff:
        ff.write(mapping_txt)

    # Handle jump tables
    logging.info("Updating jump tables")
    for jmp_target, jump_details in ida['jmp_tbls'].items():
        for jmp_source, element_size, jmp_table_base in jump_details:
            jmp_table_section = get_sec_by_va(jmp_source)
            if hasattr(jmp_table_section, 'raw'):
                jmp_table_section.raw = data_replace(jmp_table_section.raw, va2ofs(jmp_source), pack_32bit(rva2va(update_addr(va2rva(jmp_target))) - jmp_table_base))
            else:
                pe.set_dword_at_offset(va2ofs(jmp_source), rva2va(update_addr(va2rva(jmp_target))) - jmp_table_base)

    build_raw_attr_for_executable_sections()

    # All the needed modifications are contained in the "append" variable which will get appended at the end
    # of the file, so we restore the original sections to their original data by taking it from the "raw" attribute
    for phys_addr_to_inject in sorted(injections):
        section = get_sec_by_ofs(phys_addr_to_inject)
        if hasattr(section, 'raw'):
            section.raw = data_replace(section.raw, phys_addr_to_inject, b'\xCC')  # for debug use

    for section in pe.sections:
        if hasattr(section, 'raw'):
            section.raw = section.raw[unpack_32bit(section.raw[:4]):]
            if not is_exe(section):
                assert len(section.raw) == section.SizeOfRawData, 'Section size has changed'
            logging.info('Updated {}'.format(section.Name.strip(b"\x00").decode('utf-8')))

    return reloc_section_size, append + append_reloc


def update_pe_headers(args) -> None:
    """
    Update some fields in the pe headers, post instrumentation.
    :param args: Runtime arguments
    :return:
    """
    global pe
    pe.OPTIONAL_HEADER.SizeOfImage = get_last_section('rva')
    pe.FILE_HEADER.NumberOfSections += len([sec for sec in pe.sections if hasattr(sec, 'sec_diff')])
    if hasattr(args, 'pe_afl'):
        pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = update_addr(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    logging.debug(f'SizeOfImage={hex(pe.OPTIONAL_HEADER.SizeOfImage)}')
    logging.debug(f'NumberOfSections={hex(pe.FILE_HEADER.NumberOfSections)}')
    logging.debug(f'AddressOfEntryPoint={hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}')
    # clear Bound Import Directory in order to get more space for new section
    bound_import_dir = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT')
    bound_import_dir.VirtualAddress = 0
    bound_import_dir.Size = 0


def load_pe(fname: str):
    """
    Simple wrapper for loading a given PE
    """
    global pe, pe_sorted_sections
    try:
        pe = pefile.PE(fname)
        pe.path = fname
        pe_sorted_sections = SortedSections(pe)
        for section in pe.sections:
            setattr(section, 'is_original', True)
    except Exception as e:
        logging.error(f'Invalid PE file @ {fname}')
        logging.error(str(e))
        quit()


def initialize_instrumentation(args) -> Tuple[PE, Dict]:
    """
    Prepares the PE for instrumentation and loads and fixes the output from IDA's analysis.
    :param args: Runtime arguments
    :return: The PE and the IDA analysis dict
    """
    global pe

    args.enlarge = int(args.enlarge) if args.enlarge else 4

    load_pe(args.pe_file)
    new_name = clear_stub_and_certificate()
    if new_name != pe.path:
        load_pe(new_name)
    build_raw_attr_for_executable_sections()

    # import dump.txt from IDA
    with open(args.ida_dump) as f:
        ida = json.load(f)
    # Json does not support using integers as keys so when dumping it from IDA it gets
    # converted into strings automatically. We need to convert it back to integers for later use
    for key in list(ida['relative'].keys()):
        ida['relative'][int(key)] = ida['relative'].pop(key)
    for key in list(ida['jmp_tbls'].keys()):
        ida['jmp_tbls'][int(key)] = ida['jmp_tbls'].pop(key)
    for key in list(ida['jmp_tbls'].keys()):
        ida['jmp_tbls'][int(key)] = ida['jmp_tbls'].pop(key)
    ida['code_loc'] = {int(addr) for addr in ida['code_loc'].keys()}
    ida['idata'] = map(lambda v: [va2ofs(v[0]), va2ofs(v[1])], ida['idata'])
    return pe, ida


def run(ida: Dict, args, shellcode_for_addr: Dict[int, bytes]) -> None:
    """
    Instrument the PE and save it to a file.
    :param ida: IDA analysis results dict
    :param args: Runtime arguments
    :param shellcode_for_addr: Dict of addresses and shellcodes to inject there
    :return:
    """
    injections_dict: Dict[int, Code] = {}  # the keys are physical offsets in the file of basic blocks to instrument
    # basic block instrument
    for basic_block_address, shellcode in shellcode_for_addr.items():
        inject_code(basic_block_address, injections_dict, shellcode, is_bb_start=True)

    # entry point instrument
    if args.entry:
        inject_code(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase, injections_dict,
                    args.entry.decode('hex'))

    cut_size, append = process_pe(ida, args, injections_dict)

    basename, extension = os.path.splitext(args.pe_file)
    filename = f"{basename}.instrumented{extension}"
    pe.write(filename=filename, append=append, cut=cut_size)
    pe.close()
    logging.info('Removing temporary PE files')
    delete_if_exists(f"{basename}.no_stub{extension}")
    delete_if_exists(f"{basename}.no_certificate.no_stub{extension}")
    delete_if_exists(f"{basename}.no_certificate{extension}")

    logging.info('Fixing PE checksum')
    fix_checksum(filename)
    logging.info(f'Instrumented binary saved to: {filename}')
