#
# Copyright (C) 2022 Gal Kristal, Dina Teper
# Copyright (C) 2022 SentinelOne, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from typing import List, Iterable, Optional, Any, Union, Dict
import os
import struct
import bisect
import pefile

pack_64bit = lambda v: v.to_bytes(8, 'little')
pack_32bit = lambda v: v.to_bytes(4, 'little', signed=True) if v < 0 else v.to_bytes(4, 'little', signed=False)
pack_16bit = lambda v: v.to_bytes(2, 'little')
unpack_32bit = unpack_64bit = lambda v: int.from_bytes(v, 'little')
is_value_32bit = lambda v: -0x80000000 <= v < 0x80000000
bdata_replace = lambda s1, idx, s2: s1[:idx] + s2 + s1[idx + len(s2):]
delete_if_exists = lambda p: os.remove(p) if os.path.isfile(p) else None
is_driver = lambda s: '.sys' in s or 'ntoskrnl' in s
is_exe = lambda s: bool(s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) \
    if hasattr(s, 'Characteristics') else False
dword = lambda v: pack_32bit(v & 0xFFFFFFFF).hex()
is_pe_32bit = lambda pe: True if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] else False


def data_replace(s1, idx, s2):
    s1[idx:idx+len(s2)] = s2
    return s1


def in_range(val: int, pairs: Iterable[List]) -> bool:
    for a, b in pairs:
        if a <= val < b:
            return True
    return False


def get_closest_or_equal(seq: List, val) -> Optional[Any]:
    """
    Returns the item closest to val (ret<=val) in an ordered list.
    :param seq: Ordered list
    :param val: Value to search
    :return:
    """
    if val < seq[0]:
        return None
    return seq[bisect.bisect_right(seq, val) - 1]


def remove_dos_stub(fname: str) -> str:
    """
    Remove the DOS stub from the PE header to free some space for us in the headers.
    :param fname: PE name
    :return: New PE name
    """
    pe = pefile.PE(fname)
    with open(fname, 'rb') as f:
        buf = f.read()
    replace = buf[pe.DOS_HEADER.e_lfanew:pe.OPTIONAL_HEADER.SizeOfHeaders] + b'\x00' * (pe.DOS_HEADER.e_lfanew - 0x40)
    buf = buf[:0x40 - 4] + struct.pack('<I', 0x40) + replace + buf[pe.OPTIONAL_HEADER.SizeOfHeaders:]
    name, extension = fname.rsplit('.', 1)
    name = name + '.no_stub.' + extension
    with open(name, 'wb') as f:
        f.write(buf)
    pe.close()
    return name


def remove_certificate(fname: str) -> str:
    """
    Remove the certificate from the PE as it's not needed any more. Creates a new PE file with the certificate removed.
    :param fname: PE name
    :return: New PE name
    """
    pe = pefile.PE(fname)
    d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_SECURITY')
    assert d.VirtualAddress + d.Size == pe.get_length(), 'some overlays behind certificate'
    dir_size = d.Size
    d.VirtualAddress = 0
    d.Size = 0
    name, extension = fname.rsplit('.', 1)
    name = name + '.no_certificate.' + extension
    pe.write(filename=name, cut=dir_size)
    pe.close()
    return name


def fix_checksum(fname: str) -> None:
    """
    recalculates and resets PE file's checksum
    :param fname: file name
    """
    pe = pefile.PE(fname)
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(filename=fname)
    pe.close()


class SortedSections:
    """
    Sorted sections of a PE file.
    The class allows a quicker access to the sections by their file offset
    """

    def __init__(self, pe: pefile.PE):
        self.sec_offsets = []
        self.section_mapping: Dict[int, pefile.SectionStructure] = {}
        self.virtual_sec_offsets = []
        self.virtual_section_mapping: Dict[int, pefile.SectionStructure] = {}
        self.max_virtual_offset = 0
        self.extend(pe.sections)

    def _update_virtual_offsets_list(self) -> None:
        """
        When treating offsets to virtual addresses (found when Virtual Address is converted to offset using va2ofs)
        we need to look at the virtual size of each section.
        In this scenario, sections can overlap and sometimes be ignored completely.
        :return: None
        """
        new_sec_virtual_offsets = []
        new_virtual_section_mapping = {}
        max_offset = 0
        for sec_offset in self.sec_offsets:
            section = self.section_mapping[sec_offset]
            sec_end = sec_offset + section.Misc_VirtualSize
            if sec_offset >= max_offset:
                new_sec_virtual_offsets.append(sec_offset)
                new_virtual_section_mapping[sec_offset] = section
                max_offset = sec_end
            elif sec_end >= max_offset:
                new_sec_virtual_offsets.append(max_offset)
                new_virtual_section_mapping[max_offset] = section
                max_offset = sec_end
        self.virtual_sec_offsets = new_sec_virtual_offsets
        self.virtual_section_mapping = new_virtual_section_mapping
        self.max_virtual_offset = max_offset

    def extend(self, sections: Union[pefile.SectionStructure, List[pefile.SectionStructure]]) -> None:
        """
        Extend the list of sections.
        :param sections: list of sections to add to the index
        :return: none
        """
        if isinstance(sections, pefile.SectionStructure) and sections.get_PointerToRawData_adj() not in self.section_mapping:
            sec_start_offset = sections.get_PointerToRawData_adj()
            bisect.insort_right(self.sec_offsets, sec_start_offset)
            self.section_mapping[sec_start_offset] = sections
        elif isinstance(sections, list):
            for section in sections:
                if section not in self.sec_offsets:
                    bisect.insort_right(self.sec_offsets, section.get_PointerToRawData_adj())
                    self.section_mapping[section.get_PointerToRawData_adj()] = section
        self._update_virtual_offsets_list()

    def remove(self, sections: Union[pefile.SectionStructure, List[pefile.SectionStructure]]) -> None:
        """
        Remove sections from the list of sections.
        :param sections: sections to remove
        :return: none
        """
        if isinstance(sections,
                      pefile.SectionStructure) and sections.get_PointerToRawData_adj() in self.section_mapping:
            self.sec_offsets.remove(sections.get_PointerToRawData_adj())
            self.section_mapping.pop(sections.get_PointerToRawData_adj())
        elif isinstance(sections, list):
            for section in sections:
                if section in self.sec_offsets:
                    self.sec_offsets.remove(section.get_PointerToRawData_adj())
                    self.section_mapping.pop(section.get_PointerToRawData_adj())
        self._update_virtual_offsets_list()

    def get_sec_by_offset(self, offset: int, is_virtual_offset: bool = False) -> Optional[pefile.SectionStructure]:
        """
        Get the section at the given offset.
        :param offset: offset to search for
        :param is_virtual_offset: is provided offset a virtual offset
        :return: section at the given offset if found, None otherwise
        """
        # Boundaries check
        if offset < self.sec_offsets[0] or (is_virtual_offset and offset > self.max_virtual_offset):
            return None

        if is_virtual_offset:
            sec_offset = bisect.bisect_right(self.virtual_sec_offsets, offset) - 1
            return self.section_mapping.get(self.virtual_sec_offsets[sec_offset])
        else:
            sec_offset = bisect.bisect_right(self.sec_offsets, offset) - 1
            return self.section_mapping.get(self.sec_offsets[sec_offset])

    def reset_state(self):
        """
        Reset the state of the index.
        :return: none
        """
        self.sec_offsets = []
        self.section_mapping = {}
        self.virtual_sec_offsets = []
        self.virtual_section_mapping = {}
