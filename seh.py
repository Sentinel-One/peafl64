#
# Copyright (C) 2022 Gal Kristal, Dina Teper
# Copyright (C) 2022 SentinelOne, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import struct

g_c_handler = 0
g_cpp_handler = 0
g_gshandlercheck_seh_handler = 0

UNW_FLAG_N_HANDLER = 0x0
UNW_FLAG_E_HANDLER = 0x1
UNW_FLAG_U_HANDLER = 0x2
UNW_FLAG_CHAIN_INFO = 0x4


class ExInfo:
    def __init__(self, begin_addr, end_addr, unwind_info, unwind_info_addr):
        self.begin_addr = begin_addr
        self.end_addr = end_addr
        self.unwind_info = unwind_info
        self.unwind_info_addr = unwind_info_addr

    def __str__(self):
        return str([hex(self.begin_addr), hex(self.end_addr), hex(self.unwind_info_addr), self.unwind_info])

    def __repr__(self):
        return str([hex(self.begin_addr), hex(self.end_addr), hex(self.unwind_info_addr), self.unwind_info])


class ScopeEntry:
    def __init__(self, data):
        self.data = data
        self.begin, self.end, self.handler, self.target = struct.unpack('<IIII', data)

    def __repr__(self):
        return str([hex(self.begin), hex(self.end), hex(self.handler), hex(self.target)])


class UnwindInfo:
    def __init__(self, pe, unwind_info_addr):
        self.unwind_info_addr = unwind_info_addr
        self.pe = pe
        ver_flag, size_of_prolog, count_of_codes, frame_reg_ofs = struct.unpack('<BBBB',
                                                                                self.pe.get_data(self.unwind_info_addr,
                                                                                                 4))
        self.version = ver_flag & 0b111
        self.flags = (ver_flag & 0b11111000) >> 3
        self.size_of_prolog = size_of_prolog
        self.count_of_codes = count_of_codes
        self.frame_register = frame_reg_ofs & 0b1111
        self.frame_offset = (frame_reg_ofs & 0b11110000) >> 4
        self.exception_handler = None
        self.exception_handler_addr = None
        self.chained_exception = None
        self.chained_exception_addr = None
        self.scope_list = []
        self.scope_tbl_start_rva = None
        self.count_of_scope_entries = None

        self._parse_data()

    def _parse_data(self):
        if self.flags & (UNW_FLAG_E_HANDLER | UNW_FLAG_U_HANDLER):
            self.exception_handler_addr = self.unwind_info_addr + 4 + 2 * ((self.count_of_codes + 1) & ~1)
            self.exception_handler, self.count_of_scope_entries = struct.unpack('<II', self.pe.get_data(
                self.exception_handler_addr, 8))
            self.scope_tbl_start_rva = self.exception_handler_addr + 8
            # Currently I only handle _C_specific_handler and __GSHandlerCheck_SEH exceptions
            # and not __GSHandlerCheck __CxxFrameHandler3 __GSHandlerCheck_EH etc..
            if (g_c_handler != 0 and self.exception_handler == g_c_handler) or \
                    (g_gshandlercheck_seh_handler != 0 and self.exception_handler == g_gshandlercheck_seh_handler):
                for i in range(self.count_of_scope_entries):
                    self.scope_list.append(ScopeEntry(self.pe.get_data(self.scope_tbl_start_rva + i * 16, 16)))
            else:
                self.count_of_scope_entries = 0

        # If it's chained, recursively build exception info structs
        elif self.flags & UNW_FLAG_CHAIN_INFO:
            self.chained_exception_addr = self.unwind_info_addr + 4 + 2 * ((self.count_of_codes + 1) & ~1)
            begin_addr, end_addr, unwind_info_addr = struct.unpack('<III',
                                                                   self.pe.get_data(self.chained_exception_addr, 12))
            self.chained_exception = ExInfo(begin_addr=begin_addr, end_addr=end_addr,
                                            unwind_info_addr=unwind_info_addr,
                                            unwind_info=UnwindInfo(self.pe, unwind_info_addr))

    def __repr__(self):
        if self.flags & UNW_FLAG_CHAIN_INFO:
            return str(
                'Version: %s | Flags: %s | SizeOfProlog: %s | CountOfCode: %s | FrameRegister: %s | FrameOffset: %s \n\tChainedException: %s' % (
                    bin(self.version),
                    bin(self.flags), hex(self.size_of_prolog), hex(self.count_of_codes), hex(self.frame_register),
                    hex(self.frame_offset),
                    self.chained_exception))
        elif self.flags & (UNW_FLAG_E_HANDLER | UNW_FLAG_U_HANDLER):
            return str(
                'Version: %s | Flags: %s | SizeOfProlog: %s | CountOfCode: %s | FrameRegister: %s | FrameOffset: %s %s' % (
                    bin(self.version),
                    bin(self.flags), hex(self.size_of_prolog), hex(self.count_of_codes), hex(self.frame_register),
                    hex(self.frame_offset), '| ExceptionHandler: %s' % (hex(self.exception_handler))))
        else:
            return str(
                'Version: %s | Flags: %s | SizeOfProlog: %s | CountOfCode: %s | FrameRegister: %s | FrameOffset: %s' % (
                    bin(self.version),
                    bin(self.flags), hex(self.size_of_prolog), hex(self.count_of_codes), hex(self.frame_register),
                    hex(self.frame_offset)))
