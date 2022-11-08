#
# Copyright (C) 2022 Gal Kristal, Dina Teper
# Copyright (C) 2022 SentinelOne, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import functools
import logging
import re
import pefile
from typing import Optional, Tuple

import instrument
from asm_stubs64 import (asm, extract_exported_function_bytes, C_ADDR1, C_ADDR2, MAGIC, sc_suffix, sc_prefix, asm_nop,
                         asm_single, asm_filter, asm_callback, asm_thread_filter_init, asm_thread_filter_generic)
from utils import pack_64bit, is_pe_32bit, is_driver

LOGGER_FORMAT_NORMAL = '[*] %(message)s'
LOGGER_FORMAT_VERBOSE = '[*] %(asctime)s - %(levelname)s - %(message)s'


def init_shellcodes(args, nt_path: Optional[str]) -> Tuple[bytearray, Optional[bytearray]]:
    """
    Initializes the different instrumentation shellcodes.
    :param args: runtime arguments
    :param nt_path: ntoskrnl path, for driver instrumentation
    :return: Tuple of instrumentation shellcodes
    """
    getpid_func_bytes = b''
    gettid_func_bytes = b''
    if nt_path:
        exporting_pe = pefile.PE(nt_path)
        getpid_func_bytes = extract_exported_function_bytes(exporting_pe, b'PsGetCurrentProcessId')
        gettid_func_bytes = extract_exported_function_bytes(exporting_pe, b'PsGetCurrentThreadId')
    if args.nop:
        return asm_nop, None
    elif args.callback:
        return asm(sc_prefix) + getpid_func_bytes + asm(f"{asm_callback} {sc_suffix}"), None
    elif args.filter:
        return asm(sc_prefix) + getpid_func_bytes + asm(f"{asm_filter} {sc_suffix}"), None
    elif args.thread_filter:
        return asm(sc_prefix) + gettid_func_bytes + asm(f"{asm_thread_filter_generic} {sc_suffix}"), \
               asm(sc_prefix) + gettid_func_bytes + asm(f"{asm_thread_filter_init} {sc_suffix}")
    else:
        # The most basic instrumentation
        return asm(f"{sc_prefix} {asm_single} {sc_suffix}"), None


def update_snippet_with_addr(addr: int, shellcode: bytes) -> bytes:
    """
    replaces the snippet's address magic with the address
    :param addr: The address of the instrumentation
    :param shellcode: The instrumentation shellcode
    :return: instrumentation shellcode with the updated address
    """
    r = shellcode.replace(pack_64bit(C_ADDR1), pack_64bit(addr & 0xFFFF), 1)
    return r.replace(pack_64bit(C_ADDR2), pack_64bit((addr >> 1) & 0xFFFF))


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--nop', help='Instrument with NOPs for testing', action='store_true')
    parser.add_argument('-cb', '--callback',
                        help='Instrument with a callback, which is in the helper driver that\'s written in C',
                        action='store_true')
    parser.add_argument('-tf', '--thread-filter',
                        help='Driver instrumentation that filters only on thread ID (must use "-te" with this option)',
                        action='store_true')
    parser.add_argument('-te', '--thread-entry', help='The address (RVA) of the thread\'s initialization function',
                        type=functools.partial(int, base=0))
    parser.add_argument('-nt', '--ntoskrnl',
                        help='ntoskrnl.exe path for offset extraction (non-optional if instrumenting a driver)')
    parser.add_argument('-e', '--entry', help='Inject code on entry point, ie. -e9090')
    parser.add_argument('-l', '--enlarge', help='Enlarge factor for sections, default=4')
    parser.add_argument('-v', '--verbose', help='Print debug log', action='store_true')
    parser.add_argument('-lf', '--logfile', help='Print log to pe-afl64.log rather than stream', action='store_true')
    parser.add_argument('pe_file', help='Target PE file for instrumentation')
    parser.add_argument('ida_dump', help='dump.txt from IDA (created by ida_dumper.py)')
    return parser.parse_args()


def configure_logger(is_verbose: bool = False, to_file: bool = False):
    level = 'DEBUG' if is_verbose else 'INFO'
    logger_format = LOGGER_FORMAT_VERBOSE if is_verbose else LOGGER_FORMAT_NORMAL
    if to_file:
        logging.basicConfig(level=level, filename='pe-afl64.log', format=logger_format)
    else:
        logging.basicConfig(level=level, format=logger_format)


def main():
    args = parse_arguments()
    args.pe_afl = True
    configure_logger(args.verbose, args.logfile)
    if args.callback:
        raise ValueError("Callback instrumentation is not currently supported")
    # if args.callback and not instrument.is_driver(args.pe_file):
    #    raise Exception("Callback support is on kernel drivers only")
    if args.thread_filter and not args.thread_entry:
        raise ValueError("Must provide thread entry address with the --thread-filter option")

    args.filter = False
    if is_driver(args.pe_file) and not args.thread_filter:
        args.filter = True

    if is_driver(args.pe_file) and not args.ntoskrnl and not args.nop:
        raise ValueError("When instrumenting a driver with PID-aware instrumentation, ntoskrnl path must be provided")

    if is_driver(args.pe_file):
        logging.info('Kernel-mode driver is being instrumented')
    else:
        logging.info('User-mode binary is being instrumented')
        logging.info('Single-thread instrument is on')

    pe, ida = instrument.initialize_instrumentation(args)
    if is_pe_32bit(pe):
        raise ValueError("32 bit will not work. Use the original pe-afl instead")

    main_sc, init_sc = init_shellcodes(args, args.ntoskrnl)
    args.snip_len = len(update_snippet_with_addr(0, main_sc))
    # saves the indexes where the magics start
    args.sc_magic_offsets = [m.start() for m in re.finditer(pack_64bit(MAGIC), update_snippet_with_addr(0, main_sc))]
    if init_sc:
        args.init_sc_magic_offsets = [m.start() for m in re.finditer(pack_64bit(MAGIC), update_snippet_with_addr(0, init_sc))]

    # creating instrumentation shellcode with the updated address for each address
    shellcode_for_addr = {bb_addr: update_snippet_with_addr(bb_addr - pe.OPTIONAL_HEADER.ImageBase, main_sc)
                          for bb_addr in ida['bb']}
    if args.thread_filter:
        shellcode_for_addr[args.thread_entry] = update_snippet_with_addr(args.thread_entry - pe.OPTIONAL_HEADER.ImageBase, init_sc)

    instrument.run(ida, args, shellcode_for_addr)


if __name__ == '__main__':
    main()
