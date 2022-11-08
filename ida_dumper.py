#
# Copyright (C) 2022 Gal Kristal, Dina Teper
# Copyright (C) 2022 SentinelOne, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import re

import idaapi
from typing import List, Dict
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from idautils import ida_bytes, Functions, Heads, Segments
import idc
from idc import set_color, CIC_ITEM

## Globals
g_basic_blocks: List = []
g_relative_instructions: Dict = {}
g_rip_relative_instructions: Dict = {}
g_idata_section_info: List = []
g_jmp_tbls: Dict = {}
f_c_handler, f_cpp_handler, f_gshandlercheck_seh = None, None, None
g_func_addrs: Dict = {}
g_possible_code: List = []

# Global disassembler object
g_disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
g_disassembler.detail = True

## lambdas ##
# Byte array to hex repr in python2
ba2hex = lambda ba: "".join("%02x" % b for b in ba)

## Constants
BASIC_BLOCK_COLOR = 0x6699ff
EXPLICITLY_INCLUDED_COLOR = 0xffffff
EXPLICITLY_EXCLUDED_COLOR = 0x0


def parse_relative(ea):
    """
    Identify if the asm code at the given address contains a relative command
    :param ea: Address to test
    :return: (command in hex bytes, offset in hex bytes)
    """
    buf = idc.get_bytes(ea, idc.get_item_size(ea))
    idx = 0
    mpx_candidate = False

    # call (e8), http://x86.renejeschke.de/html/file_module_x86_id_26.html
    # jmp (eb/e9), http://x86.renejeschke.de/html/file_module_x86_id_147.html
    # jxx (0F 80/0F 81/0F 82/0F 83/0F 84/0F 85/0F 86/0F 87/0F 88/0F 89/0F 8A/0F 8B/0F 8C/0F 8D/0F 8E/0F 8F/70/71/72/73/74/75/76/77/78/79/7A/7B/7C/7D/7E/7F), http://x86.renejeschke.de/html/file_module_x86_id_146.html
    # jcxz/jecxz (67 e3/e3)
    # loop/loope/loopz/loopne/loopnz (e0/e1/e2), http://x86.renejeschke.de/html/file_module_x86_id_161.html
    if buf[idx] == 0xf2:
        idx += 1
        mpx_candidate = True

    if buf[idx] in {0xe0, 0xe1, 0xe2, 0xe3, 0xe8, 0xe9, 0xeb}:
        idx += 1
    elif buf[idx] == 0x0f and (0x80 <= buf[idx + 1] <= 0x8f):
        idx += 2
    elif 0x70 <= buf[idx] <= 0x7f:
        idx += 1
    elif buf[idx] == 0x67 and buf[idx + 1] == 0xe3:
        idx += 2

    if mpx_candidate and idx == 1:
        idx = 0

    if idx:
        return buf[0:idx], buf[idx:]
    else:
        return None, None


def add_relative_instruction(ea):
    """
    Identify if the asm code at the given address contains a relative command.
    If it is, add it to the global dict of addresses of relative commands
    :param ea: Address to test
    :return: None
    """
    global g_relative_instructions
    # need operand length, so parse it manually
    instruction_bytes, operand = parse_relative(ea)
    if instruction_bytes and operand:
        assert len(idc.print_operand(ea, 1)) == 0, 'more than 1 operand'
        assert len(operand) == 1 or len(operand) == 4, 'operand is not rel32'
        g_relative_instructions[ea] = [idc.get_operand_value(ea, 0), instruction_bytes.hex(), len(operand),
                                       len(instruction_bytes + operand)]
        return True
    return False


def add_rip_relative_inst(ea):
    """
    If the instruction at the given address is x64 rip-relative one, adds it to the "relative" dict
    :param ea: Address of instruction to test
    """
    global g_relative_instructions
    # Go through all the instructions parsed (should be only one in this case)
    buf = idc.get_bytes(ea, idc.get_item_size(ea))
    res = False
    for ins in g_disassembler.disasm(buf, 0):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.value.mem.base == X86_REG_RIP:
                res = True
                g_relative_instructions[ea] = [ins.disp + ea + len(ins.bytes), ba2hex(ins.bytes), ins.disp_size,
                                               len(ins.bytes)]
    return res


def add_basic_block(ea, op):
    """
    Identify if the asm code at the given address is the start of a basic block.
    Basic block for us is a conditional jump/call/loop.
    :param ea: Address to test
    :return: None
    """
    global g_basic_blocks

    # validating branch, ie. jmp near ptr get_wide_dword_1007F84+1
    operand = idc.get_operand_value(ea, 0)
    if idc.prev_head(idc.next_head(operand)) != operand and idc.get_operand_type(ea, 0) in [idc.o_imm, idc.o_far,
                                                                                            idc.o_near]:
        return

    # skip non-conditional branch
    if op in ('call', 'jmp'):
        return

    # identify as basic block, jxx/loop true/false target
    g_basic_blocks.append(idc.next_head(ea))
    g_basic_blocks.append(operand)


def set_basic_block_colors():
    """
    Helper function to color the start of every basic block we identified
    :return: None
    """
    global g_basic_blocks
    for ea in g_basic_blocks:
        set_color(ea, CIC_ITEM, BASIC_BLOCK_COLOR)


def check_unicode(ea):
    """
    Check if an address is of a unicode/wide string.
    :param ea: Address
    :return: None
    """
    if idc.get_type(ea) in ('const WCHAR', 'WCHAR', 'wchar_t'):
        ida_bytes.create_strlit(ea, 0, idc.STRTYPE_C_16)
        idc.auto_wait()
        if idc.get_str_type(ea) and idc.get_str_type(ea) & 0xFF != idc.STRTYPE_C_16 and idc.get_wide_word(ea) != 0:
            print('[WARN] Possible unicode @', ea)


def check_suspicious_data(segea):
    """
    Search the data of a segment for executable code instructions.
    Could be useful in case IDA missed it.
    :param segea: Segment's start address
    :return:
    """
    global g_possible_code
    func_end_addrs = [idc.find_func_end(funcea) for funcea in Functions(segea, idc.get_segm_end(segea))]
    idc_get_wide_dword = idc.get_wide_dword
    idc_get_wide_byte = idc.get_wide_byte
    for idx, func_end_addr in enumerate(func_end_addrs):
        ofs = func_end_addr
        while idc_get_wide_byte(ofs) == 0xCC or idc_get_wide_byte(ofs) == 0x90:
            ofs += 1
        if idc.get_wide_word(ofs) == 0xff8b:  # mov edi, edi
            idc.create_insn(ofs)
            continue
        for addr in range(ofs, ofs + 0x80):
            addr_wide_byte = idc_get_wide_byte(addr)
            addr_wide_dword = idc_get_wide_dword(addr)
            addr_disasm = idc.GetDisasm(addr)
            if (idc.is_code(idc.get_full_flags(addr)) or
                    (idc.get_str_type(addr) is not None) or  # string
                    (idc.get_type(addr) is not None) or  # struct
                    ('offset' in addr_disasm or 'rva' in addr_disasm) or  # valid data
                    ('.' in addr_disasm) or  # floating point
                    (addr_wide_dword == 0xfffffffe or addr_wide_dword == 0xFFFFFFE4) or  # GSCookieOffset
                    ((addr_wide_dword >> 8) == 0) or  # integer
                    ('align' in addr_disasm)  # alignment
            ):
                break
            if (addr_wide_byte in [0xe0, 0xe1, 0xe2, 0xe3, 0xe8, 0xe9, 0xeb] or  # search for branch
                    (0x70 <= addr_wide_byte <= 0x7f) or
                    (addr_wide_byte == 0x67 and idc_get_wide_byte(addr + 1) == 0xe3) or
                    (addr_wide_byte == 0x0f and (0x80 <= idc_get_wide_byte(addr + 1) <= 0x8f))):
                g_possible_code.append(addr)
                break
    idc.auto_wait()


def calculate_jumptable_size(ea: int, parsed_size: int) -> int:
    """
    Uses a heuristic to calculate the number of cases in a jumptable.
    This is relevant in cases where IDA miscalculates.
    @param ea: Address of the jumptable
    @param parsed_size: The size of the jumptable according to IDA
    @return: The number of cases in a jumptable.
    """
    element_num = parsed_size
    ## Jumptable heuristics
    # Before the switch jump, there's a check that the jump is within bounds
    # For example, a switch-case of 5 cases, will have 'cmp eax, 4; ja label_default'
    # We're searching for that comparison.
    # If the jumptable uses an additional indirect table then we discard our previous check and trust IDA's parsing.
    # TODO Calculate the number of elements more precisely
    inc_up = ('jae', 'jnb', 'jnc')
    inc_down = ('jbe', 'jna')
    non_inc_up = ('ja', 'jnbe')
    non_inc_down = ('jb', 'jnae', 'jc')

    MAX_STEPS_BACK = 10
    prev_insn = idc.prev_head(ea)
    heur_element_num = 0
    found_indirect_table = False
    for i in range(MAX_STEPS_BACK):
        if idc.print_insn_mnem(prev_insn) == 'cmp':
            heur_element_num = idc.get_operand_value(prev_insn, 1) + 1
            break
        # This is indicative of an additional indirect table usage
        elif idc.print_insn_mnem(prev_insn) == 'movzx' and idc.print_operand(prev_insn, 0).endswith('ax'):
            found_indirect_table = True
        prev_insn = idc.prev_head(prev_insn)
    if found_indirect_table == False and heur_element_num > element_num:
        print(f"At {hex(ea)}: Jumptable heuristic was used, parsed size: {element_num}, "
              f"heur size: {heur_element_num} (Found indirect: {found_indirect_table})")
        element_num = heur_element_num
    return element_num

def check_jump_table(ea: int) -> None:
    """
    Jump tables use hardcoded offsets that needs to be adjusted too.
    Fortunately, IDA recognizes and parses them pretty well
    :param ea: The address of the jmp table
    """
    switch_info = idaapi.get_switch_info(ea)
    if not switch_info or switch_info.jumps == 0:
        return

    global g_jmp_tbls, g_basic_blocks
    func_dict = {1: ida_bytes.get_byte, 2: ida_bytes.get_16bit, 4: ida_bytes.get_wide_dword}
    loc = switch_info.jumps
    element_num = calculate_jumptable_size(ea, switch_info.get_jtable_size())
    element_size = switch_info.get_jtable_element_size()
    elbase = switch_info.elbase
    if element_size == 4:
        for num in range(0, element_num):
            table_entry = loc + num * element_size
            if func_dict[element_size](table_entry) == 0:
                print(f"At {hex(ea)}: found empty entry (idx {num})")
                continue
            jmp_target = func_dict[element_size](table_entry) + elbase
            if not g_jmp_tbls.get(jmp_target):
                g_jmp_tbls[jmp_target] = []
            g_jmp_tbls[jmp_target].append((table_entry, element_size, elbase))
            g_basic_blocks.append(jmp_target)


def identify_seh_handlers():
    """
    This is a best-effort code to identify common default exception handler functions,
    to use later in instrumentation when we patch the exception records for x64 binaries.
    """
    global f_c_handler, f_cpp_handler, f_gshandlercheck_seh
    for func_addr in Functions():
        func_name = idc.get_func_name(func_addr)
        if func_name == '__C_specific_handler':
            f_c_handler = func_addr
        elif func_name == '__GSHandlerCheck':
            f_cpp_handler = func_addr
        elif func_name == '__GSHandlerCheck_SEH':
            f_gshandlercheck_seh = func_addr


def output_to_file():
    """
    Gather all collected data into a dict and dump it into a json file.
    :return:
    """
    ida_dump = {'bb': g_basic_blocks, 'relative': g_relative_instructions, 'rip_inst': g_rip_relative_instructions,
                'idata': g_idata_section_info, 'code_loc': g_func_addrs,
                'jmp_tbls': g_jmp_tbls, 'c_handler': f_c_handler, 'cpp_handler': f_cpp_handler,
                'gshandlercheck_seh': f_gshandlercheck_seh}
    print('[INFO]', str(len(g_basic_blocks)), 'blocks')
    print('[INFO]', str(len(g_relative_instructions)), 'branches')
    print('[INFO]', idc.get_input_file_path() + '.dump.json is created')
    with open(idc.get_input_file_path() + '.dump.json', 'w+') as f:
        json.dump(ida_dump, f)


def partial_exclude(start, end=None):
    """
    Exclude functions by offsets from the list of basic blocks we instrument.
    Examples: partial_exclude(ScreenEA()), partial_exclude(0x401020, 0x401040)
    :param start: Functions' start address
    :param end: Functions' end address
    :return: None
    """
    global g_basic_blocks
    if end is None:
        # clear whole function
        start = idc.get_next_func(idc.get_prev_func(start))
        end = idc.find_func_end(start)
    for head in Heads(start, end):
        if head in g_basic_blocks:
            set_color(head, CIC_ITEM, EXPLICITLY_EXCLUDED_COLOR)
            g_basic_blocks.remove(head)


def partial_exclude_by_name(expr):
    """
    Exclude functions by regex from the list of basic blocks we instrument.
    Example: partial_exclude_by_name('(_?Cm|_Hv[^il])')
    :param expr: regex of function names
    :return: None
    """
    global g_basic_blocks
    func_finder = lambda x: re.search(expr, idc.get_func_name(x))
    funcs_to_exclude = set(filter(func_finder, g_basic_blocks))
    for func in funcs_to_exclude:
        set_color(func, CIC_ITEM, EXPLICITLY_EXCLUDED_COLOR)
    g_basic_blocks = list(set(g_basic_blocks) - funcs_to_exclude)


def partial_include_by_name(expr):
    """
    Include only functions that match the given regex in the list of basic blocks we instrument.
    Example: partial_include_by_name('(_?Cm|_Hv[^il])')
    :param expr: regex of function names
    :return: None
    """
    global g_basic_blocks
    func_finder = lambda x: re.search(expr, idc.get_func_name(x))
    funcs_to_include = set(filter(func_finder, g_basic_blocks))
    for func in set(g_basic_blocks) - funcs_to_include:
        set_color(func, CIC_ITEM, EXPLICITLY_INCLUDED_COLOR)
    g_basic_blocks = list(funcs_to_include)


def process_segment(segment_start, segment_end):
    """
    Inspects each command in a segment for relevant things, such as basic blocks and relative commands.
    :param segment_start: Segment start address
    :param segment_end: Segment end address
    :return: None
    """
    global g_func_addrs
    # check_suspicious_data(segment_start) # Currently commented out because it looks unnecessary, will be verified later
    func_start = None
    # This goes through each instruction or data item in the segment
    for addr in Heads(segment_start, idc.get_segm_end(segment_end)):
        # check_unicode(addr) # Currently commented out because it looks unnecessary, will be verified later
        if idc.is_code(idc.get_full_flags(addr)):
            if not func_start:
                func_start = addr
            # TODO: we parse the instruction both in add_relative_instruction and in add_rip_relative, can probably be optimized
            # these flags are for optimization and are meant to avoid unnecessary func calls.
            # If an instruction is relative, it cannot be rip relative. If an instruction is rip relative it cannot be a jump table.
            is_rip_rel = False
            is_rel = False
            op = idc.print_insn_mnem(addr)
            if op.startswith(('call', 'j', 'loop')):
                add_basic_block(addr, op)
                is_rel = add_relative_instruction(addr)
            if not is_rel:
                is_rip_rel = add_rip_relative_inst(addr)
            if not is_rip_rel:
                check_jump_table(addr)
        else:
            if func_start is not None:
                g_func_addrs[func_start] = addr
                func_start = None


def process_file():
    """
    The main function of this script. This parses the PE and outputs it to a file.
    :return:
    """
    global g_basic_blocks, g_idata_section_info
    idc.auto_wait()
    g_idata_section_info = [[x, idc.get_segm_end(x)] for x in Segments() if
                            (idaapi.getseg(x).perm & idaapi.SEGPERM_EXEC) and idc.get_segm_name(x) == '.idata']
    segments = [[x, idc.get_segm_end(x)] for x in Segments() if
                (idaapi.getseg(x).perm & idaapi.SEGPERM_EXEC) and idc.get_segm_name(x) != '.idata']
    for segment_start, segment_end in segments:
        process_segment(segment_start, segment_end)

    g_basic_blocks = sorted(list(set(g_basic_blocks)))
    set_basic_block_colors()
    identify_seh_handlers()

    # dump result
    print(
        '[INFO] To do partial instrumentation use the functions partial_exclude/partial_exclude_by_name/partial_include_by_name')
    print('[INFO] And then call output_to_file() again')
    output_to_file()


if __name__ == '__main__':
    process_file()
