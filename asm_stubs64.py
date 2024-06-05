from keystone.keystone import Ks, KS_ARCH_X86, KS_MODE_64

import pefile


def asm(code) -> bytearray:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    return bytearray(ks.asm(code)[0])


def extract_exported_function_bytes(exporting_pe: pefile.PE, funcname: bytes) -> bytes:
    """
    Extracts the instructions bytes of the wanted function from ntoskrnl.exe.
    :param exporting_pe: PE object for the pe file with the wanted exported function
    :param funcname: Function name
    :return: bytes
    """
    matching_symbols = [sym for sym in exporting_pe.DIRECTORY_ENTRY_EXPORT.symbols if sym.name == funcname]
    if not matching_symbols:
        raise ValueError(
            f"The function {funcname.decode('utf-8')} wasn't found in the given kernel file, can't build shellcode")
    export = matching_symbols[0]
    # Read arbitrary large amount of bytes
    func_data = exporting_pe.get_data(export.address, 200)
    # Return only the instructions up until the "ret" (0xc3)
    return func_data[:func_data.find(b'\xc3')]


## Magics
C_ADDR1 = C_ADDR2 = 0x4444444444444444
M_PREV_LOC1 = M_PREV_LOC2 = M_PID = M_AREA_PTR = M_CALLBACK = M_TID = MAGIC = 0x5555555555555555

# Common prefix for our shellcodes, saves our used registers
sc_prefix = '''
push rbx
push rax
pushfq
'''

# Common suffix for our shellcodes, restores our used registers
sc_suffix = '''
popfq
pop rax
pop rbx
'''

# Define different shellcodes
asm_nop = bytearray(b'\x90' * 0x6)

# Simple shellcode that updates the AFL's bitmap
asm_single = f'''
mov rax, [{hex(M_PREV_LOC1)}]           # __afl_prev_loc @ .cov+0x10000
mov rbx, {hex(C_ADDR1)}
xor rbx, rax
mov rax, {hex(M_AREA_PTR)}              # __afl_area_ptr @ .cov
inc byte ptr [rbx + rax]              
mov rax, {hex(C_ADDR2)}
mov [{hex(M_PREV_LOC2)}], rax
'''
# Multi threaded shellcode is not yet implemented
asm_multi = asm_nop

# Shellcode that only updates the AFL's bitmap if the current pid matches the harness's pid
asm_filter = f'''
mov rbx, rax
mov rax, [{hex(M_PID)}]                 # pid @ .cov+0x10000+0x10
cmp rbx, rax                            # rax should contain our pid from PsGetCurrentProcessId
jne skip
mov rax, [{hex(M_PREV_LOC1)}]           # __afl_prev_loc @ .cov+0x10000
mov rbx, {hex(C_ADDR1)}
xor rbx, rax
mov rax, {hex(M_AREA_PTR)}              # __afl_area_ptr @ .cov
inc byte ptr [rbx + rax]              
mov rax, {hex(C_ADDR2)}
mov [{hex(M_PREV_LOC2)}], rax
skip:
'''

# TODO Shellcode that calls an external function for each instrumented block
# Currently not implemented and tested
asm_callback = f'''
mov rbx, rax
mov rax, [{hex(M_PID)}]                  # pid @ .cov+0x10000+0x10
cmp rbx, rax                             # rax should contain our pid from PsGetCurrentProcessId
jne skip
mov rax, [{hex(M_CALLBACK)}]             # callback @ .cov+0x10000+0x20
call qword ptr [rax]
skip:
'''

# Shellcode that initializes the thread id for the next shellcode
asm_thread_filter_init = f'''
mov     rbx, rax
# read thread ID address and check if it's empty
mov 	rax, [{hex(M_TID)}]              # tid @ .cov+0x10000+0x30
cmp 	rax, 0
jne 	skip
mov     rax, rbx
mov 	[{hex(M_TID)}], rax              # tid @ .cov+0x10000+0x30
# restore state
skip:
'''

# Shellcode that only updates the AFL's bitmap if the current thread id matches the harness's pid
asm_thread_filter_generic = f'''
# read desired thread id from memory and get current thread ID
mov     rbx, rax
mov 	rax, [{hex(M_TID)}]             # __afl_prev_loc @ .cov+0x10000 + 0x30
cmp 	rax, rbx
jne 	skip
mov 	rax, [{hex(M_PREV_LOC1)}]       # __afl_prev_loc @ .cov+0x10000
mov 	rbx, {hex(C_ADDR1)}
xor 	rbx, rax
mov 	rax, {hex(M_AREA_PTR)}          # __afl_area_ptr @ .cov
inc 	byte ptr [rbx + rax]              
mov 	rax, {hex(C_ADDR2)}
mov 	[{hex(M_PREV_LOC2)}], rax
# restore state
skip:
'''
