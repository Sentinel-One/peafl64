## Overview
peafl64 is a static instrumentation tool for x64 PEs in Windows.  
Static instrumentation is the practice of editing executable files and adding code to specific locations in them.    
The instrumentation adds code to the start of every basic block in the binary, logging the execution flow in an AFL-compatible way.  
It allows us to fuzz binaries in Usermode (using WinAFL) and Kernelmode (using kAFL) without access to their source code.  

There are other ways of fuzzing Windows binaries; in this project we chose to focus on static instrumentation because it's the fastest method.  

This project builds on the [pe-afl](https://github.com/wmliang/pe-afl) tool by wmliang, with added x64 support.

## Features
* Full Windows x64 binaries support
* High performance
* Supports instrumenting with process ID or thread ID filtering
* Handles relocations, exception tables, relative instructions, jump tables, imports, exports and more
* Compatible with WinAFL (headers included) and kAFL
  
## Usage
### IDA Analysis
The instrumentation script requires an IDA analysis output.  
To create it, run the provided `ida_dumper.py` script in IDA.  
The script requires IDA 7+ and python3.8+.  

### Instrumentation
```
usage: pe_afl.py [-h] [-n] [-cb] [-tf] [-te THREAD_ENTRY] [-nt NTOSKRNL] [-e ENTRY] [-l ENLARGE] [-v] [-lf] pefile ida_dump

positional arguments:
  pefile                Target PE file for instrumentation
  ida_dump              dump.json from IDA (created by ida_dumper.py)

optional arguments:
  -h, --help            show this help message and exit
  -n, --nop             Instrument with NOPs for testing
  -cb, --callback       Instrument with a callback, which is in the helper driver that's written in C
  -tf, --thread-filter  Driver instrumentation that filters only on thread ID (must use "-te" with this option)
  -te THREAD_ENTRY, --thread-entry THREAD_ENTRY
                        The address (RVA) of the thread's initialization function
  -nt NTOSKRNL, --ntoskrnl NTOSKRNL
                        ntoskrnl.exe path for offset extraction (non-optional if instrumenting a driver)
  -e ENTRY, --entry ENTRY
                        Inject code on entry point, ie. -e9090
  -l ENLARGE, --enlarge ENLARGE
                        Enlarge factor for sections, default=4
  -v, --verbose         Print debug log
  -lf, --logfile        Print log to pe-afl64.log rather than stream
  ```

**Instrumenting usermode binary with NOPs**
```
PS pe-afl-64> python .\pe_afl.py -n C:\Work\cmd.exe C:\Work\cmd.exe.dump.json
[*] User-mode binary is being instrumented
[*] Single-thread instrument is on
[*] Preparing new sections
[*] Added section .text^
[*] Added section .cov
[*] Expanding relative jumps
[*] Expanded 3874 of 14353 branches
[*] Building address map
[*] Updating relative instructions
[*] Updating relocations...
[*] Updating Export table
[*] Updating load config
[*] Updating exception records
[*] Updating the PE headers
[*] Finalizing...
[*] Creating instrumented code
[*] Writing address mapping to C:\Work\cmd.exe.mapping.txt
[*] Updating jump tables
[*] Updated .text
...
[*] Removing temporary PE files
[*] Fixing PE checksum
[*] Instrumented binary saved to: C:\Work\cmd.instrumented.exe
```
**Instrumenting kernelmode binary with process ID filtering**
```
python .\pe_afl.py -l 6 -nt "C:\Work\ntoskrnl.exe" "C:\Work\driver.sys" "C:\Work\driver.sys.dump.json"
```
**Instrumenting kernelmode binary with thread ID filtering and verbose output**
```
python .\pe_afl.py -v -tf -te 0x40000 -l 6 -nt "C:\Work\ntoskrnl.exe" "C:\Work\ntoskrnl.exe" "C:\Work\ntoskrnl.exe.dump.json"
```

## How to replace Windows drivers
First you'll need to check if your machine is booting using BIOS or UEFI.   
For Hyper-V machines: Gen 1 machines are BIOS based, and the Gen 2 are UEFI based.  
If your machine is BIOS based then you need to patch `winload.exe`:
* Get a copy of winload.exe from your VM and find the function `ImgpValidateImageHash` in it
* Patch the return value to always return 0 in rax. For example replace `mov eax, edi` with `xor eax, eax` in the last code block of the function
* Copy the patched winload to system32 folder and run `bcdedit /set path \Windows\system32\winload2.exe`
  
If your machine is booted using UEFI then use [EfiGuard](https://github.com/Mattiwatti/EfiGuard) util to patch `winload.efi`.  
Command cheatsheet if using Hyper-V Manager:
1. Create a new hard drive for the Virtual Machine
2. Use the supplied FAT.vhdx in the Tools folder (or create one yourself) containing the UefiShell+EfiGuard module with the new hard driver
3. Change the machine's boot order, so the new hard drive is first in order
4. After boot, while in the UefiShell run the following commands:
```
FS1:
cd EFI/Boot
Load EfiGuard.Dxe.efi
FS0:
\EFI\Boot\bootx64.efi
```
  
Then instrument your driver of choice. To load an instrumented driver on a Windows machine it must be signed, 
and a self-signing certificate is enough to pass the OS's demands:
```shell
# In elevated powershell terminal
$c = New-SelfSignedCertificate -Type CodeSigningCert -KeyUsage DigitalSignature -Subject 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
Set-AuthenticodeSignature .\driver.instrumented.sys -Certificate $c -Force
```
If the driver you instrumented is already used by the system, use these commands (as admin) to replace the driver's file:
```batch
set NAME=mydriver.sys
icacls %NAME% /save C:\windows\temp\%NAME%.icacls
takeown /F %NAME%
icacls %NAME% /grant Everyone:F
move %NAME% %NAME%.bak
move instrumented_driver.sys %NAME%
icacls . /restore C:\windows\temp\%NAME%.icacls
```
  
Then run:
```batch
bcdedit /set recoveryenabled no
bcdedit /set nointegritychecks on
shutdown -t 0 -r
```


## WinAFL Fuzzing
Integration with WinAFL is by compiling a harness using the provided headers.  
Alongside the headers there's `example.c`, which is a sample program that shows how to use them.  
The provided headers are a slight modification of the headers that are already provided by WinAFL to integrate with
another Static Binary Instrumentation tool called Syzygy.

## kAFL Fuzzing
The way we integrate with kAFL is pretty simple.  
Normally, a kAFL harness is running on a virtual machine and talks to the fuzzer's frontend using special "hypercalls".  
These hypercalls tell the fuzzer to do many things, among them is to load coverage data from IntelPT and parse it as an AFL bitmap.  
Because peafl64 makes IntelPT tracing obsolete, we must prepare a way to transmit the coverage data to the fuzzer.  
Therefore, we expanded qemu and kvm with "hypercalls" that allow the (usermode) harness that runs in a VM to send the coverage data it collected using the helper driver.  

### ESXi Setup
This is specifically about the setup on ESXi but should be relevant for other virtualization platforms like AWS.  
The setup is pretty simple:
* Create an Ubuntu machine
* Make sure "Expose hardware assisted virtualization to the guest OS" is enabled in the machine's CPU configuration
* Clone the sbi_kAFL repo
* Install kAFL normally as instructed in the kAFL repo, but instead of `install.sh qemu` step, run `install.sh qemu_sbi`  

To fuzz using kAFL and peafl64, we need to setup a fuzzing machine:
* Compile the helper driver and sign it
* Compile a harness using the headers provided with our kAFL fork
* On the VM - load the helper driver 
* Run the kAFL's loader

Other than that, fuzzing with our kAFL fork is the same as normal fuzzing with kAFL.  


## Execution Flow
Steps Overview:
1. Determine insertion points for instrumentation code
2. Locate instructions and structures that will need adjustments
3. Insert the instrumentation code to the requested functions
4. Adjust:
    * Relative instructions
    * Jump tables
    * Exception handlers
    * PE headers
    * Various PE configurations (load config)
5. Rebuilding the PE with the instrumented sections


First, we use IDA to find and analyze the instructions and locations of interest.  
The analysis creates a `dump.json` file that contains all that information in a json format.  
`instrument.py` contains the instrumentation logic, and the flow itself is outlined in the `process_pe` function.  
To instrument the binary, we duplicate its executable sections, where all the instrumented code will be found.  
Next, we process all the relative instructions and determine how and if we need to handle them.
Suppose we have a short jmp from address X to address Y. We insert instrumentation code between X and Y, and now the target is at address Z (`Z = Y + len(instrumentation)`).  
That means we have to modify the jump. 
If address Z is now located outside the range of short jmps - we need to transform the jump from `short` to `far`.  (instrument.py:expand_relative_instructions)   
For example:
* `short jmp 0x57` (eb 55) -> `near jmp 0x604` (e9 ff 05 00 00)
  
That's also the case for instructions like `call`, `loop` and conditional jumps.  
Another common case that needs handling is rip-relative instructions that were introduced in x64 assembly:
* `call [rip+0x1000]`

We update the following things to point to the instrumented code: relocation table, export table, load configuration, the TLS directory and exception records.  
The updates are done by updating all addresses from the original sections to their instrumented counterparts. (instrument.py:update_addr)  
The headers are updated to reflect the changes to the PE structure - added sections, changed entrypoint and PE size. (instrument.py:update_pe_headers)

Additionally, peafl64 is able to instrument the Windows Kernel. To achieve that, it parses and updated the Dynamic Value Relocation Table (DVRT) and the SSDT, and handles PatchGuard specifics.

The DVRT is a compiler generated table which describes the locations of addresses that need to be changed when loading the PE.  
It's used to improve KASLR and helps mitigate the Spectre vulnerability ([1](https://xlab.tencent.com/en/2016/11/02/return-flow-guard/), [2](https://techcommunity.microsoft.com/t5/windows-kernel-internals-blog/mitigating-spectre-variant-2-with-retpoline-on-windows/ba-p/295618), [3](https://github.com/saferwall/pe/blob/f7468c51a591d5ba47480704c29a1462fd1d4214/loadconfig.go)).  
The DVRT is parsed using a set of classes that mimic the structure of the table (drt.py; instrument.py:get_updated_dynamic_relocs)

Handling and updating the SSDT wasn't as straight-forward.  
Its address is not exported, so we had to either rely on symbols or on heuristics to locate it.  
Our solution uses a heuristic approach, using `NtWaitForSingleObject` as a constant marker for all Windows 10 versions and finding the address of the SSDT relatively to it. (instrument.py:ntoskrnl_update_KiServiceTable)  
This approach works for all Windows 10 Kernels, but will need to be adjusted for other kernel versions.

## TODO

* ~~support x64~~
* New exception handlers (cxx4)
* Improve IDA dumper performance
* Fully parse LOAD_CONFIG struct
* Add tests
* Support more Windows Kernel versions out of the box
* Integrate with Nyx (the new kAFL)  

