#include "afl-staticinstr.h"
#include <stdio.h>

typedef BOOL(*_fuzzMe)(char* input);


#define SBI

int main(int argc, char * argv[])
{
    if (argc < 2) {
        printf("Usage: harness.exe <pipe_name>\n");
        return -1;
    }

    HANDLE target = LoadLibrary(L"target.instrumented.dll");

    if (!target) {
        printf("[-] Failed opening target dll: %d\n", GetLastError());
        MessageBoxA(NULL, "Failed opening target dll", NULL, MB_OK | MB_ICONERROR);
        return 0;
    }
    printf("[+] Opened target dll\n");
    _fuzzMe fuzzMe = (_fuzzMe)GetProcAddress(target, "fuzzMe");
    if (!fuzzMe) {
        printf("[-] Failed getting target func: %d\n", GetLastError());
        MessageBoxA(NULL, "Failed getting target func", NULL, MB_OK | MB_ICONERROR);
        return 0;
    }

    PVOID Base = (PVOID)target;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
    PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)(NtHeaders + 1);
    USHORT j = 0;
    UINT_PTR base = 0;

    for (j = 0; j < NtHeaders->FileHeader.NumberOfSections; ++j) {
        if (memcmp(Sections[j].Name, ".cov", 4) != 0) {
            continue;
        }
        base = (UINT_PTR)(Sections[j].VirtualAddress) + (UINT_PTR)Base;
        memset(base, 0, 0x10000 + 8);
    }

    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, argv[1]);
    if (!hMapFile) {
        printf("[-] Failed opening the file mapping: %d\n", GetLastError());
        //MessageBoxA(NULL, "Failed opening the file mapping", NULL, MB_OK | MB_ICONERROR);
        return 0;
    }
    LPVOID buf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 1 << 16);
    if (!buf) {
        printf("[-] Failed MapViewOfFile: %d\n", GetLastError());
        //MessageBoxA(NULL, "Failed MapViewOfFile", NULL, MB_OK | MB_ICONERROR);
        return 0;
    }

    int len = 0;
    char volatile fuzzbuf[4096] = { 0 };

    while (__afl_persistent_loop()) {
        fuzzMe((UINT_PTR)buf + 4);
    }

    printf("End\n");
    return 0;
}
