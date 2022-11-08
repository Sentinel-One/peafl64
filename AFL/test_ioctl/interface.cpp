#include "header.h"

ULONG_PTR HELPER_GetModuleSectionAddress(PTCHAR pBuffer)
{
	DWORD dwRet = 0, dwOutLen = 0, dwInLen = 0;
	ULONG_PTR dwData = 0;
	BOOLEAN bRet = 0;

	dwInLen = (DWORD)_tcsclen(pBuffer) + 1;
	dwInLen *= 2;
	dwOutLen = sizeof(ULONG_PTR);
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_GET_SECTION_ADDRESS, pBuffer, dwInLen, &dwData, dwOutLen, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_GetModuleSectionAddress(%s) failed, GLE(%x)\n"), pBuffer, GetLastError());
	}
	return dwData;
}

DWORD HELPER_ReadMemory(PBYTE dwAddr, PBYTE pRetBuffer, DWORD dwLen)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_READ_MEMORY, &dwAddr, dwLen, pRetBuffer, dwLen, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_ReadMemory(%p, %p, %x) failed, GLE(%x)\n"), dwAddr, pRetBuffer, dwLen, GetLastError());
	}
	return dwRet;
}

DWORD HELPER_WriteMemory(PBYTE dwAddr, PBYTE pRetBuffer, DWORD dwLen)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_WRITE_MEMORY, &dwAddr, dwLen, pRetBuffer, dwLen, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_WriteMemory(%p, %p, %x) failed, GLE(%x)\n"), dwAddr, pRetBuffer, dwLen, GetLastError());
	}
	return dwRet;
}

ULONG_PTR HELPER_AllocateMemory(DWORD dwPoolType, DWORD dwLen, DWORD dwTag)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;
	ULONG_PTR dwData = 0;

	DWORD in[] = { dwPoolType, dwLen, dwTag };
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_ALLOCATE_MEMORY, in, sizeof(in), &dwData, sizeof(&dwData), &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_AllocateMemory(%x, %x, 0x%x) failed, GLE(%x)\n"), dwPoolType, dwLen, dwTag, GetLastError());
	}
	return dwData;
}

DWORD HELPER_FreeMemory(PBYTE dwAddr, DWORD dwTag)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	// DWORD in[] = { (ULONG_PTR)dwAddr, dwTag };
	unsigned char in2[sizeof(ULONG_PTR) + sizeof(DWORD)]{};
	*(ULONG_PTR*)in2 = (ULONG_PTR)dwAddr;
	*(DWORD*)((ULONG_PTR)in2 + sizeof(ULONG_PTR)) = dwTag;
	//bRet = DeviceIoControl(hHelper, IOCTL_HELPER_FREE_MEMORY, in, sizeof(in), NULL, NULL, &dwRet, NULL);
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_FREE_MEMORY, in2, sizeof(in2), NULL, NULL, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_FreeMemory(%p, %x) failed, GLE(%x)\n"), dwAddr, dwTag, GetLastError());
	}
	return dwRet;
}

DWORD HELPER_MapMemory(ULONG_PTR dwAddr, DWORD dwLen, ULONG_PTR*ptrUserAddr, ULONG_PTR *ptrMdl)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	//DWORD in[] = { (ULONG_PTR)dwAddr, dwLen };
    unsigned char in2[sizeof(ULONG_PTR) + sizeof(DWORD)]{};
    *(ULONG_PTR*)in2 = (ULONG_PTR)dwAddr;
    *(DWORD*)((ULONG_PTR)in2 + sizeof(ULONG_PTR)) = dwLen;
	ULONG_PTR out[2] = { 0 };
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_MAP_MEMORY, in2, sizeof(in2), out, sizeof(out), &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_MapMemory(%p, %x, %p, %p) failed, GLE(%x)\n"), dwAddr, dwLen, ptrUserAddr, ptrMdl);
	}
	*ptrUserAddr = out[0];
	*ptrMdl = out[1];
	return dwRet;
}

DWORD HELPER_UnmapMemory(ULONG_PTR ptrUserAddr, ULONG_PTR ptrMdl)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	ULONG_PTR in[] = { (ULONG_PTR)ptrUserAddr, (ULONG_PTR)ptrMdl };
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_UNMAP_MEMORY, in, sizeof(in), NULL, NULL, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_UnmapMemory(%p, %p) failed, GLE(%x)\n"), ptrUserAddr, ptrMdl);
	}
	return dwRet;
}

DWORD HELPER_ResetBuffer()
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_DUMP_AND_RESET_CALLBACK, NULL, NULL, NULL, NULL, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_ResetBuffer() failed, GLE(%x)\n"), GetLastError());
	}
	return dwRet;
}