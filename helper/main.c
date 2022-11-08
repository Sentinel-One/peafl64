#include <ntddk.h>
#include <Ntstrsafe.h>
#include <ntimage.h>
#include "main.h"

#pragma warning (disable: 4201)
#define DRIVER_NAME                       L"\\Device\\helper"
#define DEVICE_NAME                       L"\\DosDevices\\helper"
#define MAX_PATH_LEN					  1024




#define IMAGE_SIZEOF_SHORT_NAME           8
#define IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES  16

typedef enum _SYSTEM_INFORMATION_CLASS {	// indicates what information the ZwQuerySystemInformation function should query
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,				// to get information about all kernel modules
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

// Class 11
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG  Unknown1;
	ULONG  Unknown2;
#ifdef _WIN64
	ULONG Unknown3;
	ULONG Unknown4;
#endif
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  NameOffset;
	CHAR  ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

//extern "C"
NTKERNELAPI  NTSTATUS ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

/*
 * Function: KernelGetModuleBase
 * -----------------------------
 * Finds the base address of a kernel module
 * 
 * pModuleName: name of module to look for
 * 
 * returns: module base address, NULL on error.
 */
PVOID KernelGetModuleBase(PCHAR  pModuleName)
{
	PVOID pModuleBase = NULL;
	PULONG pSystemInfoBuffer = NULL;
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	__try
	{
		ULONG    SystemInfoBufferSize = 0;

		//first passing NULL to SystemInformation to get the accurate size of the information and allocate memory accordingly
		status = ZwQuerySystemInformation(SystemModuleInformation,
			NULL,
			0,
			&SystemInfoBufferSize);

		if (NT_SUCCESS(status)) {
			return NULL;
		}

		if (!SystemInfoBufferSize) {
		return NULL;
		}

		KdPrint(("SystemInfoBufferSize: 0x%x", SystemInfoBufferSize));
		pSystemInfoBuffer = (PULONG)ExAllocatePoolWithTag(NonPagedPool, SystemInfoBufferSize, 0x12345678);

		if (!pSystemInfoBuffer) {
			KdPrint(("pSystemInfoBuffer allocation failed.\n"));
			return NULL;
		}

		memset(pSystemInfoBuffer, 0, SystemInfoBufferSize);

		// calling the function to get information about all kernel modules
		status = ZwQuerySystemInformation(SystemModuleInformation,
			pSystemInfoBuffer,
			SystemInfoBufferSize,
			&SystemInfoBufferSize);

		if (NT_SUCCESS(status))
		{
			PSYSTEM_MODULE_INFORMATION systemModulesInformation = (PSYSTEM_MODULE_INFORMATION)pSystemInfoBuffer;
			PSYSTEM_MODULE_INFORMATION_ENTRY pSysModuleEntry = systemModulesInformation->Modules;
			ULONG i;
			KdPrint(("systemModulesInformation Count: 0x%p\n", systemModulesInformation->Count));

			//iterating over all systemModulesInformation entries, untill it reaches the one that matches the requested name
			for (i = 0; i < systemModulesInformation->Count; i++)
			{
				if (_stricmp(pSysModuleEntry[i].ImageName +
					pSysModuleEntry[i].NameOffset, pModuleName) == 0)
				{
					pModuleBase = pSysModuleEntry[i].Base;
					break;
				}
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		pModuleBase = NULL;
		status = GetExceptionCode();
		DbgPrint("Exception code: 0x%X\n", status);
	}
	if (pSystemInfoBuffer) {
		ExFreePool(pSystemInfoBuffer);
	}

	return pModuleBase;
} // end KernelGetModuleBase()

void Unload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	KdPrint(("helper driver unloaded !\n"));
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoDeleteSymbolicLink(&usSymboName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(pIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*
 * Function: ReadOrWriteMemory
 * ---------------------
 * Writes / Reads data to memory
 *
 * ulAddr: Address to write to / read from
 * pData: pointer to data to write /pointer to buffer to read into 
 * ulLen: length of data
 * read: TRUE for read action, FALSE for write action
 *
 * returns: Write operation status
 */
NTSTATUS ReadOrWriteMemory(ULONG_PTR ulAddr, UCHAR* pData, ULONG ulLen, BOOLEAN read)
{
	PMDL ptrMdl = NULL;
	PVOID ptrBuffer = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (ptrMdl == NULL) {
		KdPrint(("IoAllocateMdl failed\n"));
		return status;
	}
	else {
		__try {
			MmProbeAndLockPages(ptrMdl, KernelMode, IoModifyAccess);
			ptrBuffer = MmMapLockedPagesSpecifyCache(ptrMdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (ptrBuffer == NULL) {
				KdPrint(("MmMapLockedPagesSpecifyCache failed\n"));
			}
			else {
				status = MmProtectMdlSystemAddress(ptrMdl, PAGE_EXECUTE_READWRITE);
				if (status == STATUS_SUCCESS) {
					KdPrint(("MmProtectMdlSystemAddress successed\n"));
					if (read) {
						RtlCopyMemory(pData, ptrBuffer, ulLen);
						KdPrint(("Read data complete\n"));
					}
					else {
						RtlCopyMemory(ptrBuffer, pData, ulLen);
						KdPrint(("Write data complete\n"));
					}
				}
				else {
					KdPrint(("MmProtectMdlSystemAddress failed 0x%X\n", status));
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}

		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}

		if (ptrMdl) {
			MmUnlockPages(ptrMdl);
			IoFreeMdl(ptrMdl);
		}
	}
	return status;
}// end ReadOrWriteMemory()


/*
 * Function: WriteMemory
 * ---------------------
 * Writes data to memory
 * 
 * ulAddr: Address to write to
 * pData: pointer to data
 * ulLen: length of data
 * 
 * returns: Write operation status
 */
NTSTATUS WriteMemory(ULONG_PTR ulAddr, UCHAR* pData, ULONG ulLen)
{
	return ReadOrWriteMemory(ulAddr, pData, ulLen, FALSE);
}// end WriteMemory()

/*
 * Function: ReadMemory
 * ---------------------
 * Reads data from memory
 *
 * ulAddr: Address to read from
 * pData: pointer to where to read into
 * ulLen: length of data to read
 * 
 * returns: Read operation status
 */
NTSTATUS ReadMemory(ULONG_PTR ulAddr, UCHAR* pData, ULONG ulLen)
{
	return ReadOrWriteMemory(ulAddr, pData, ulLen, TRUE);
}// end ReadMemory()

NTSTATUS MapMemory(ULONG_PTR ulAddr, ULONG ulLen, PVOID *ptrBuffer, PMDL *ptrMdl)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	*ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (*ptrMdl == NULL) {
		KdPrint(("IoAllocateMdl failed\n"));
		return status;
	}
	else {
		__try {
			MmBuildMdlForNonPagedPool(*ptrMdl);
			*ptrBuffer = MmMapLockedPagesSpecifyCache(*ptrMdl, UserMode, MmCached, NULL, FALSE, HighPagePriority);
			if (*ptrBuffer == NULL) {
				KdPrint(("MmMapLockedPagesSpecifyCache failed\n"));
			}
			return STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}
	}
	return status;
}// end MapMemory()

VOID UnmapMemory(PVOID ptrBuffer, PMDL ptrMdl)
{
	if (ptrBuffer) {
		MmUnmapLockedPages(ptrBuffer, ptrMdl);
	}
	if (ptrMdl) {
		MmUnlockPages(ptrMdl);
		IoFreeMdl(ptrMdl);
	}
}// end UnmapMemory()

#define DllExport _declspec(dllexport)
DWORD tbl_size = 0x100;
DllExport DWORD tbl_idx = 0;
DllExport DWORD* tbl = NULL;
// DllExport NTSTATUS callback() {
// 	if (!tbl) tbl = ExAllocatePoolWithTag(NonPagedPoolNx, tbl_size * sizeof(DWORD), 0x41414141);
// 	if (tbl_idx >= tbl_size) {
// 		DWORD* old_tbl = tbl;
// 		tbl_size *= 2;
// 		tbl = ExAllocatePoolWithTag(NonPagedPoolNx, tbl_size * sizeof(DWORD), 0x41414141);
// 		memcpy(tbl, old_tbl, tbl_size * sizeof(DWORD) / 2);
// 		ExFreePoolWithTag(old_tbl, 0x41414141);
// 	}
// 	tbl[tbl_idx++] = (DWORD)_ReturnAddress();
// 	return 0;
// }

void dump_and_reset_callback() {
	for (DWORD i = 0; i < tbl_idx; i++) {
		KdPrint(("%x\n", tbl[i]));
	}
	if (tbl) {
		ExFreePoolWithTag(tbl, 0x41414141);
		tbl = NULL;
		tbl_size = 0x100;
		tbl_idx = 0;
	}
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	ULONG i = 0, code = 0, len = 0;
	DWORD32 size = 0;
	ULONG_PTR ptrBaseAddr = 0, ptrRetAddr = 0;
	DWORD32 ptrTag = 0, ptrType = 0;
	ULONG_PTR ptrUserAddr = 0, ptrMdl = 0;
	PIO_STACK_LOCATION stack = NULL;
	ANSI_STRING cov = { 4,5,".cov" };
	ANSI_STRING secName;
	NTSTATUS status = STATUS_SUCCESS;

	stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;
	switch (code) {
	case IOCTL_HELPER_GET_SECTION_ADDRESS:
		KdPrint(("Get Section Address: %ws\n", (PWCHAR)pIrp->AssociatedIrp.SystemBuffer));

		CHAR name[MAX_PATH_LEN] = { 0 };
		status = RtlStringCchPrintfA(name, MAX_PATH_LEN, "%ws", pIrp->AssociatedIrp.SystemBuffer);
		if (!NT_SUCCESS(status)) {
			KdPrint(("Failed creating string with error: %d\n", status));
			len = 0;
			break;
		}
		ptrBaseAddr = (ULONG_PTR)KernelGetModuleBase(name);
		if (ptrBaseAddr == NULL) {
			KdPrint(("Base Addr not found..."));
			break;
		}
		else {
			KdPrint(("KernelGetModuleBase(%s) = 0x%p\n", name, ptrBaseAddr));

			if (ptrBaseAddr && (((PUCHAR)ptrBaseAddr)[0] == 'M') && (((PUCHAR)ptrBaseAddr)[1] == 'Z')) {
				IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)ptrBaseAddr;
				IMAGE_NT_HEADERS *pImageNTHeader = (IMAGE_NT_HEADERS*)((PUCHAR)ptrBaseAddr + pDosHeader->e_lfanew);
				IMAGE_FILE_HEADER *pFileheader = &pImageNTHeader->FileHeader;
				IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &pImageNTHeader->OptionalHeader;
				IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER*)((PUCHAR)pImageOptionalHeader + pFileheader->SizeOfOptionalHeader);
				for (i = 0; i<pFileheader->NumberOfSections; i++) {
					RtlInitAnsiString(&secName, (PCSZ)sectionHeader->Name);
					if (RtlCompareString(&secName, &cov, TRUE) == 0) {
						ptrRetAddr = sectionHeader->VirtualAddress;
					}
					/*
					KdPrint(("------------------------------------------------------------------\n"));
					KdPrint(("Section Name = %s\n", sectionHeader->Name));
					KdPrint(("Virtual Offset = %X\n", sectionHeader->VirtualAddress));
					KdPrint(("Virtual Size = %X\n", sectionHeader->Misc.VirtualSize));
					KdPrint(("Raw Offset = %X\n", sectionHeader->PointerToRawData));
					KdPrint(("Raw Size = %X\n", sectionHeader->SizeOfRawData));
					KdPrint(("Characteristics = %X\n", sectionHeader->Characteristics));
					KdPrint(("------------------------------------------------------------------\n"));
					*/
					sectionHeader++;
				}
			}
			if(ptrRetAddr) ptrRetAddr += ptrBaseAddr;
			KdPrint((".cov Address: 0x%p\n", ptrRetAddr));
			*((ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer) = ptrRetAddr;

			len = sizeof(ULONG_PTR);
			break;
		}

	case IOCTL_HELPER_READ_MEMORY:
		ptrBaseAddr = *(ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer;
		KdPrint(("Read memory: addr 0x%llX, size %d\n", ptrBaseAddr, stack->Parameters.DeviceIoControl.InputBufferLength));
		ReadMemory(ptrBaseAddr, (UCHAR*)pIrp->AssociatedIrp.SystemBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
		len = stack->Parameters.DeviceIoControl.InputBufferLength;
		break;

	case IOCTL_HELPER_WRITE_MEMORY:
		ptrBaseAddr = *(ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer;
		KdPrint(("Write memory: addr 0x%X, size %d\n", ptrBaseAddr, stack->Parameters.DeviceIoControl.InputBufferLength));
		WriteMemory(ptrBaseAddr, (UCHAR*)pIrp->UserBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
		len = 0;
		break;

	case IOCTL_HELPER_ALLOCATE_MEMORY:
		ptrType = *(DWORD32*)pIrp->AssociatedIrp.SystemBuffer;
		size = *((DWORD32*)pIrp->AssociatedIrp.SystemBuffer + 1);
		ptrTag = *((DWORD32*)pIrp->AssociatedIrp.SystemBuffer + 2);
		KdPrint(("Allocate memory: pooltype 0x%x, tag %X, size 0x%x\n", ptrType, ptrTag, size));
		*((ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer) = (ULONG_PTR)ExAllocatePoolWithTag(ptrType, size, ptrTag);
		len = sizeof(ULONG_PTR);
		break;

	case IOCTL_HELPER_FREE_MEMORY:
		ptrBaseAddr = *(ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer;
		ptrTag = *(DWORD32*)((ULONG_PTR)pIrp->AssociatedIrp.SystemBuffer + sizeof(ULONG_PTR));
		KdPrint(("free memory: tag %X, address 0x%x\n", ptrTag, ptrBaseAddr));
		ExFreePoolWithTag((PVOID)ptrBaseAddr, ptrTag);
		len = 0;
		break;

	case IOCTL_HELPER_MAP_MEMORY:
		ptrBaseAddr = *(ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer;
		size = *(DWORD32*)((ULONG_PTR)pIrp->AssociatedIrp.SystemBuffer + sizeof(ULONG_PTR));
		KdPrint(("Kernel Address: 0x%p\n", ptrBaseAddr));
		KdPrint(("Size: 0x%X\n", size));
		NTSTATUS ns = MapMemory(ptrBaseAddr, size, (PVOID*)&ptrUserAddr, (PMDL*)&ptrMdl);
		if (ns == STATUS_SUCCESS) {
			KdPrint(("Mapped User Address: 0x%X\n", ptrUserAddr));
			KdPrint(("MDL Address: 0x%X\n", ptrMdl));
		}
		*((ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer) = ptrUserAddr;
		*((ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer + 1) = ptrMdl;
		len = sizeof(ULONG_PTR)*2;
		break;

	case IOCTL_HELPER_UNMAP_MEMORY:
		ptrUserAddr = *(ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer;
		ptrMdl = *((ULONG_PTR*)pIrp->AssociatedIrp.SystemBuffer + 1);
		KdPrint(("Unmapped User Address: 0x%X\n", ptrUserAddr));
		KdPrint(("MDL Address: 0x%X\n", ptrMdl));
		UnmapMemory((PVOID)ptrUserAddr, (PMDL)ptrMdl);
		len = 0;
		break;

	case IOCTL_HELPER_DUMP_AND_RESET_CALLBACK:
		dump_and_reset_callback();
		len = 0;
		break;

	default:
		KdPrint(("Invalid IOCTL code: 0x%X\n", code));
		break;
	}

	pIrp->IoStatus.Information = len;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	PDEVICE_OBJECT pFunObj = NULL;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymboName;
	UNREFERENCED_PARAMETER(pRegPath);

	KdPrint(("helper driver loaded\n"));
	RtlInitUnicodeString(&usDeviceName, DRIVER_NAME);
	IoCreateDevice(pDrvObj, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pFunObj);
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoCreateSymbolicLink(&usSymboName, &usDeviceName);

	pDrvObj->MajorFunction[IRP_MJ_CREATE] =
		pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDrvObj->DriverUnload = Unload;
	return STATUS_SUCCESS;
}
