#pragma once

#include <pch.h>

#define DRIVER_TAG 'MICH'
#define MAX_PATH 260

typedef NTSTATUS(*PZwCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

PZwCreateFile oldZwCreateFile = NULL;

PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size, PULONG foundIndex, ULONG relativeOffset) {
	bool found;

	if (pattern == NULL || base == NULL || len == 0 || size == 0 || (len > size))
		return NULL;

	for (ULONG_PTR i = 0; i < size - len; i++) {
		found = true;

		for (ULONG_PTR j = 0; j < len; j++) {
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
				found = false;
				break;
			}
		}

		if (found) {
			if (foundIndex)
				*foundIndex = i;
			return (PUCHAR)base + i + relativeOffset;
		}
	}

	return NULL;
}

KIRQL DisableWP()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	__writecr0(__readcr0() & 0xFFFEFFFF);
	_disable();
	return irql;
}

void EnableWP(KIRQL irql)
{
	_enable();
	__writecr0(__readcr0() | 0x00010000);
	KeLowerIrql(irql);
}

PVOID GetNtoskrnlBase()
{
	PVOID NtoskrnlBase = NULL;
	ULONG size = 0;
	PRTL_PROCESS_MODULES proccessModulesInfo = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");

	// ZwQuerySystemInformation is not exported, so we get its address
	PZwQuerySystemInformation ZwQuerySystemInformation = (PZwQuerySystemInformation)MmGetSystemRoutineAddress(&routineName);

	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (proccessModulesInfo)
		{
			ExFreePoolWithTag(proccessModulesInfo, DRIVER_TAG);
			proccessModulesInfo = NULL;
		}

		// allocate memory to the struct that will be returned from ZwQuerySystem Information
		proccessModulesInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);

		if (!proccessModulesInfo)
			goto CleanUp;

		// get the system modules information
		status = ZwQuerySystemInformation(SystemModuleInformation, proccessModulesInfo, size, &size);
	}

	if (!NT_SUCCESS(status) || !proccessModulesInfo)
		goto CleanUp;

	// ntoskrnl is always the first module but i need to add a check in the future
	NtoskrnlBase = proccessModulesInfo->Modules[0].ImageBase;

CleanUp:
	if (proccessModulesInfo)
		ExFreePoolWithTag(proccessModulesInfo, DRIVER_TAG);
	return NtoskrnlBase;
}

DWORD GetSystemCallNumber(PCSTR functionName)
{
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatusBlock;
	UNICODE_STRING ntdllPath;
	NTSTATUS status;
	HANDLE ntdllHandle = NULL;
	HANDLE sectionHandle = NULL;
	PVOID ntdllBaseAddress = NULL;
	LARGE_INTEGER  sectionOffset;
	SIZE_T viewSize = 0;
	DWORD syscallNumber = -1;
	RtlInitUnicodeString(&ntdllPath, L"\\??\\C:\\Windows\\System32\\ntdll.dll");

	// Initialize the object attributes
	InitializeObjectAttributes(&objAttr, &ntdllPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// Open the file
	status = ZwOpenFile(&ntdllHandle, FILE_GENERIC_READ, &objAttr, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, ntdllHandle);
	if (!NT_SUCCESS(status))
		goto CleanUp;

	sectionOffset.QuadPart = 0;
	status = ZwMapViewOfSection(sectionHandle, ZwCurrentProcess(), &ntdllBaseAddress, 0, 0, &sectionOffset, &viewSize, ViewUnmap, 0, PAGE_READWRITE);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdllBaseAddress;
	PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntdllBaseAddress + dosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER first_section = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
	PIMAGE_OPTIONAL_HEADER optional_header = &ntHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY data_directories = &optional_header->DataDirectory[0];
	IMAGE_DATA_DIRECTORY export_directory_rva = data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntdllBaseAddress + export_directory_rva.VirtualAddress);
	DWORD base = export_directory->Base;
	PDWORD functions_rva = (PDWORD)((PUCHAR)ntdllBaseAddress + export_directory->AddressOfFunctions);
	PDWORD names_rva = (PDWORD)((PUCHAR)ntdllBaseAddress + export_directory->AddressOfNames);
	PWORD ordinals = (PWORD)((PUCHAR)ntdllBaseAddress + export_directory->AddressOfNameOrdinals);
	for (DWORD i = 0; i < export_directory->NumberOfNames; i++)
	{
		if (strcmp((const char*)((PUCHAR)ntdllBaseAddress + names_rva[i]), functionName) == 0)
		{
			syscallNumber = *(PDWORD)((PUCHAR)ntdllBaseAddress + functions_rva[ordinals[i]] + 4);
			DbgPrint("Syscall number of %s is:%d\n", functionName, syscallNumber);
			break;
		}
	}

CleanUp:
	if (ntdllHandle)
		ZwClose(ntdllHandle);
	if (sectionHandle)
		ZwClose(sectionHandle);
	if (ntdllBaseAddress)
		ZwUnmapViewOfSection(ZwCurrentProcess(), &ntdllBaseAddress);
	return syscallNumber;
}

PLONG GetSsdtAddress(PVOID ntoskrnlBase)
{
	UCHAR pattern[] = "\x4c\x8d\x15****\x4c\x8d\x1d****\xf7";
	PLONG ssdt = NULL;
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntoskrnlBase;
	PFULL_IMAGE_NT_HEADERS nt_headers = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntoskrnlBase + (dos_header->e_lfanew));
	PIMAGE_SECTION_HEADER first_section = (PIMAGE_SECTION_HEADER)(nt_headers + 1);
	for (PIMAGE_SECTION_HEADER section = first_section; section < first_section + nt_headers->FileHeader.NumberOfSections; section++)
	{
		if (strcmp((const char*)section->Name, ".text") == 0)
		{
			PUCHAR section_start = (PUCHAR)ntoskrnlBase + section->VirtualAddress;
			PUCHAR KiSystemServiceRepeat = (PUCHAR)FindPattern(pattern, '*', sizeof(pattern) - 1, section_start, section->Misc.VirtualSize, NULL, NULL);

			//The first instruction in KiSystemServiceRepeat is :
			//4C 8D 15 * * * * <===> lea r10, KeSystemDesciptorTable
			//where the * * * * is the relative address to KeSystemDescriptorTable
			//
			ULONG SdtRelativeOffset = (*(PULONG)(KiSystemServiceRepeat + 3)) + 7; //+3 takes us to the relative address, +7 because the address is relative to the end of the instruction and the instruction is 7 bytes
			PVOID sdt = (PVOID)(KiSystemServiceRepeat + SdtRelativeOffset);
			ssdt = (PLONG) * ((PULONG_PTR)sdt);
		}
	}
	return ssdt;
}

NTSTATUS UnHookSSDT(const char* functionName)
{
	// function is not hooked
	if (oldZwCreateFile == NULL)
		return STATUS_UNSUCCESSFUL;

	PVOID ntoskrnlBase = GetNtoskrnlBase();
	if (ntoskrnlBase == NULL)
		return STATUS_UNSUCCESSFUL;

	PLONG ssdt = GetSsdtAddress(ntoskrnlBase);
	if (ssdt == NULL)
		return STATUS_UNSUCCESSFUL;

	DWORD syscall = GetSystemCallNumber(functionName);
	if (syscall == -1)
		return STATUS_UNSUCCESSFUL;

	LONG functionNumOfParams = ssdt[syscall] & 0xF;
	ULONG oldZwCreateFileRVA = (((PUCHAR)oldZwCreateFile - (PUCHAR)ssdt) << 4);
	LONG oldZwCreateFileSsdtEntry = oldZwCreateFileRVA | functionNumOfParams;
	
	KIRQL irql = DisableWP();
	InterlockedExchange(&ssdt[syscall], oldZwCreateFileSsdtEntry);
	EnableWP(irql);

	oldZwCreateFile = NULL;
	return STATUS_SUCCESS;
}

NTSTATUS ZwCreateFileHook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	// check objectAttributes and Object name arent nulls
	if (!((ObjectAttributes != NULL) && (ObjectAttributes->ObjectName != NULL) && (ObjectAttributes->ObjectName->Length < 256)))
		return oldZwCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

	PCWCHAR targetName = L"New Text Document";
	SIZE_T targetNameLength = wcslen(targetName) * 2; // all the functions are designed for chars so we need to x2

	// check if it our our target file name
	PVOID indexToName = FindPattern((PCUCHAR)targetName, '_', targetNameLength, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, NULL, NULL);

	if (indexToName)
		memcpy(indexToName, L"Sugiot2 ssdt hook", targetNameLength);

	return oldZwCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

}

PVOID findShellCodeCave(PUCHAR startSearchAddress, LONG caveSize, LONG sectionSize)
{
	for (unsigned int i = 0, j = 0; i < sectionSize; i++)
	{
		if (startSearchAddress[i] == 0x90 || startSearchAddress[i] == 0xCC) // NOP or INT3
			j++;
		else
			j = 0;
		if (j == caveSize)
			return (PVOID)(startSearchAddress + i - j + 1);
	}
	return NULL;
}

PIMAGE_SECTION_HEADER GetFunctionSection(PVOID ntoskrnlBase, PVOID functionAddress)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntoskrnlBase;
	PFULL_IMAGE_NT_HEADERS nt_headers = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntoskrnlBase + (dos_header->e_lfanew));
	PIMAGE_SECTION_HEADER first_section = (PIMAGE_SECTION_HEADER)(nt_headers + 1);
	for (PIMAGE_SECTION_HEADER section = first_section; section < first_section + nt_headers->FileHeader.NumberOfSections; section++)
	{
		if (functionAddress > ((PUCHAR)ntoskrnlBase + section->VirtualAddress) &&
			functionAddress < ((PUCHAR)ntoskrnlBase + section->VirtualAddress + section->Misc.VirtualSize))
			return section;
	}
	return NULL;
}

// copy code to read only memory regions
NTSTATUS CopyToMemory(UNALIGNED PVOID destination, UNALIGNED PVOID source, ULONG length)
{
	PMDL mdl = IoAllocateMdl(destination, length, 0, 0, NULL);
	if (!mdl)
		return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(mdl);

	PVOID mapped = MmMapLockedPages(mdl, KernelMode);
	if (!mapped)
	{
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	KIRQL irql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(mapped, source, length);
	KeLowerIrql(irql);
	MmUnmapLockedPages((PVOID)mapped, mdl);
	IoFreeMdl(mdl);
	return STATUS_SUCCESS;
}

NTSTATUS HookSSDT(const char* functionName)
{
	// function is already hooked
	if (oldZwCreateFile != NULL)
		return STATUS_UNSUCCESSFUL;

	NTSTATUS status = STATUS_SUCCESS;
	UCHAR shellCode[] = "\x48\xB8********\x50\xC3"; //movabs rax, xxxx ; push rax; ret
	*(PULONGLONG)(shellCode + 2) = (ULONGLONG)ZwCreateFileHook;

	PVOID ntoskrnlBase = GetNtoskrnlBase();
	if (ntoskrnlBase == NULL)
		return STATUS_UNSUCCESSFUL;

	PLONG ssdt = GetSsdtAddress(ntoskrnlBase);
	if (ssdt == NULL)
		return STATUS_UNSUCCESSFUL;

	DWORD syscall = GetSystemCallNumber(functionName);
	if (syscall == -1)
		return STATUS_UNSUCCESSFUL;

	// 4 LSB in an ssdt entry are reserved for the number of parameters so we dont need them
	LONG functionRVA = (ssdt[syscall] >> 4);
	LONG functionNumOfParams = ssdt[syscall] & 0xF;
	PVOID functionAddress = (PUCHAR)ssdt + functionRVA;
	oldZwCreateFile = (PZwCreateFile)functionAddress;

	// find the section of the function we want to hook, because we want the shell code to be in the same section
	PIMAGE_SECTION_HEADER functionSection = GetFunctionSection(ntoskrnlBase, functionAddress);
	if (functionSection == NULL)
		return STATUS_UNSUCCESSFUL;

	// our shell code is 12 bytes, so we need to look for 12 free bytes in the section of the function we want to hook
	PVOID shellCodeCave = findShellCodeCave((PUCHAR)ntoskrnlBase + functionSection->VirtualAddress, 12, functionSection->Misc.VirtualSize);
	if (findShellCodeCave == NULL)
		return STATUS_UNSUCCESSFUL;

	// copy the shellcode to the cave
	status = CopyToMemory(shellCodeCave, (PVOID)shellCode, 12);
	if (!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	// create ssdt entry to the shellcode cave 
	ULONG shellCodeRVA = (((PUCHAR)shellCodeCave - (PUCHAR)ssdt) << 4);
	LONG shellCodeSsdtEntry = shellCodeRVA | functionNumOfParams;

	// disable WP 
	KIRQL irql = DisableWP();

	// atomicly change the ssdt entry with our new entry
	InterlockedExchange(&ssdt[syscall], shellCodeSsdtEntry);

	// restore WP
	EnableWP(irql);

	return STATUS_SUCCESS;
}
