#pragma once
#include <pch.h>
#include <defines.h>
//#include <WindowsTypes.hpp>

#define SUGIOT2 0x8001
#define IOCTL_SUGIOT1_MALWARE_COMMAND CTL_CODE(SUGIOT2, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define DRIVER_TAG 'MICH'



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

NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_SUGIOT1_MALWARE_COMMAND:
		{

			KdPrint(("Malicious Command\n"));
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
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//https://stackoverflow.com/questions/47876087/zwquerysysteminformation-is-not-working-properly
VOID NtoskrnlBase(PVOID NtoskrnlBase)
{
	ULONG size = 0;
	PRTL_PROCESS_MODULES proccessModulesInfo = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING routineName;

	RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
	
	KdPrint(("Function NtosKrnlBase\n"));

	// ZwQuerySystemInformation is not exported, so we get its address
	PZwQuerySystemInformation ZwQuerySystemInformation = (PZwQuerySystemInformation)MmGetSystemRoutineAddress(&routineName);
	
	KdPrint(("Got address of ZwQuerySystemInformation:%p\n", ZwQuerySystemInformation));

	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);

	KdPrint(("Called ZwQuerySystemInformation:"));
	KdPrint(("ZwQuerySystemInformation status:%ld", status));
	KdPrint(("Called ZwQuerySystemInformation info size:%d", size));

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (proccessModulesInfo) {
			ExFreePoolWithTag(proccessModulesInfo, DRIVER_TAG);
			proccessModulesInfo = NULL;
		}

		// allocate memory to the struct that will be returned from ZwQuerySystem Information
		proccessModulesInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);

		if (!proccessModulesInfo)
		{
			KdPrint(("!proccessModulesInfo"));
			goto CleanUp;
		}

		// get the system module information
		status = ZwQuerySystemInformation(SystemModuleInformation, &proccessModulesInfo, size, &size);
	}

	KdPrint(("After While"));
	if (!NT_SUCCESS(status) || !proccessModulesInfo)
		goto CleanUp;

	KdPrint(("###############################"));
	for (int i = 0; i < proccessModulesInfo->NumberOfModules; i++)
	{
		RTL_PROCESS_MODULE_INFORMATION ModuleInfo = proccessModulesInfo->Modules[i];
		KdPrint(("Module Name:%s\n", ModuleInfo.FullPathName));
		KdPrint(("Module base:%p\n", ModuleInfo.ImageBase));
	}
	KdPrint(("###############################"));


CleanUp:
	KdPrint(("Cleanup"));
	if(proccessModulesInfo)
		ExFreePoolWithTag(proccessModulesInfo, DRIVER_TAG);
}

NTSTATUS GetSSDTAddress() 
{
	ULONG infoSize;
	PVOID ntoskrnlBase = NULL;
	PRTL_PROCESS_MODULES info = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UCHAR pattern[] = "\x4c\x8d\x15****\x4c\x8d\x1d****\xf7";
	KdPrint(("Function GetSSDT Address\n"));
	NtoskrnlBase(&ntoskrnlBase);

	// ------------------
	/*
	PFULL_IMAGE_NT_HEADERS nt_headers = (PFULL_IMAGE_NT_HEADERS)(bp + (dos_header->e_lfanew));

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		goto CleanUp;

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
			PVOID ssdt = (PVOID)*((PULONG_PTR)sdt);
			KdPrint(("sdt:%p\n", sdt));
			KdPrint(("ssdt:%p\n", ssdt));
		}
	}
	// ------------
	*/
	

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
		KdPrint(("Failed to create Device object\n"));
		return status;
	}
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Sugiot2");
	status = IoCreateSymbolicLink(&symLink, &dev_name);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create symbolic link"));
		return status;
	}

	GetSSDTAddress();
	return STATUS_SUCCESS;

}