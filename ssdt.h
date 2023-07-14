#pragma once

#include <pch.h>

typedef NTSTATUS(*PZwCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);


PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size, PULONG foundIndex, ULONG relativeOffset);
KIRQL DisableWP();

void EnableWP(KIRQL irql);

PVOID GetNtoskrnlBase();
DWORD GetSystemCallNumber(PCSTR functionName);

PLONG GetSsdtAddress(PVOID ntoskrnlBase);
NTSTATUS UnHookSSDT(const char* functionName);

NTSTATUS ZwCreateFileHook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

PVOID findShellCodeCave(PUCHAR startSearchAddress, LONG caveSize, LONG sectionSize);

PIMAGE_SECTION_HEADER GetFunctionSection(PVOID ntoskrnlBase, PVOID functionAddress);

// copy code to read only memory regions
NTSTATUS CopyToMemory(UNALIGNED PVOID destination, UNALIGNED PVOID source, ULONG length);

NTSTATUS HookSSDT(const char* functionName);
