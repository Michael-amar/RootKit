#pragma once

NTSTATUS hide(ULONG pid);
VOID unhide(ULONG pid);
void unhideAll();
void printProcessList();

typedef struct _HIDDEN_PROCESS_LIST
{
	ULONG pid;
	PLIST_ENTRY hiddenProcessLink;
	_HIDDEN_PROCESS_LIST* nextHiddenProcess;
} HIDDEN_PROCESS_LIST, *PHIDDEN_PROCESS_LIST;