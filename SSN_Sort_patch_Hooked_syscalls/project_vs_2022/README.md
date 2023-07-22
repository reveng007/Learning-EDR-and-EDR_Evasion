### According to: https://github.com/Mr-Un1k0d3r/EDRs/blob/main/EDRs.md

### This Project is basically Based on Halos Gate Project!

### Compile:
1.
```
Directly via VS compiler (add enc_shellcode_bin.h to header file list)
```
2. Also via compile.bat (prefer option 1.)
```
./compile.bat
```

### 1. NtAllocateVirtualMemory(): => Should be Unhooked!

![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/344e7823-8375-4318-9818-04acd4a62c03)

### 2. NtWriteVirtualMemory(): => Should be Unhooked!

![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/5955adca-b7fe-453c-900e-1e617a70b7d6)

### 3. NtProtectVirtualMemory(): => Should be Unhooked!

![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/35b30576-2841-48bd-85d9-6289ef6ebcbe)

### 4. NtCreateThreadEx(): => Should be Unhooked!

![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/22a28588-8989-4603-a2b6-cc4156bb8376)

### 5. NtWaitForSingleObject(): No Need! => Just Check InCase!

![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/94206be2-4840-4f69-83cf-9f884165e327)

### 5. ShellCode Encryption via SystemFunction033 Nt API Function + EnvironMental Keying Factor () + GetSystemDirectoryA() [strip the last 2 chars]

https://github.com/reveng007/MaldevTechniques/tree/main/3.Evasions/SystemFunction033%2BEnvKeying%2BGetSystemDirectoryA

--------------------

### To get Syscall Instruction: Calculation:

![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/23adf4b4-9a8f-485e-b328-a4c5cd38cc4e)

--------------------
