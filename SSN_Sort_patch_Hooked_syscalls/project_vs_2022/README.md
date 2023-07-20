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

![image](https://github.com/reveng007/MaldevTechniques/assets/61424547/317c22ad-4ab4-46f9-9a54-b5def6b4c50c)

### 2. NtWriteVirtualMemory(): => Should be Unhooked!

![image](https://github.com/reveng007/MaldevTechniques/assets/61424547/9295b4e1-b062-41ba-aaf1-8d8c60f50b70)

### 3. NtProtectVirtualMemory(): => Should be Unhooked!

![image](https://github.com/reveng007/MaldevTechniques/assets/61424547/48b3cda9-c473-4486-8d47-db87459c4d16)

### 4. NtCreateThreadEx(): => Should be Unhooked!

![image](https://github.com/reveng007/MaldevTechniques/assets/61424547/245e413a-ad8a-468a-900e-50570864cd89)

### 5. NtWaitForSingleObject(): No Need! => Just Check InCase!

![image](https://github.com/reveng007/MaldevTechniques/assets/61424547/2ae8bc15-d8f4-4222-b1a5-1b3208a591cf)

### 5. ShellCode Encryption via SystemFunction033 Nt API Function + EnvironMental Keying Factor () + GetSystemDirectoryA() [strip the last 2 chars]

https://github.com/reveng007/MaldevTechniques/tree/main/3.Evasions/SystemFunction033%2BEnvKeying%2BGetSystemDirectoryA

--------------------

### To get Syscall Instuction: Calculation:

![image](https://github.com/reveng007/MaldevTechniques/assets/61424547/2040c2e7-b472-451a-b593-358420d73d8f)

--------------------
