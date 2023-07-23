### Compile:
1.
```
Directly via VS compiler:
```
![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/622c39a1-c3b3-4388-ad3a-5a36d18e29ff)

2. Also via compile.bat (prefer option 1.)
```
./compile.bat
```

### How Thread Stack Looks of the Implant Process:

![image](https://github.com/reveng007/MaldevTechniques/assets/61424547/b845bd5b-9ca2-4a73-aa04-16930c7a1d5e)

#### Process to Check the Thread Stack:
1. Just Uncomment this (`NtDelayExecution Snippet`) and compile -> Execute and open the implant process in process hacker -> check thread Stack -> It's totally Legit 
```
1. Top of the stack will indeed show ntoskrnl.exe as 
  => ProcessHacker has a Driver inbuilt which will see beyond the call to ntdll and into ntoskrnl (kernel)

2. Compared with legit cmd process, stack looks kinda identical.
  i. => Nt functions are present at the top of the Stack (Leaving, the "ntoskrnl.exe is on TOP of CallStack" factor)
  ii. => Nt functions are retrieved from ntdll itself, NOT from implant process
```
cmd Thread Stack:

![image](https://github.com/reveng007/MaldevTechniques/assets/61424547/940d87ad-2c87-4e91-b7d4-2c0e2f3d5dfb)

