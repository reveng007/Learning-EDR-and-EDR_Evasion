# Learning-EDR-and-EDR_Evasion
I will be uploading all the codes which I created with the help of either open-source projects or blogs. This is a step-by-step EDR learning path for me.

------

### NOTE:
Syscall Implementation in Nim: [sysplant](https://github.com/x42en/sysplant) by [x42en](https://github.com/x42en)

------------

## Learning Curve:

#### Schematic WorkFlow:
1. ***SSN Sorting and Patching***:\
   i. Neither, Direct Syscall nor Indirect Syscall, but can be **Weaponised** to do both with **SSN Sorting**.\
   Thanks to [@D1rkMtr](https://twitter.com/D1rkMtr) for his Project: [UnhookingPatch](https://github.com/TheD1rkMtr/UnhookingPatch)
   
   ii. My Implementation of **SSN Sorting and Patching**:\
   ***(SSN + syscall address Sorting via Halo's Gate + patching + SystemFunction033 Nt Api RC4 encrypted shellcode decryption directly from process memory + EnumThreadWindows)*** : [link](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/tree/main/SSN_Sort_patch_Hooked_syscalls/project_vs_2022)
   
3. _**Direct Dynamic Syscall (Not Hard Coded Stub)**_:\
   Blog by [@VirtualAllocEx](https://twitter.com/VirtualAllocEx):\
      i. https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls (Concept, as well as Code Snippet : [Whole Code](https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls/tree/main/Direct_Syscalls_Create_Thread),\
   Exceptionally well Explained!)
   
      ii. _**Hell's Gate**_: [Exploring Hell's Gate](https://redops.at/en/blog/exploring-hells-gate) -> ...

      iii. ***TartarusGate***: Modified Halos Gate Implementation: Why needed? Cause: Not all EDRs hook the same way: More here: [Blog](https://trickster0.github.io/posts/Halo's-Gate-Evolves-to-Tartarus-Gate/)\
      Whole Code: [here](https://github.com/trickster0/TartarusGate).

      iv. ***FreshyCalls****:\
      Source Code: [here](https://github.com/crummie5/FreshyCalls)\
      Blog Post: [here](https://www.crummie5.club/freshycalls/)

      Comparative table taken from Cyber bit's blog (link doesn't work: [link](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/)):

![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/804a9d2b-ee7f-4bf5-a666-afa621c9e04d)
   
5. _**Indirect Syscall (.C Version)**_ :\
   i. Blog: https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls : [Source Code](https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls)
   
6. _**Indirect Dynamic Syscall**_:\
    i. _**HellHall (.C Version)**_:\
      https://github.com/Maldev-Academy/HellHall (Hells Gate + Indirect Syscall)
   
    ii. ***[D1rkLdr](https://github.com/TheD1rkMtr/D1rkLdr/)*** and ***[HadesLdr](https://github.com/CognisysGroup/HadesLdr)***:\
     ***SSN + syscall address Sorting via Halo's Gate + Indirect Syscall + API Hashing + Stageless shellcode*** by [@D1rkMtr](https://twitter.com/D1rkMtr)

   iii. My Implementation of Indirect Dynamic Syscall.
   
8. Memory Scanning Evasion
9. Advanced Module Stomping
10. ...

### Curtesy To:
> Not A Complete list -> I will be adding rest, while I continue my learning\
> and Please, they are not listed based on anything!\
> => All have made a great **contribution** to OpenSource Community!
1. [@SEKTOR7net](https://twitter.com/SEKTOR7net)
2. [@zodiacon](https://twitter.com/zodiacon)
3. [@_winterknife_](https://twitter.com/_winterknife_)
4. [redops - knowledge-base](https://redops.at/knowledge-base) by [@VirtualAllocEx](https://twitter.com/VirtualAllocEx)
5. [Evading EDR](https://nostarch.com/book-edr#content) by [@matterpreter](https://twitter.com/matterpreter) 
6. [@0xBoku](https://twitter.com/0xBoku)
7. [@jack_halon](https://twitter.com/jack_halon)
8. [@Jean_Maes_1994](https://twitter.com/Jean_Maes_1994)
9. [@peterwintrsmith](https://twitter.com/peterwintrsmith)
10. [@x86matthew](https://twitter.com/x86matthew)
11. [@domchell](https://twitter.com/domchell)
12. [@FuzzySec](https://twitter.com/FuzzySec)
13. [@modexpblog](https://twitter.com/modexpblog)
14. [@D1rkMtr](https://twitter.com/D1rkMtr)
15. [@ZeroMemoryEx](https://twitter.com/ZeroMemoryEx)
16. [@NinjaParanoid](https://twitter.com/NinjaParanoid)
17. [Windows-Internals](https://github.com/Faran-17/Windows-Internals) and [MA](https://chrollo-dll.gitbook.io/chrollo/security-blogs/malware-analysis-and-re/wannacry-ransomware) by [@Chrollo_l33t](https://twitter.com/Chrollo_l33t)
18. [trustedsec](https://www.trustedsec.com/) by [@TrustedSec](https://twitter.com/TrustedSec)
19. [@spotheplanet](https://twitter.com/spotheplanet)
20. [@C5pider](https://twitter.com/C5pider)
21. [@0xTriboulet](https://twitter.com/0xTriboulet)
22. [@codex_tf2](https://twitter.com/codex_tf2)
23. [@Jackson_T](https://twitter.com/Jackson_T)
24. [@_RastaMouse](https://twitter.com/_RastaMouse)
25. [@ShitSecure](https://twitter.com/ShitSecure)
26. [@CaptMeelo](https://twitter.com/CaptMeelo)
27. [@0x09AL](https://twitter.com/0x09AL)
28. [@hasherezade](https://twitter.com/hasherezade)
29. [@0gtweet](https://twitter.com/0gtweet)
30. [@phraaaaaaa](https://twitter.com/phraaaaaaa)
31. [@Flangvik](https://twitter.com/Flangvik)
32. [@rad9800](https://twitter.com/rad9800)
33. [@Octoberfest73](https://twitter.com/Octoberfest73)
34. [@eversinc33](https://twitter.com/eversinc33)
35. [@allevon412](https://twitter.com/allevon412)
36. [@0xLegacyy](https://twitter.com/0xLegacyy)
37. [@d_tranman](https://twitter.com/d_tranman)
