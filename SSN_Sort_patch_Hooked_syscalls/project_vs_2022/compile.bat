@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp project_vs_2022.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj