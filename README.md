# Hook KdTrap -- Windows global exception handler

KdTrap is the very first function get called when an exception occur, by hooking it, your code can gain full control of kernel. 

HookKdtrap modifies HalpStallCounter and other variables to take over control flow.  


## Result
Accessing 0 address and setting reserved bit in cr3 will normally cause a bsod, but it's safe after we use our custom exception handler  
```
*(vu8*)0;
__writecr3(__readcr3() | 1ui64 << 63);
*(vu8*)0;    
```  

Set NtGlobalFlag to 1 will catch global exception, normal system will instantly crash if NtGlobalFlag is 1.  
![Result1](/pic/18362.png)
  
## How to build
Open .sln file, choose debug-x64 and press build. 
  
## BSOD
![WhatHappen](/pic/how.jpg)  
The exported "DbgCtx" variable is useful for debugging, but using a actual debugger is more helpful for debug.  
Setting up [Qemu+Windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-qemu-kernel-mode-debugging-using-exdi) so that the debugger can step through/in KdTrap  

## Compatibility
ONLY TEST IN Win10-18362/3 and Win10-19041/5, using other version of windows may leads to unexpected behaviour! 
  
## Limitations
Some exception in kernel such as excuting NX pages and write to read only memory are not be able to catch by kdtrap and therefore won't goes into our handler. 
  
For executing NX page in kernel:  
```KiPageFault->MmAccessFault->MiSystemFault->MiCheckSystemNxFault->BugCheck ```
  
For write to read only pages in kernel:  
```KiPageFault->MmAccessFault->MiSystemFault->BugCheck ```  

## Stack trace  
HookKdtrap extensively use stack trace to gather register, different winver may have different offset in stack.  

### Sample Stack trace when exception handler get called  

Inserting __debugbreak() in Drivermain:  
```
00 KMDFDriver1!ExceptionHandler
01 KMDFDriver1!HookPosition+0xa9
02 hal!KeStallExecutionProcessor+0xac
03 nt!KeFreezeExecution+0x26a
04 nt!KdEnterDebugger+0x64
05 nt!KdpReport+0x71
06 nt!KdpTrap+0x14d
07 nt!KdTrap+0x2c
08 nt!KiDispatchException+0x15f
09 nt!KiExceptionDispatch+0x11d
0a nt!KiBreakpointTrap+0x318
0b KMDFDriver1!DriverEntry+0xe0
0c nt!IopLoadDriver+0x4c2
0d nt!IopLoadUnloadDriver+0x4e
0e nt!ExpWorkerThread+0x105
0f nt!PspSystemThreadStartup+0x55
10 nt!KiStartSystemThread+0x2a
```  
  
Exception in PatchGuard routine:  
```
00 KMDFDriver1!HookPosition
01 nt!KeStallExecutionProcessor + 0x120
02 nt!KeFreezeExecution + 0x110
03 nt!KdEnterDebugger + 0x6d
04 nt!KdpReport + 0x74
05 nt!KdpTrap + 0x160
06 nt!KdTrap + 0x2d
07 nt!KiDispatchException + 0x177
08 nt!KxExceptionDispatchOnExceptionStack + 0x12
09 nt!KiExceptionDispatchOnExceptionStackContinue
0a nt!KiExceptionDispatch + 0x125
0b nt!KiGeneralProtectionFault + 0x320
0c nt!KiCustomRecurseRoutine0 + 0xd
0d nt!KiCustomRecurseRoutine9 + 0xd
0e nt!KiCustomRecurseRoutine8 + 0xd
0f nt!KiCustomRecurseRoutine7 + 0xd
10 nt!KiCustomAccessRoutine7 + 0x22
11 nt!ExpTimeRefreshDpcRoutine + 0x9f
12 nt!KiSwInterruptDispatch + 0xfe6
13 nt!KiProcessExpiredTimerList + 0x172
14 nt!KiRetireDpcList + 0x5dd
15 nt!KiIdleLoop + 0x9e
```  

## Some Test
![Result2](/pic/19045.png)


