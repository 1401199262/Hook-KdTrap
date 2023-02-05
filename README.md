# Hook KdTrap -- Windows global exception handler

KdTrap is the very first function get called when an exception occur, by hooking it, your code can gain full control of kernel. 

HookKdtrap modifies HalpStallCounter and other variables to take over control flow.  


## Result
Set NtGlobalFlag to 1 will catch global exception, normal system will crash if you set NtGlobalFlag to 1.  
![Result1](/pic/18362.png)
  
## BSOD
The exported "DbgCtx" variable is useful for debugging, but using a actual debugger is more helpful for debug.  
Setup [Qemu+Windbg]([https://www.runoob.com](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-qemu-kernel-mode-debugging-using-exdi#download-and-install-qemu-on-windows)) so that the debugger can step through/in KdTrap  


## How to build
Open .sln file, choose debug-x64 and press build. 
  
## Compatibility
ONLY TEST IN Win10-18362/3 and Win10-19041/5, using other version of windows may leads to unexpected behaviour! 
  
## Limitations
Some exception in kernel such as excuting NX pages and write to read only memory are not be able to catch by kdtrap and therefore won't goes into our handler. 
  
For executing NX page in kernel:  
KiPageFault->MmAccessFault->MiSystemFault->MiCheckSystemNxFault->BugCheck 
  
For write to read only pages in kernel:  
KiPageFault->MmAccessFault->MiSystemFault->BugCheck 


## Some Test
![Result2](/pic/19045.png)

