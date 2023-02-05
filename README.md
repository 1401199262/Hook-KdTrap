# Hook KdTrap -- Windows global exception handler

KdTrap is the very first function get called when an exception occur, by hooking it, your code can gain full control of kernel. 

HookKdtrap modifies HalpStallCounter and other variables to take over control flow.  


## Result
![Result1](/pic/18362.png)
![Result2](/pic/19045.png)

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



