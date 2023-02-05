# Hook KdTrap -- Windows global exception handler

KdTrap is the very first function get called when an exception occur, hooking it so that you have the full control of kernel. 

HookKdtrap modifies HalpStallCounter and other variables to take over control flow.



## Compatibility
ONLY TEST IN Win10-18362/3 and Win10-19041/5, using other version of windows may leads to unexpected behaviour!


## How to build
Open .sln file, choose debug-x64 and press build in visual studio solution.




