# Hook KdTrap -- Windows global exception handler

KdTrap is the very first function get called when an exception occur, hooking it so that you have the full control of kernel. HookKdtrap modifies HalpStallCounter and other variables to take over control flow.



