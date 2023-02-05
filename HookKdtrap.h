#pragma once

using ExceptionCallback = bool(__stdcall*)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context);

void HookKdTrap(ExceptionCallback Handler);

void UnHookKdTrap();

u64 BpMe(u64 line);

