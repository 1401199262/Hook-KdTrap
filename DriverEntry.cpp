#include "Utils.h"
#include "HookKdTrap.h"
#include "DriverEntry.h"

int _fltused = 0;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrintEx(0, 0, "UnLoad\n");

	//todo Stop thread exceptionfun
	UnHookKdTrap();

	//__db();
}

bool Handler(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
{
	if (Context->Rip - (u64)exceptionfun < 0x500)
	{		
		if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
		{
			// mov al,[00000000]
			if (*(u32*)Context->Rip == 0x25048A)
			{
				Context->Rip += 7;
				return true;
			}
		}

		if (ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION)
		{
			if (*(USHORT*)(Context->Rip) == 0x220F) // mov cr
			{
				Context->Rip += 3;
				return true;
			}
		}

	}

	return false;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	HookKdTrap(Handler);

	HANDLE thread = NULL;
	PsCreateSystemThread(&thread, 0L, NULL, NULL, NULL, (PKSTART_ROUTINE)exceptionfun, 0);

	return STATUS_SUCCESS;
}

noinl void TestSeh()
{
	_disable();
	__try
	{
		__nop();
		__debugbreak();
		KeBugCheck(0);
	}
	__except (1)
	{
		__nop();
		_enable();
	}

	__try
	{
		auto a = (volatile u64)1;
		auto b = (volatile u64)0;
		__nop();
		volatile u64 c = a / b;
		KeBugCheck(0);
	}
	__except (1)
	{
		__nop();
	}
}

void exceptionfun()
{
	while (1)
	{
		//test seh are working
		TestSeh();
		
		//try some dangerous, see Handler
		*(vu8*)0;
		__writecr3(__readcr3() | 1ui64 << 63);
		*(vu8*)0;

		//can't do this since this kind of fault doesn't go into KdTrap 
		//KiPageFault->MmAccessFault->MiSystemFault->BugCheck 
		//*(u64*)exceptionfun = 0x6969696969696969;

		KSleep(5000);
	}

}
