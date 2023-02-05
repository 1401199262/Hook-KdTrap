#pragma once

void exceptionfun();

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath);

ULONG GetWinver();

extern "C" int _fltused;

