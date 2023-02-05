#include "utils.h"

NTSTATUS getKernelModuleByName(const char* moduleName, PVOID* moduleStart, size_t* moduleSize)
{
	if (!moduleStart)
		return STATUS_INVALID_PARAMETER;

	size_t size{};
	ZwQuerySystemInformation(SystemModuleInformation, nullptr, size, reinterpret_cast<PULONG>(&size));

	const auto listHeader = ExAllocatePool(NonPagedPool, size);
	if (!listHeader)
		return STATUS_MEMORY_NOT_ALLOCATED;

	if (const auto status = ZwQuerySystemInformation(SystemModuleInformation, listHeader, size, reinterpret_cast<PULONG>(&size)))
		return status;

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;
	for (size_t i = 0; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule)
	{
		const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (!strcmp(moduleName, currentModuleName))
		{
			*moduleStart = currentModule->ImageBase;
			if (moduleSize)
				*moduleSize = currentModule->ImageSize;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}

#define SizeAlign(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)
#define IMAGE_FIRST_SECTION(NtHeader) (PIMAGE_SECTION_HEADER)(NtHeader + 1)
#define NT_HEADER(ModBase) (PIMAGE_NT_HEADERS)((ULONG64)(ModBase) + ((PIMAGE_DOS_HEADER)(ModBase))->e_lfanew)

BOOLEAN StrICmp(const char* Str, const char* InStr, BOOLEAN Two)
{
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)

	if (!Str || !InStr)
		return FALSE;

	WCHAR c1, c2; do {
		c1 = *Str++; c2 = *InStr++;
		c1 = ToLower(c1); c2 = ToLower(c2);
		if (!c1 && (Two ? !c2 : 1))
			return TRUE;
	} while (c1 == c2);

	return FALSE;
}

PVOID FindSection(PVOID ModBase, const char* Name, PULONG SectSize)
{
	//get & enum sections
	PIMAGE_NT_HEADERS NT_Header = NT_HEADER(ModBase);
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Header);

	for (PIMAGE_SECTION_HEADER pSect = Sect; pSect < Sect + NT_Header->FileHeader.NumberOfSections; pSect++)
	{
		//copy section name
		char SectName[9]; SectName[8] = 0;
		*(ULONG64*)&SectName[0] = *(ULONG64*)&pSect->Name[0];

		//check name
		if (StrICmp(Name, SectName, true))
		{
			//save size
			if (SectSize) {
				ULONG SSize = SizeAlign(max(pSect->Misc.VirtualSize, pSect->SizeOfRawData));
				*SectSize = SSize;
			}

			//ret full sect ptr
			return (PVOID)((ULONG64)ModBase + pSect->VirtualAddress);
		}
	}

	//no section
	return nullptr;
}

bool readByte(PVOID addr, UCHAR* ret)
{
	*ret = *(volatile char*)addr;
	return true;
}

PUCHAR FindPatternSect(PVOID ModBase, const char* SectName, const char* Pattern)
{
	//find pattern utils
#define InRange(x, a, b) (x >= a && x <= b) 
#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))

//get sect range
	ULONG SectSize;
	PUCHAR ModuleStart = (PUCHAR)FindSection(ModBase, SectName, &SectSize);
	PUCHAR ModuleEnd = ModuleStart + SectSize;

	if (!ModuleStart) return nullptr;

	//scan pattern main
	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	if (*Pattern == '\0')
		CurPatt++;

	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');

		//hp(ModuleStart);
		UCHAR byte1;
		if (!readByte(ModuleStart, &byte1)) {
			auto addr2 = (u64)ModuleStart;
			addr2 &= 0xFFFFFFFFFFFFF000;
			addr2 += 0xFFF;
			ModuleStart = (PUCHAR)addr2;
			//sp("123");
			goto Skip;
		}

		if (SkipByte || byte1 == GetByte(CurPatt)) {
			if (!FirstMatch) FirstMatch = ModuleStart;
			if (SkipByte)
				CurPatt += 2;
			else
				CurPatt += 3;
			if (CurPatt[-1] == 0) return FirstMatch;
		}

		else if (FirstMatch) {
			ModuleStart = FirstMatch;
		Skip:
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	//failed
	return nullptr;
}

PUCHAR FindPatternRange(PVOID Start, u32 size, const char* Pattern)
{
	//find pattern utils
#define InRange(x, a, b) (x >= a && x <= b) 
#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))

//get sect range
	ULONG SectSize;
	PUCHAR ModuleStart = (PUCHAR)Start;
	PUCHAR ModuleEnd = ModuleStart + size;

	//scan pattern main
	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	if (*Pattern == '\0')
		CurPatt++;

	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');

		//hp(ModuleStart);
		UCHAR byte1;
		if (!readByte(ModuleStart, &byte1)) {
			auto addr2 = (u64)ModuleStart;
			addr2 &= 0xFFFFFFFFFFFFF000;
			addr2 += 0xFFF;
			ModuleStart = (PUCHAR)addr2;
			//sp("123");
			goto Skip;
		}

		if (SkipByte || byte1 == GetByte(CurPatt)) {
			if (!FirstMatch) FirstMatch = ModuleStart;
			SkipByte ? CurPatt += 2 : CurPatt += 3;
			if (CurPatt[-1] == 0) return FirstMatch;
		}

		else if (FirstMatch) {
			ModuleStart = FirstMatch;
		Skip:
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	//failed
	return nullptr;
}

NTSTATUS CopyPhysics(void* Dst, const void* PhySics, size_t _MaxCount)
{
	MM_COPY_ADDRESS copyaddr;
	copyaddr.PhysicalAddress.QuadPart = (LONGLONG)PhySics;
	SIZE_T copyed = 0;
	return MmCopyMemory(Dst, copyaddr, _MaxCount, MM_COPY_MEMORY_PHYSICAL, &copyed);
}

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

BOOLEAN IsKernelDebuggerPresent()
{
	SYSTEM_KERNEL_DEBUGGER_INFORMATION DebuggerInfo;
	ULONG RetLen = 0;
	ZwQuerySystemInformation(SystemKernelDebuggerInformation, &DebuggerInfo, 8, &RetLen);

	return !DebuggerInfo.DebuggerNotPresent;
}

PVOID GetProcAddress(PVOID ModBase, const char* Name)
{
	if (!ModBase) return 0;
	//parse headers
	PIMAGE_NT_HEADERS NT_Head = NT_HEADER(ModBase);
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);

	//process records
	for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
	{
		//get ordinal & name
		USHORT Ordinal = ((USHORT*)((ULONG64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
		const char* ExpName = (const char*)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames))[i];

		//check export name
		if (StrICmp(Name, ExpName, true))
			return (PVOID)((ULONG64)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfFunctions))[Ordinal]);
	}

	//no export
	return nullptr;
}

//MmMapIoSpace, not allow write to page table 
NTSTATUS WritePhysicalSafe2(DWORD64 PhysicalAddress, pv Buffer, u64 Length)
{
	PHYSICAL_ADDRESS phy; phy.QuadPart = PhysicalAddress;
	PVOID MapedVirt = MmMapIoSpace(phy, Length, MmNonCached);
	if (!MapedVirt)
		return STATUS_UNSUCCESSFUL;

	memcpy(MapedVirt, Buffer, Length);
	MmUnmapIoSpace(MapedVirt, Length);
	return STATUS_SUCCESS;
}
