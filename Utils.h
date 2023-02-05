#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>

typedef unsigned long long u64;
typedef signed long long i64;
typedef volatile unsigned long long vu64;
typedef unsigned int u32;
typedef void* pv;
typedef void* pv64;
typedef unsigned short u16;
typedef unsigned char u8;
typedef volatile unsigned char vu8;
#define __db __debugbreak
#define noinl __declspec(noinline)
#define naked __declspec(naked)
#define inl __forceinline

#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))
#define RVA2(Instr, InstrSize, Off) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + Off))

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0x0,
    SystemProcessorInformation = 0x1,
    SystemPerformanceInformation = 0x2,
    SystemTimeOfDayInformation = 0x3,
    SystemPathInformation = 0x4,
    SystemProcessInformation = 0x5,
    SystemCallCountInformation = 0x6,
    SystemDeviceInformation = 0x7,
    SystemProcessorPerformanceInformation = 0x8,
    SystemFlagsInformation = 0x9,
    SystemCallTimeInformation = 0xa,
    SystemModuleInformation = 0xb,
    SystemLocksInformation = 0xc,
    SystemStackTraceInformation = 0xd,
    SystemPagedPoolInformation = 0xe,
    SystemNonPagedPoolInformation = 0xf,
    SystemHandleInformation = 0x10,
    SystemObjectInformation = 0x11,
    SystemPageFileInformation = 0x12,
    SystemVdmInstemulInformation = 0x13,
    SystemVdmBopInformation = 0x14,
    SystemFileCacheInformation = 0x15,
    SystemPoolTagInformation = 0x16,
    SystemInterruptInformation = 0x17,
    SystemDpcBehaviorInformation = 0x18,
    SystemFullMemoryInformation = 0x19,
    SystemLoadGdiDriverInformation = 0x1a,
    SystemUnloadGdiDriverInformation = 0x1b,
    SystemTimeAdjustmentInformation = 0x1c,
    SystemSummaryMemoryInformation = 0x1d,
    SystemMirrorMemoryInformation = 0x1e,
    SystemPerformanceTraceInformation = 0x1f,
    SystemObsolete0 = 0x20,
    SystemExceptionInformation = 0x21,
    SystemCrashDumpStateInformation = 0x22,
    SystemKernelDebuggerInformation = 0x23,
    SystemContextSwitchInformation = 0x24,
    SystemRegistryQuotaInformation = 0x25,
    SystemExtendServiceTableInformation = 0x26,
    SystemPrioritySeperation = 0x27,
    SystemVerifierAddDriverInformation = 0x28,
    SystemVerifierRemoveDriverInformation = 0x29,
    SystemProcessorIdleInformation = 0x2a,
    SystemLegacyDriverInformation = 0x2b,
    SystemCurrentTimeZoneInformation = 0x2c,
    SystemLookasideInformation = 0x2d,
    SystemTimeSlipNotification = 0x2e,
    SystemSessionCreate = 0x2f,
    SystemSessionDetach = 0x30,
    SystemSessionInformation = 0x31,
    SystemRangeStartInformation = 0x32,
    SystemVerifierInformation = 0x33,
    SystemVerifierThunkExtend = 0x34,
    SystemSessionProcessInformation = 0x35,
    SystemLoadGdiDriverInSystemSpace = 0x36,
    SystemNumaProcessorMap = 0x37,
    SystemPrefetcherInformation = 0x38,
    SystemExtendedProcessInformation = 0x39,
    SystemRecommendedSharedDataAlignment = 0x3a,
    SystemComPlusPackage = 0x3b,
    SystemNumaAvailableMemory = 0x3c,
    SystemProcessorPowerInformation = 0x3d,
    SystemEmulationBasicInformation = 0x3e,
    SystemEmulationProcessorInformation = 0x3f,
    SystemExtendedHandleInformation = 0x40,
    SystemLostDelayedWriteInformation = 0x41,
    SystemBigPoolInformation = 0x42,
    SystemSessionPoolTagInformation = 0x43,
    SystemSessionMappedViewInformation = 0x44,
    SystemHotpatchInformation = 0x45,
    SystemObjectSecurityMode = 0x46,
    SystemWatchdogTimerHandler = 0x47,
    SystemWatchdogTimerInformation = 0x48,
    SystemLogicalProcessorInformation = 0x49,
    SystemWow64SharedInformationObsolete = 0x4a,
    SystemRegisterFirmwareTableInformationHandler = 0x4b,
    SystemFirmwareTableInformation = 0x4c,
    SystemModuleInformationEx = 0x4d,
    SystemVerifierTriageInformation = 0x4e,
    SystemSuperfetchInformation = 0x4f,
    SystemMemoryListInformation = 0x50,
    SystemFileCacheInformationEx = 0x51,
    SystemThreadPriorityClientIdInformation = 0x52,
    SystemProcessorIdleCycleTimeInformation = 0x53,
    SystemVerifierCancellationInformation = 0x54,
    SystemProcessorPowerInformationEx = 0x55,
    SystemRefTraceInformation = 0x56,
    SystemSpecialPoolInformation = 0x57,
    SystemProcessIdInformation = 0x58,
    SystemErrorPortInformation = 0x59,
    SystemBootEnvironmentInformation = 0x5a,
    SystemHypervisorInformation = 0x5b,
    SystemVerifierInformationEx = 0x5c,
    SystemTimeZoneInformation = 0x5d,
    SystemImageFileExecutionOptionsInformation = 0x5e,
    SystemCoverageInformation = 0x5f,
    SystemPrefetchPatchInformation = 0x60,
    SystemVerifierFaultsInformation = 0x61,
    SystemSystemPartitionInformation = 0x62,
    SystemSystemDiskInformation = 0x63,
    SystemProcessorPerformanceDistribution = 0x64,
    SystemNumaProximityNodeInformation = 0x65,
    SystemDynamicTimeZoneInformation = 0x66,
    SystemCodeIntegrityInformation = 0x67,
    SystemProcessorMicrocodeUpdateInformation = 0x68,
    SystemProcessorBrandString = 0x69,
    SystemVirtualAddressInformation = 0x6a,
    SystemLogicalProcessorAndGroupInformation = 0x6b,
    SystemProcessorCycleTimeInformation = 0x6c,
    SystemStoreInformation = 0x6d,
    SystemRegistryAppendString = 0x6e,
    SystemAitSamplingValue = 0x6f,
    SystemVhdBootInformation = 0x70,
    SystemCpuQuotaInformation = 0x71,
    SystemNativeBasicInformation = 0x72,
    SystemErrorPortTimeouts = 0x73,
    SystemLowPriorityIoInformation = 0x74,
    SystemBootEntropyInformation = 0x75,
    SystemVerifierCountersInformation = 0x76,
    SystemPagedPoolInformationEx = 0x77,
    SystemSystemPtesInformationEx = 0x78,
    SystemNodeDistanceInformation = 0x79,
    SystemAcpiAuditInformation = 0x7a,
    SystemBasicPerformanceInformation = 0x7b,
    SystemQueryPerformanceCounterInformation = 0x7c,
    SystemSessionBigPoolInformation = 0x7d,
    SystemBootGraphicsInformation = 0x7e,
    SystemScrubPhysicalMemoryInformation = 0x7f,
    SystemBadPageInformation = 0x80,
    SystemProcessorProfileControlArea = 0x81,
    SystemCombinePhysicalMemoryInformation = 0x82,
    SystemEntropyInterruptTimingInformation = 0x83,
    SystemConsoleInformation = 0x84,
    SystemPlatformBinaryInformation = 0x85,
    SystemThrottleNotificationInformation = 0x86,
    SystemHypervisorProcessorCountInformation = 0x87,
    SystemDeviceDataInformation = 0x88,
    SystemDeviceDataEnumerationInformation = 0x89,
    SystemMemoryTopologyInformation = 0x8a,
    SystemMemoryChannelInformation = 0x8b,
    SystemBootLogoInformation = 0x8c,
    SystemProcessorPerformanceInformationEx = 0x8d,
    SystemSpare0 = 0x8e,
    SystemSecureBootPolicyInformation = 0x8f,
    SystemPageFileInformationEx = 0x90,
    SystemSecureBootInformation = 0x91,
    SystemEntropyInterruptTimingRawInformation = 0x92,
    SystemPortableWorkspaceEfiLauncherInformation = 0x93,
    SystemFullProcessInformation = 0x94,
    SystemKernelDebuggerInformationEx = 0x95,
    SystemBootMetadataInformation = 0x96,
    SystemSoftRebootInformation = 0x97,
    SystemElamCertificateInformation = 0x98,
    SystemOfflineDumpConfigInformation = 0x99,
    SystemProcessorFeaturesInformation = 0x9a,
    SystemRegistryReconciliationInformation = 0x9b,
    MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;
typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;
typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

extern "C"
{
    NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(
        _In_ PVOID ImageBase,
        _In_ PCCH RoutineNam
    );

    NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(
        PEPROCESS Process
    );

    //phy and PhysicalLength must be 0x1000 align
    NTKERNELAPI NTSTATUS MmMarkPhysicalMemoryAsBad(
        IN PPHYSICAL_ADDRESS phy,
        IN OUT PLARGE_INTEGER PhysicalLength
    );

    NTKERNELAPI NTSTATUS MmMarkPhysicalMemoryAsGood(
        IN PPHYSICAL_ADDRESS phy,
        IN OUT PLARGE_INTEGER PhysicalLength
    );

    NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );
}

NTSTATUS getKernelModuleByName(const char* moduleName, PVOID* moduleStart, size_t* moduleSize);

NTSTATUS GetProcessIdByProcessName(LPWCH ImageName, OUT HANDLE* OutPid);

PUCHAR FindPatternSect(PVOID ModBase, const char* SectName, const char* Pattern);

PUCHAR FindPatternRange(PVOID Start, u32 size, const char* Pattern);

NTSTATUS RtlSuperCopyMemory(IN VOID* Dst, IN CONST VOID* Src, IN ULONG Length);

NTSTATUS RtlSuperWriteMemoryPipi(IN VOID* Dst, IN CONST VOID* Src, IN ULONG Length);

void Log2File(const char* format, ...);

BOOLEAN IsKernelDebuggerPresent();

PVOID GetProcAddress(PVOID ModBase, const char* Name);

NTSTATUS WritePhysicalSafe2(DWORD64 PhysicalAddress, pv Buffer, u64 Length);

inl void KSleep(u64 ms)
{
    LARGE_INTEGER delay;
    delay.QuadPart = -1000 * ms;
    KeDelayExecutionThread(KernelMode, TRUE, &delay);
}

///**
// * The 32-bit EFLAGS register contains a group of status flags, a control flag, and a group of system flags. The status
// * flags (bits 0, 2, 4, 6, 7, and 11) of the EFLAGS register indicate the results of arithmetic instructions, such as the
// * ADD, SUB, MUL, and DIV instructions.
// * The system flags and IOPL field in the EFLAGS register control operating-system or executive operations.
// *
// * @see Vol1[3.4.3(EFLAGS)] (reference)
// */
//typedef union
//{
//    struct
//    {
//        /**
//         * @brief Carry flag
//         *
//         * [Bit 0] Set if an arithmetic operation generates a carry or a borrow out of the mostsignificant bit of the result;
//         * cleared otherwise. This flag indicates an overflow condition for unsigned-integer arithmetic. It is also used in
//         * multiple-precision arithmetic.
//         */
//        UINT32 CarryFlag : 1;
//
//        /**
//         * [Bit 1] Reserved - always 1
//         */
//        UINT32 ReadAs1 : 1;
//
//        /**
//         * @brief Parity flag
//         *
//         * [Bit 2] Set if the least-significant byte of the result contains an even number of 1 bits; cleared otherwise.
//         */
//        UINT32 ParityFlag : 1;
//        UINT32 Reserved1 : 1;
//
//        /**
//         * @brief Auxiliary Carry flag
//         *
//         * [Bit 4] Set if an arithmetic operation generates a carry or a borrow out of bit 3 of the result; cleared otherwise. This
//         * flag is used in binary-coded decimal (BCD) arithmetic.
//         */
//        UINT32 AuxiliaryCarryFlag : 1;
//        UINT32 Reserved2 : 1;
//
//        /**
//         * @brief Zero flag
//         *
//         * [Bit 6] Set if the result is zero; cleared otherwise.
//         */
//        UINT32 ZeroFlag : 1;
//
//        /**
//         * @brief Sign flag
//         *
//         * [Bit 7] Set equal to the most-significant bit of the result, which is the sign bit of a signed integer. (0 indicates a
//         * positive value and 1 indicates a negative value.)
//         */
//        UINT32 SignFlag : 1;
//
//        /**
//         * @brief Trap flag
//         *
//         * [Bit 8] Set to enable single-step mode for debugging; clear to disable single-step mode.
//         */
//        UINT32 TrapFlag : 1;
//
//        /**
//         * @brief Interrupt enable flag
//         *
//         * [Bit 9] Controls the response of the processor to maskable interrupt requests. Set to respond to maskable interrupts;
//         * cleared to inhibit maskable interrupts.
//         */
//        UINT32 InterruptEnableFlag : 1;
//
//        /**
//         * @brief Direction flag
//         *
//         * [Bit 10] Controls string instructions (MOVS, CMPS, SCAS, LODS, and STOS). Setting the DF flag causes the string
//         * instructions to auto-decrement (to process strings from high addresses to low addresses). Clearing the DF flag causes
//         * the string instructions to auto-increment (process strings from low addresses to high addresses).
//         */
//        UINT32 DirectionFlag : 1;
//
//        /**
//         * @brief Overflow flag
//         *
//         * [Bit 11] Set if the integer result is too large a positive number or too small a negative number (excluding the
//         * sign-bit) to fit in the destination operand; cleared otherwise. This flag indicates an overflow condition for
//         * signed-integer (two's complement) arithmetic.
//         */
//        UINT32 OverflowFlag : 1;
//
//        /**
//         * @brief I/O privilege level field
//         *
//         * [Bits 13:12] Indicates the I/O privilege level of the currently running program or task. The current privilege level
//         * (CPL) of the currently running program or task must be less than or equal to the I/O privilege level to access the I/O
//         * address space. The POPF and IRET instructions can modify this field only when operating at a CPL of 0.
//         */
//        UINT32 IoPrivilegeLevel : 2;
//
//        /**
//         * @brief Nested task flag
//         *
//         * [Bit 14] Controls the chaining of interrupted and called tasks. Set when the current task is linked to the previously
//         * executed task; cleared when the current task is not linked to another task.
//         */
//        UINT32 NestedTaskFlag : 1;
//        UINT32 Reserved3 : 1;
//
//        /**
//         * @brief Resume flag
//         *
//         * [Bit 16] Controls the processor's response to debug exceptions.
//         */
//        UINT32 ResumeFlag : 1;
//
//        /**
//         * @brief Virtual-8086 mode flag
//         *
//         * [Bit 17] Set to enable virtual-8086 mode; clear to return to protected mode without virtual-8086 mode semantics.
//         */
//        UINT32 Virtual8086ModeFlag : 1;
//
//        /**
//         * @brief Alignment check (or access control) flag
//         *
//         * [Bit 18] If the AM bit is set in the CR0 register, alignment checking of user-mode data accesses is enabled if and only
//         * if this flag is 1. If the SMAP bit is set in the CR4 register, explicit supervisor-mode data accesses to user-mode pages
//         * are allowed if and only if this bit is 1.
//         *
//         * @see Vol3A[4.6(ACCESS RIGHTS)]
//         */
//        UINT32 AlignmentCheckFlag : 1;
//
//        /**
//         * @brief Virtual interrupt flag
//         *
//         * [Bit 19] Virtual image of the IF flag. Used in conjunction with the VIP flag. (To use this flag and the VIP flag the
//         * virtual mode extensions are enabled by setting the VME flag in control register CR4.)
//         */
//        UINT32 VirtualInterruptFlag : 1;
//
//        /**
//         * @brief Virtual interrupt pending flag
//         *
//         * [Bit 20] Set to indicate that an interrupt is pending; clear when no interrupt is pending. (Software sets and clears
//         * this flag; the processor only reads it.) Used in conjunction with the VIF flag.
//         */
//        UINT32 VirtualInterruptPendingFlag : 1;
//
//        /**
//         * @brief Identification flag
//         *
//         * [Bit 21] The ability of a program to set or clear this flag indicates support for the CPUID instruction.
//         */
//        UINT32 IdentificationFlag : 1;
//        UINT32 Reserved4 : 10;
//    };
//
//    UINT32 AsUInt;
//} EFLAGS;
//
///**
// * The 64-bit RFLAGS register contains a group of status flags, a control flag, and a group of system flags in 64-bit mode.
// * The upper 32 bits of RFLAGS register is reserved. The lower 32 bits of RFLAGS is the same as EFLAGS.
// *
// * @see EFLAGS
// * @see Vol1[3.4.3.4(RFLAGS Register in 64-Bit Mode)] (reference)
// */
//typedef union
//{
//    struct
//    {
//        /**
//         * @brief Carry flag
//         *
//         * [Bit 0] See the description in EFLAGS.
//         */
//        UINT64 CarryFlag : 1;
//
//        /**
//         * [Bit 1] Reserved - always 1
//         */
//        UINT64 ReadAs1 : 1;
//
//        /**
//         * @brief Parity flag
//         *
//         * [Bit 2] See the description in EFLAGS.
//         */
//        UINT64 ParityFlag : 1;
//        UINT64 Reserved1 : 1;
//
//        /**
//         * @brief Auxiliary Carry flag
//         *
//         * [Bit 4] See the description in EFLAGS.
//         */
//        UINT64 AuxiliaryCarryFlag : 1;
//        UINT64 Reserved2 : 1;
//
//        /**
//         * @brief Zero flag
//         *
//         * [Bit 6] See the description in EFLAGS.
//         */
//        UINT64 ZeroFlag : 1;
//
//        /**
//         * @brief Sign flag
//         *
//         * [Bit 7] See the description in EFLAGS.
//         */
//        UINT64 SignFlag : 1;
//
//        /**
//         * @brief Trap flag
//         *
//         * [Bit 8] See the description in EFLAGS.
//         */
//        UINT64 TrapFlag : 1;
//
//        /**
//         * @brief Interrupt enable flag
//         *
//         * [Bit 9] See the description in EFLAGS.
//         */
//        UINT64 InterruptEnableFlag : 1;
//
//        /**
//         * @brief Direction flag
//         *
//         * [Bit 10] See the description in EFLAGS.
//         */
//        UINT64 DirectionFlag : 1;
//
//        /**
//         * @brief Overflow flag
//         *
//         * [Bit 11] See the description in EFLAGS.
//         */
//        UINT64 OverflowFlag : 1;
//
//        /**
//         * @brief I/O privilege level field
//         *
//         * [Bits 13:12] See the description in EFLAGS.
//         */
//        UINT64 IoPrivilegeLevel : 2;
//
//        /**
//         * @brief Nested task flag
//         *
//         * [Bit 14] See the description in EFLAGS.
//         */
//        UINT64 NestedTaskFlag : 1;
//        UINT64 Reserved3 : 1;
//
//        /**
//         * @brief Resume flag
//         *
//         * [Bit 16] See the description in EFLAGS.
//         */
//        UINT64 ResumeFlag : 1;
//
//        /**
//         * @brief Virtual-8086 mode flag
//         *
//         * [Bit 17] See the description in EFLAGS.
//         */
//        UINT64 Virtual8086ModeFlag : 1;
//
//        /**
//         * @brief Alignment check (or access control) flag
//         *
//         * [Bit 18] See the description in EFLAGS.
//         *
//         * @see Vol3A[4.6(ACCESS RIGHTS)]
//         */
//        UINT64 AlignmentCheckFlag : 1;
//
//        /**
//         * @brief Virtual interrupt flag
//         *
//         * [Bit 19] See the description in EFLAGS.
//         */
//        UINT64 VirtualInterruptFlag : 1;
//
//        /**
//         * @brief Virtual interrupt pending flag
//         *
//         * [Bit 20] See the description in EFLAGS.
//         */
//        UINT64 VirtualInterruptPendingFlag : 1;
//
//        /**
//         * @brief Identification flag
//         *
//         * [Bit 21] See the description in EFLAGS.
//         */
//        UINT64 IdentificationFlag : 1;
//        UINT64 Reserved4 : 42;
//    };
//
//    UINT64 AsUInt;
//} RFLAGS;
//