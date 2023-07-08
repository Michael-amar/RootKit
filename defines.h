// documented
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_SIZEOF_SHORT_NAME              8

// Directory Entries
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

typedef unsigned short      WORD;
typedef DWORD*				PDWORD;
typedef unsigned char       BYTE;
typedef WORD*				PWORD;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;



typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_DOS_HEADER 
{      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

// undocumented
// most undocumented structs are taken from  https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm

enum SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0x00,
	SystemProcessorInformation = 0x01,
	SystemPerformanceInformation = 0x02,
	SystemTimeOfDayInformation = 0x03,
	SystemPathInformation = 0x04,
	SystemProcessInformation = 0x05,
	SystemCallCountInformation = 0x06,
	SystemDeviceInformation = 0x07,
	SystemProcessorPerformanceInformation= 0x08,
	SystemFlagsInformation = 0x09,
	SystemCallTimeInformation= 0x0A,
	SystemModuleInformation = 0x0B,
	SystemLocksInformation = 0x0C,
	SystemStackTraceInformation = 0x0D,
	SystemPagedPoolInformation = 0x0E,
	SystemNonPagedPoolInformation = 0x0F,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation= 0x13,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation	= 0x19,
	SystemTimeAdjustmentInformation	= 0x1C,
	SystemSummaryMemoryInformation = 0x1D,
	SystemNextEventIdInformation = 0x1E,
	SystemPerformanceTraceInformation= 0x1F,
	SystemCrashDumpInformation = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation	= 0x22,
	SystemKernelDebuggerInformation	= 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemPlugPlayBusInformation = 0x28,
	SystemDockInformation = 0x29,
	SystemProcessorIdleInformation = 0x2A,
	SystemLegacyDriverInformation = 0x2B,
	SystemCurrentTimeZoneInformation = 0x2C,
	SystemLookasideInformation = 0x2D,
	SystemRangeStartInformation	= 0x32,
	SystemVerifierInformation = 0x33,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3A,
	SystemComPlusPackage = 0x3B,
	SystemNumaAvailableMemory = 0x3C,
	SystemProcessorPowerInformation	= 0x3D,
	SystemEmulationBasicInformation = 0x3E,
	SystemEmulationProcessorInformation = 0x3F,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation	= 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	unknown	= 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemFirmwareTableInformation = 0x4C,
	SystemModuleInformationEx = 0x4D,
	SystemSuperfetchInformation	= 0x4F,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemProcessorIdleCycleTimeInformation	= 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemBootEnvironmentInformation = 0x5A,
	SystemHypervisorInformation	= 0x5B,
	SystemVerifierInformationEx	= 0x5C,
	SystemCoverageInformation = 0x5F,
	SystemPrefetchPatchInformation = 0x60,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6A,
	SystemProcessorCycleTimeInformation = 0x6C,
	SystemStoreInformation = 0x6D,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemAcpiAuditInformation = 0x7A,
	SystemBasicPerformanceInformation = 0x7B,
	SystemQueryPerformanceCounterInformation = 0x7C,
	SystemSessionBigPoolInformation = 0x7D,
	SystemBootGraphicsInformation = 0x7E,
	SystemBadPageInformation = 0x80,
	SystemPlatformBinaryInformation	= 0x85,
	SystemPolicyInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8A,
	SystemMemoryChannelInformation = 0x8B,
	SystemBootLogoInformation = 0x8C,
	SystemProcessorPerformanceInformationEx = 0x8D,
	SystemSecureBootPolicyInformation = 0x8F,
	SystemPageFileInformationEx	= 0x90,
	SystemSecureBootInformation = 0x91,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9A,
	SystemEdidInformation = 0x9C,
	SystemManufacturingInformation = 0x9D,
	SystemEnergyEstimationConfigInformation	= 0x9E,
	SystemHypervisorDetailInformation = 0x9F,
	SystemProcessorCycleStatsInformation = 0xA0,
	SystemTrustedPlatformModuleInformation = 0xA2,
	SystemKernelDebuggerFlags = 0xA3,
	SystemCodeIntegrityPolicyInformation = 0xA4,
	SystemIsolatedUserModeInformation = 0xA5,
	SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
	SystemSingleModuleInformation = 0xA7,
	SystemDmaProtectionInformation = 0xA9,
	SystemSecureBootPolicyFullInformation = 0xAB,
	SystemCodeIntegrityPolicyFullInformation = 0xAC,
	SystemAffinitizedInterruptProcessorInformation = 0xAD,
	SystemRootSiloInformation = 0xAE,
	SystemCpuSetInformation = 0xAF,
	SystemSecureKernelProfileInformation = 0xB2,
	SystemCodeIntegrityPlatformManifestInformation = 0xB3,
	SystemInterruptSteeringInformation = 0xB4,
	SystemSupportedProcessorArchitectures = 0xB5,
	SystemMemoryUsageInformation = 0xB6,
	SystemCodeIntegrityCertificateInformation = 0xB7,
	SystemPhysicalMemoryInformation = 0xB8,
	SystemControlFlowTransition = 0xB9,
	SystemKernelDebuggingAllowed = 0xBA,
	SystemActivityModerationUserSettings = 0xBC,
	SystemCodeIntegrityPoliciesFullInformation = 0xBD,
	SystemCodeIntegrityUnlockInformation = 0xBE,
	SystemFlushInformation = 0xC0,
	SystemProcessorIdleMaskInformation = 0xC1,
	SystemWriteConstraintInformation = 0xC3,
	SystemKernelVaShadowInformation = 0xC4,
	SystemHypervisorSharedPageInformation = 0xC5,
	SystemFirmwareBootPerformanceInformation = 0xC6,
	SystemCodeIntegrityVerificationInformation = 0xC7,
	SystemFirmwarePartitionInformation = 0xC8,
	SystemSpeculationControlInformation = 0xC9,
	SystemDmaGuardPolicyInformation = 0xCA,
};

typedef NTSTATUS(NTAPI* PZwQuerySystemInformation)
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	PVOID Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR FullPathName[0x0100];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

