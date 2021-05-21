using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using NACF.Tools;

namespace NACF.UnmanagedProviders
{
    public unsafe class PEBContextManager
    {
        //https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
        //https://www.aldeid.com/wiki/PEB-Process-Environment-Block

        private static nuint* _PEBPointer;
        public static nuint* PEBPointer
        {
            get
            {
                if((nint)_PEBPointer == 0)
                {
                    byte[] instruct = Environment.Is64BitProcess ? new byte[]
                    {
                        0x65, 0x48, 0xA1, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov rax, gs:60h
                        0xC3                                                              //ret
                    } : new byte[]
                    {
                        0x64, 0xa1, 0x30, 0x00, 0x00, 0x00,                              //mov eax, fs:30h
                        0xC3,                                                            //ret
                    };

                    fixed (void* p = instruct)
                    {
                        if (!NativeImport.VirtualProtect((IntPtr)p, (nuint)instruct.Length, NativeImport.NativeStructs.VirtualProtectionType.ExecuteReadWrite, out var oldProtection))
                            throw new Exception($"Failed to change protection to ExecuteReadWrite at: 0x{(nint)p:X}");

                        var ptrToPEB = ((delegate* unmanaged[Stdcall]<nuint*>)p)();

                        if (!NativeImport.VirtualProtect((IntPtr)p, (nuint)instruct.Length, oldProtection, out var temp))
                            throw new Exception($"Failed to change protection back to {oldProtection} at: 0x{(nint)p:X}");

                        _PEBPointer = ptrToPEB;
                    }
                }

                return _PEBPointer;
            }
        }

        private static _PEB? StoredPEB;
        public static _PEB GetPEB()
        {
            if(StoredPEB == null)
                StoredPEB = * (_PEB*)((nint)PEBPointer);
            return (_PEB)StoredPEB;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct _PEB
        {
#if WIN86
            [FieldOffset(0x0)] public byte InheritedAddressSpace;
            [FieldOffset(0x1)] public byte ReadImageFileExecOptions;
            [FieldOffset(0x2)] public byte BeingDebugged;
            [FieldOffset(0x3)] public byte SpareBool;
            [FieldOffset(0x4)] public nint* Mutant;
            [FieldOffset(0x8)] public nint ImageBaseAddress;
            [FieldOffset(0xC)] public nint PointerToLdr;
            public _PEB_LDR_DATA Ldr => *(_PEB_LDR_DATA*)(PointerToLdr);
            
            [FieldOffset(0x10)] public nint* ProcessParameters;
            [FieldOffset(0x14)] public nint* SubSystemData;
            [FieldOffset(0x18)] public nint* PointerToProcessHeap; //https://www.aldeid.com/wiki/PEB-Process-Environment-Block/ProcessHeap
            public _PEB_Process_Heap ProcessHeap => Marshal.PtrToStructure<_PEB_Process_Heap>((nint)PointerToProcessHeap);

            [FieldOffset(0x1C)] public nint* FastPebLock;
            [FieldOffset(0x20)] public nint* FastPebLockRoutine;
            [FieldOffset(0x24)] public nint* FastPebUnlockRoutine;
            [FieldOffset(0x28)] public nint EnvironmentUpdateCount;
            [FieldOffset(0x2C)] public nint* KernelCallbackTable;
            [FieldOffset(0x30)] public nint SystemReserved; //SystemReserved[1]
            [FieldOffset(0x34)] public nint ExecuteOptions; //length = 2
            [FieldOffset(0x34)] public nint SpareBits; //length = 30
            [FieldOffset(0x38)] public nint* FreeList;
            [FieldOffset(0x3C)] public nint TlsExpansionCounter;
            [FieldOffset(0x40)] public nint* TlsBitmap;
            [FieldOffset(0x44)] public nint TlsBitmapBits; //length = 2
            [FieldOffset(0x4C)] public nint* ReadOnlySharedMemoryBase;
            [FieldOffset(0x50)] public nint* ReadOnlySharedMemoryHeap;
            [FieldOffset(0x54)] public nint** ReadOnlyStaticServerData;
            [FieldOffset(0x58)] public nint* AnsiCodePageData;
            [FieldOffset(0x5C)] public nint* OemCodePageData;
            [FieldOffset(0x60)] public nint* UnicodeCaseTableData;
            [FieldOffset(0x64)] public nint NumberOfProcessors;
            [FieldOffset(0x68)] public byte NtGlobalFlag; //https://www.aldeid.com/wiki/PEB-Process-Environment-Block/NtGlobalFlag
            [FieldOffset(0x70)] public nint CriticalSectionTimeout; //https://stackoverflow.com/a/683810/7294598
            [FieldOffset(0x78)] public nint HeapSegmentReserve;
            [FieldOffset(0x7C)] public nint HeapSegmentCommit;
            [FieldOffset(0x80)] public nint HeapDeCommitTotalFreeThreshold;
            [FieldOffset(0x84)] public nint HeapDeCommitFreeBlockThreshold;
            [FieldOffset(0x88)] public nint NumberOfHeaps;
            [FieldOffset(0x8C)] public nint MaximumNumberOfHeaps;
            [FieldOffset(0x90)] public nint** ProcessHeaps;
            [FieldOffset(0x94)] public nint* GdiSharedHandleTable;
            [FieldOffset(0x98)] public nint* ProcessStarterHelper;
            [FieldOffset(0x9C)] public nint GdiDCAttributeList;
            [FieldOffset(0xA0)] public nint* LoaderLock;
            [FieldOffset(0xA4)] public nint OSMajorVersion;
            [FieldOffset(0xA8)] public nint OSMinorVersion;
            [FieldOffset(0xAC)] public ushort OSBuildNumber;
            [FieldOffset(0xAE)] public ushort OSCSDVersion;
            [FieldOffset(0xB0)] public nint OSPlatformId;
            [FieldOffset(0xB4)] public nint ImageSubsystem;
            [FieldOffset(0xB8)] public nint ImageSubsystemMajorVersion;
            [FieldOffset(0xBC)] public nint ImageSubsystemMinorVersion;
            [FieldOffset(0xC0)] public nint ImageProcessAffinityMask;
            [FieldOffset(0xC4)] public nint GdiHandleBuffer; //Length = 34
            //0x14c void (*PostProcessInitRoutine)();
            [FieldOffset(0x150)] public nint* TlsExpansionBitmap;
            [FieldOffset(0x154)] public nint TlsExpansionBitmapBits; //Length = 32
            [FieldOffset(0x1D4)] public nint SessionId;
            [FieldOffset(0x1D8)] public NativeImport.NativeStructs.LARGE_INTEGER AppCompatFlags;
            [FieldOffset(0x1E0)] public NativeImport.NativeStructs.LARGE_INTEGER AppCompatFlagsUser;
            [FieldOffset(0x1E8)] public nint* pShimData;
            [FieldOffset(0x1EC)] public nint* AppCompatInfo;
            //[FieldOffset(0x1F0)] public NativeImport.NativeStructs.UNICODE_STRING CSDVersion;
            [FieldOffset(0x1F8)] public nint* ActivationContextData;
            [FieldOffset(0x1FC)] public nint* ProcessAssemblyStorageMap;
            [FieldOffset(0x200)] public nint* SystemDefaultActivationContextData;
            [FieldOffset(0x204)] public nint* SystemAssemblyStorageMap;
            [FieldOffset(0x208)] public nint MinimumStackCommit;
#else
            [FieldOffset(0x0)] public byte InheritedAddressSpace;
            [FieldOffset(0x1)] public byte ReadImageFileExecOptions;
            [FieldOffset(0x2)] public byte BeingDebugged;
            [FieldOffset(0x3)] public byte SpareBool;
            [FieldOffset(0x8)] public nint* Mutant;
            [FieldOffset(0x10)] public nint ImageBaseAddress;
            [FieldOffset(0x18)] public nint PointerToLdr;
            public _PEB_LDR_DATA Ldr => *(_PEB_LDR_DATA*)(PointerToLdr);

            [FieldOffset(0x20)] public nint* ProcessParameters;
            [FieldOffset(0x28)] public nint* SubSystemData;
            [FieldOffset(0x30)] public nint* PointerToProcessHeap; //https://www.aldeid.com/wiki/PEB-Process-Environment-Block/ProcessHeap
            public _PEB_Process_Heap ProcessHeap => Marshal.PtrToStructure<_PEB_Process_Heap>((nint)PointerToProcessHeap);

            [FieldOffset(0x38)] public nint* FastPebLock;
            [FieldOffset(0x40)] public nint* FastPebLockRoutine;
            [FieldOffset(0x48)] public nint* FastPebUnlockRoutine;
            [FieldOffset(0x50)] public nint EnvironmentUpdateCount;
            [FieldOffset(0x58)] public nint* KernelCallbackTable;
            [FieldOffset(0x60)] public nint SystemReserved; //SystemReserved[1]
            [FieldOffset(0x64)] public nint ExecuteOptions; //length = 2
            [FieldOffset(0x68)] public nint SpareBits; //length = 30
            [FieldOffset(0x68)] public nint* FreeList;
            [FieldOffset(0x70)] public nint TlsExpansionCounter;
            [FieldOffset(0x78)] public nint* TlsBitmap;
            [FieldOffset(0x80)] public nint TlsBitmapBits; //length = 2
            [FieldOffset(0x88)] public nint* ReadOnlySharedMemoryBase;
            [FieldOffset(0x90)] public nint* ReadOnlySharedMemoryHeap;
            [FieldOffset(0x98)] public nint** ReadOnlyStaticServerData;
            [FieldOffset(0xA0)] public nint* AnsiCodePageData;
            [FieldOffset(0xA8)] public nint* OemCodePageData;
            [FieldOffset(0xB0)] public nint* UnicodeCaseTableData;
            [FieldOffset(0xB8)] public nint NumberOfProcessors;
            [FieldOffset(0xBC)] public byte NtGlobalFlag; //https://www.aldeid.com/wiki/PEB-Process-Environment-Block/NtGlobalFlag
            [FieldOffset(0xC0)] public nint CriticalSectionTimeout; //https://stackoverflow.com/a/683810/7294598
            [FieldOffset(0xC8)] public nint HeapSegmentReserve;
            [FieldOffset(0xD0)] public nint HeapSegmentCommit;
            [FieldOffset(0xD8)] public nint HeapDeCommitTotalFreeThreshold;
            [FieldOffset(0xE0)] public nint HeapDeCommitFreeBlockThreshold;
            [FieldOffset(0xE8)] public nint NumberOfHeaps;
            [FieldOffset(0xEC)] public nint MaximumNumberOfHeaps;
            [FieldOffset(0xF0)] public nint** ProcessHeaps;
            [FieldOffset(0xF8)] public nint* GdiSharedHandleTable;
            [FieldOffset(0x100)] public nint* ProcessStarterHelper;
            [FieldOffset(0x108)] public nint GdiDCAttributeList;
            [FieldOffset(0x110)] public nint* LoaderLock;
            [FieldOffset(0x118)] public nint OSMajorVersion;
            [FieldOffset(0x11C)] public nint OSMinorVersion;
            [FieldOffset(0x120)] public ushort OSBuildNumber;
            [FieldOffset(0x122)] public ushort OSCSDVersion;
            [FieldOffset(0x124)] public nint OSPlatformId;
            [FieldOffset(0x128)] public nint ImageSubsystem;
            [FieldOffset(0x12C)] public nint ImageSubsystemMajorVersion;
            [FieldOffset(0x130)] public nint ImageSubsystemMinorVersion;
            [FieldOffset(0x138)] public nint ImageProcessAffinityMask;
            [FieldOffset(0x140)] public nint GdiHandleBuffer; //Length = 34
            //0x14c void (*PostProcessInitRoutine)();
            [FieldOffset(0x238)] public nint* TlsExpansionBitmap;
            [FieldOffset(0x240)] public nint TlsExpansionBitmapBits; //Length = 32
            [FieldOffset(0x2C0)] public nint SessionId;
            [FieldOffset(0x2C8)] public NativeImport.NativeStructs.LARGE_INTEGER AppCompatFlags;
            [FieldOffset(0x2D0)] public NativeImport.NativeStructs.LARGE_INTEGER AppCompatFlagsUser;
            [FieldOffset(0x2D8)] public nint* pShimData;
            [FieldOffset(0x2E0)] public nint* AppCompatInfo;
            //[FieldOffset(0x2E8)] public NativeImport.NativeStructs.UNICODE_STRING CSDVersion;
            [FieldOffset(0x2F8)] public nint* ActivationContextData;
            [FieldOffset(0x300)] public nint* ProcessAssemblyStorageMap;
            [FieldOffset(0x308)] public nint* SystemDefaultActivationContextData;
            [FieldOffset(0x310)] public nint* SystemAssemblyStorageMap;
            [FieldOffset(0x318)] public nint MinimumStackCommit;
#endif
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct _PEB_Process_Heap
        {
            //https://www.aldeid.com/wiki/PEB-Process-Environment-Block/ProcessHeap
#if WIN86
            [FieldOffset(0x40)] public byte Flags;
            [FieldOffset(0x44)] public byte ForceFlags;
#else
            [FieldOffset(0x70)] public byte Flags;
            [FieldOffset(0x74)] public byte ForceFlags;
#endif
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct _PEB_LDR_DATA
        {
#if WIN86
            [FieldOffset(0x0)] public ulong Length; /* Size of structure, used by ntdll.dll as structure version ID */
            [FieldOffset(0x4)] public bool Initialized; /* If set, loader data section for current process is initialized */
            [FieldOffset(0x8)] public nint* SsHandle;
            [FieldOffset(0xC)] public nint* InLoadOrderModuleListPtr; /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in load order */
            [FieldOffset(0x14)] public nint* InMemoryOrderModuleListPtr; /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in memory placement order */
            public _List_Entry InMemoryOrderModuleList => (*(_List_Entry*)(nint)InMemoryOrderModuleListPtr);

            [FieldOffset(0x1C)] public nint* InInitializationOrderModuleListPtr; /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in initialization order */
            [FieldOffset(0x24)] public nint* EntryInProgress;
            [FieldOffset(0x28)] public byte ShutdownInProgress;
            [FieldOffset(0x2C)] public nint ShutdownThreadId;
#else
            [FieldOffset(0x0)] public ulong Length; /* Size of structure, used by ntdll.dll as structure version ID */
            [FieldOffset(0x4)] public bool Initialized; /* If set, loader data section for current process is initialized */
            [FieldOffset(0x8)] public nint* SsHandle;
            [FieldOffset(0x10)] public nint* InLoadOrderModuleListPtr; /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in load order */
            [FieldOffset(0x20)] public nint* InMemoryOrderModuleListPtr; /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in memory placement order */
            public _List_Entry InMemoryOrderModuleList => (*(_List_Entry*)(nint)InMemoryOrderModuleListPtr);

            [FieldOffset(0x30)] public nint* InInitializationOrderModuleListPtr; /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in initialization order */
            [FieldOffset(0x40)] public nint* EntryInProgress;
            [FieldOffset(0x48)] public byte ShutdownInProgress;
            [FieldOffset(0x50)] public nint ShutdownThreadId;
#endif
        }

        [StructLayout(LayoutKind.Explicit)] 
        public struct _List_Entry
        {
#if WIN86
            [FieldOffset(0x0)] public nint* Flink;
            [FieldOffset(0x4)] public nint* Blink;
#else
            [FieldOffset(0x0)] public nint* Flink;
            [FieldOffset(0x8)] public nint* Blink;
#endif
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct LDR_DATA_TABLE_ENTRY
        {
#if WIN86
            [FieldOffset(0x0)] public nint InLoadOrderLinksAddress;
            [FieldOffset(0x8)] public nint InMemoryOrderLinksAddress;
            [FieldOffset(0x10)] public nint InInitializationOrderLinks;
            [FieldOffset(0x18)] public nint DllBase;
            [FieldOffset(0x1C)] public nint EntryPoint;
            [FieldOffset(0x20)] public uint SizeOfImage;
            public nint FullDllNameAddress => InLoadOrderLinksAddress + 0x24;
            public nint BaseDllNameAddress => InLoadOrderLinksAddress + 0x2C;

            //https://stackoverflow.com/questions/6838302/list-entry-and-unicode-string-pinvoke-c-sharp
            public string FullDllName => (*(NativeImport.NativeStructs.UNICODE_STRING*)FullDllNameAddress).ToString();
            public string BaseDllName => (*(NativeImport.NativeStructs.UNICODE_STRING*)BaseDllNameAddress).ToString();

            [FieldOffset(0x34)] public uint Flags;
            [FieldOffset(0x38)] public uint ObsoleteLoadCount;
            [FieldOffset(0x3A)] public uint TlsIndex;
            [FieldOffset(0x48)] public nint* EntryPointActivationContext;
#else 
            [FieldOffset(0x0)] public nint InLoadOrderLinksAddress;
            [FieldOffset(0x10)] public nint InMemoryOrderLinksAddress;
            [FieldOffset(0x20)] public nint InInitializationOrderLinks;
            [FieldOffset(0x30)] public nint DllBase;
            [FieldOffset(0x38)] public nint EntryPoint;
            [FieldOffset(0x40)] public uint SizeOfImage;
            public nint FullDllNameAddress => InLoadOrderLinksAddress + 0x48;
            public nint BaseDllNameAddress => InLoadOrderLinksAddress + 0x58;

            //https://stackoverflow.com/questions/6838302/list-entry-and-unicode-string-pinvoke-c-sharp
            public string FullDllName => (*(NativeImport.NativeStructs.UNICODE_STRING*)FullDllNameAddress).ToString();
            public string BaseDllName => (*(NativeImport.NativeStructs.UNICODE_STRING*)BaseDllNameAddress).ToString();

            [FieldOffset(0x68)] public uint Flags;
            [FieldOffset(0x6C)] public uint LoadCount;
            [FieldOffset(0x6E)] public uint TlsIndex;
            [FieldOffset(0x70)] public nint* EntryPointActivationContext;
#endif
        }
    }
}
