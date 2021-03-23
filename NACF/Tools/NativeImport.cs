using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace NACF.Tools
{
    public class NativeImport
    {
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, NativeStructs.VirtualProtectionType flNewProtect, out NativeStructs.VirtualProtectionType lpflOldProtect);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void GetSystemInfo(ref NativeStructs.SYSTEM_INFO Info);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, NativeStructs.AllocationType lAllocationType, NativeStructs.MemoryProtection flProtect);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool SetWindowTextA(IntPtr hwnd, String lpString);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();

        public class NativeStructs
        {
            public enum VirtualProtectionType : uint
            {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                NoAccess = 0x01,
                Readonly = 0x02,
                ReadWrite = 0x04,
                WriteCopy = 0x08,
                GuardModifierflag = 0x100,
                NoCacheModifierflag = 0x200,
                WriteCombineModifierflag = 0x400
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SYSTEM_INFO
            {
                public ushort wProcessorArchitecture;
                public ushort wReserved;
                public uint dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public IntPtr dwActiveProcessorMask;
                public uint dwNumberOfProcessors;
                public uint dwProcessorType;
                public uint dwAllocationGranularity;
                public ushort wProcessorLevel;
                public ushort wProcessorRevision;
            }

            [Flags]
            public enum AllocationType
            {
                Commit = 0x1000,
                Reserve = 0x2000,
                Decommit = 0x4000,
                Release = 0x8000,
                Reset = 0x80000,
                Physical = 0x400000,
                TopDown = 0x100000,
                WriteWatch = 0x200000,
                LargePages = 0x20000000
            }

            [Flags]
            public enum MemoryProtection
            {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                NoAccess = 0x01,
                ReadOnly = 0x02,
                ReadWrite = 0x04,
                WriteCopy = 0x08,
                GuardModifierflag = 0x100,
                NoCacheModifierflag = 0x200,
                WriteCombineModifierflag = 0x400
            }
        }
    }
}
