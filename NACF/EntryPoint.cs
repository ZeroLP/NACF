using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NACF.Tools;

namespace NACF
{
    public class EntryPoint
    {
        public unsafe static void Main()
        {
            PEBTest();
        }

        private unsafe static void PEBTest()
        {
            var pebX86 = UnmanagedProviders.PEBContextManager.GetX86PEB();
            var pebX64 = UnmanagedProviders.PEBContextManager.GetX64PEB();

            var isProcX64 = Environment.Is64BitProcess;

            Console.WriteLine($"PEB: 0x{(nuint)UnmanagedProviders.PEBContextManager.PEBPointer:X}\nBeingDebugged: {(isProcX64 ? pebX64.BeingDebugged : pebX86.BeingDebugged)}\nNtGlobalFlag: 0x{(isProcX64 ? pebX64.NtGlobalFlag.ToString("X") : pebX86.NtGlobalFlag.ToString("X"))}\nLdr: 0x{(isProcX64 ? ((nint)pebX64.PointerToLdr).ToString("X") : ((nint)pebX86.PointerToLdr).ToString("X"))}\nLdr Length: {(isProcX64 ? pebX64.Ldr.Length : pebX86.Ldr.Length)}");
        }

        private static void HookTest()
        {
            Hooks.DetouredFunctions.SetWindowTextAHook.Install();

            NativeImport.SetWindowTextA(NativeImport.GetConsoleWindow(), "Test");
        }
    }
}



