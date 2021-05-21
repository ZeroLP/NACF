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
            EnumerateModulesTest();
            //PEBTest();
            //HookTest();
        }

        private unsafe static void EnumerateModulesTest()
        {
            var peb = UnmanagedProviders.PEBContextManager.GetPEB();

            Console.WriteLine($"PointerToLdr: {peb.PointerToLdr:X}" +
                              $"\nInMemoryOrderModuleListPtr: {(nint)peb.Ldr.InMemoryOrderModuleListPtr:X}" +
                              $"\n");

            var baseModPtr = (nint)peb.Ldr.InMemoryOrderModuleList.Blink;
            var currModPtr = baseModPtr;

            do
            {
                var currModEntry = Marshal.PtrToStructure<UnmanagedProviders.PEBContextManager.LDR_DATA_TABLE_ENTRY>(currModPtr);

                if(!string.IsNullOrEmpty(currModEntry.FullDllName))
                    Console.WriteLine($"[0x{currModEntry.EntryPoint:X}] {currModEntry.FullDllName} - Size: {currModEntry.SizeOfImage:X}");

                currModPtr = currModEntry.InLoadOrderLinksAddress;
            }
            while (baseModPtr != currModPtr);
        }

        private unsafe static void PEBTest()
        {
            var peb = UnmanagedProviders.PEBContextManager.GetPEB();

            Console.WriteLine($"PEB: 0x{(nuint)UnmanagedProviders.PEBContextManager.PEBPointer:X}" +
                              $"\nBeingDebugged: {peb.BeingDebugged}" +
                              $"\nNtGlobalFlag: 0x{peb.NtGlobalFlag.ToString("X")}" +
                              $"\nLdr: 0x{((nint)peb.PointerToLdr).ToString("X")}" +
                              $"\nLdr Length: {peb.Ldr.Length}");
        }

        private static void HookTest()
        {
            Hooks.DetouredFunctions.SetWindowTextAHook.Install();

            NativeImport.SetWindowTextA(NativeImport.GetConsoleWindow(), "Test");
        }
    }
}



