using System;
using System.Diagnostics;
using NACF.Tools;

namespace NACF
{
    public class EntryPoint
    {
        public unsafe static void Main()
        {
            Hooks.DetouredFunctions.SetWindowTextAHook.Install();

            NativeImport.SetWindowTextA(NativeImport.GetConsoleWindow(), "Test");
        }
    }
}



