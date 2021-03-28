using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace NACF.Hooks.DetouredFunctions
{
    public class LoadLibraryAHook
    {
        private delegate bool LoadLibraryADelegate(string lpFileName);

        private static LoadLibraryADelegate HookedInstance, OriginalInstance;

        private static DetourEngine DEngine;

        static LoadLibraryAHook()
        {
            var funcAddr = DetourEngine.GetFunctionAddress("Kernel32.dll", "LoadLibraryA");

            HookedInstance = HLoadLibraryA;
            OriginalInstance = Marshal.GetDelegateForFunctionPointer<LoadLibraryADelegate>(funcAddr);

            DEngine = new DetourEngine(funcAddr, Marshal.GetFunctionPointerForDelegate(HookedInstance));
        }

        public static void Install() => DEngine.Install();
        public static void Uninstall() => DEngine.Uninstall();

        private static bool HLoadLibraryA(string lpFileName)
        {
            Console.WriteLine($"LoadLibraryA is being called to load: {lpFileName}");

            return DEngine.CallOriginal<bool>(OriginalInstance, new object[] { lpFileName });
        }
    }
}
