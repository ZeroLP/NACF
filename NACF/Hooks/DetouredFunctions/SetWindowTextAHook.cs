using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace NACF.Hooks.DetouredFunctions
{
    public class SetWindowTextAHook
    {
        private delegate bool SetWindowstextADelegate(IntPtr hwnd, string lpString);

        private static SetWindowstextADelegate HookedInstance, OriginalInstance;

        private static DetourEngine DEngine;

        static SetWindowTextAHook()
        {
            var funcAddr = DetourEngine.GetFunctionAddress("User32.dll", "SetWindowTextA");

            HookedInstance = HSetWindowTextA;
            OriginalInstance = Marshal.GetDelegateForFunctionPointer<SetWindowstextADelegate>(funcAddr);

            DEngine = new DetourEngine(funcAddr, Marshal.GetFunctionPointerForDelegate(HookedInstance));
        }

        public static void Install() => DEngine.Install();
        public static void Uninstall() => DEngine.Uninstall();

        private static bool HSetWindowTextA(IntPtr hwnd, string lpString)
        {
            Console.WriteLine($"SetWindowTextA is being called to set window to: {lpString}");

            return DEngine.CallOriginal<bool>(OriginalInstance, new object[] { hwnd, lpString });
        }
    }
}
