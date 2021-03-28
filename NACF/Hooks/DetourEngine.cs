using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NACF.Tools;

namespace NACF.Hooks
{
    public unsafe class DetourEngine
    {
        private X64EngineProvider X64HookEngineHandle;
        private X86EngineProvider X86HookEngineHandle;

        public DetourEngine(nint targetFuncAddr, nint hookedFuncAddr)
        {
            switch (Environment.Is64BitProcess.ToString()){case "True": X64HookEngineHandle = new X64EngineProvider(targetFuncAddr, hookedFuncAddr);break;case "False": X86HookEngineHandle = new X86EngineProvider(targetFuncAddr, hookedFuncAddr);break;}                
        }

        public void Install()
        {
            switch (Environment.Is64BitProcess.ToString()){case "True": X64HookEngineHandle.Install();break;case "False": X86HookEngineHandle.Install();break;}
        }

        public void Uninstall()
        {
            switch (Environment.Is64BitProcess.ToString()){case "True": X64HookEngineHandle.Uninstall();break;case "False": X86HookEngineHandle.Uninstall();break;}
        }

        public T CallOriginal<T>(Delegate origFunc, params object[] args)
        {
            switch (Environment.Is64BitProcess.ToString()){case "True": X64HookEngineHandle.CallOriginal<T>(origFunc, args);break;case "False": X86HookEngineHandle.CallOriginal<T>(origFunc, args);break;}
        }

        public static nint GetFunctionAddress(string libName, string funcName) => NativeImport.GetProcAddress(NativeImport.LoadLibrary(libName), funcName);

        public static void MemCpy(nint dest, nint source, int count)
        {
            var bufferSize = new UIntPtr((uint)count);
            NativeImport.NativeStructs.VirtualProtectionType oldProtection, temp;

            //Unprotect memory to copy buffer
            if (!NativeImport.VirtualProtect(dest, bufferSize, NativeImport.NativeStructs.VirtualProtectionType.ExecuteReadWrite, out oldProtection))
                throw new Exception($"Failed to change protection to ExecuteReadWrite at: 0x{dest:X}");

            byte* pDest = (byte*)dest;
            byte* pSrc = (byte*)source;

            // copy buffer to address
            for (int i = 0; i < count; i++)
                *(pDest + i) = *(pSrc + i);

            //Protect back
            if (!NativeImport.VirtualProtect(dest, bufferSize, oldProtection, out temp))
                throw new Exception($"Failed to change protection back to {oldProtection} at: 0x{dest:X}");
        }
    }
}
