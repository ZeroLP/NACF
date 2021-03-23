using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NACF.Hooks
{
    public unsafe class X86EngineProvider
    {
        private byte[] RelativeJmpInstructions;
        private byte[] OriginalTargetFunctionInstructions;

        public nint TargetFunctionAddress { get; private set; }
        public nint HookedFunctionAddress { get; private set; }

        public X86EngineProvider(nint targetFuncAddr, nint hookedFuncAddr)
        {
            TargetFunctionAddress = targetFuncAddr;
            HookedFunctionAddress = hookedFuncAddr;

            OriginalTargetFunctionInstructions = new byte[5];

            fixed (byte* p = OriginalTargetFunctionInstructions)
                DetourEngine.MemCpy((nint)p, targetFuncAddr, OriginalTargetFunctionInstructions.Length);

            BuildHook();
        }

        public void Install()
        {
            fixed (byte* p = RelativeJmpInstructions)
                DetourEngine.MemCpy(TargetFunctionAddress, (nint)p, RelativeJmpInstructions.Length);

            Console.WriteLine($"Successfully installed hook at: 0x{TargetFunctionAddress:X}");
        }

        public void Uninstall()
        {
            fixed (byte* p = OriginalTargetFunctionInstructions)
                DetourEngine.MemCpy(TargetFunctionAddress, (nint)p, OriginalTargetFunctionInstructions.Length);

            Console.WriteLine($"Successfully uninstalled hook at: 0x{TargetFunctionAddress:X}");
        }

        public T CallOriginal<T>(Delegate origFunc, params object[] args)
        {
            Uninstall();

            var ret = origFunc.DynamicInvoke(args);
            this.Install();

            return (T)ret;
        }

        private void BuildHook()
        {
            RelativeJmpInstructions = new byte[]
            {
                0xE9,                 //Jmp [DWORD]
                0x0, 0x0, 0x0, 0x0    //DWORD
            };

            fixed(byte* allocInstructions = &RelativeJmpInstructions[1])
                *(nint*)((nint)allocInstructions) = HookedFunctionAddress - TargetFunctionAddress - 5;

            Console.WriteLine("Successfully built X86 Hook");
        }
    }
}
