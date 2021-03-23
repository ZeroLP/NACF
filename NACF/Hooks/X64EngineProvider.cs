using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using NACF.Tools;

namespace NACF.Hooks
{
    public unsafe class X64EngineProvider
    {
		private byte[] X64AbsoluteJmpInstructions;
		private byte[] RelativeJmpInstructions;
		private byte[] OriginalTargetFunctionInstructions;

		public nint TargetFunctionAddress { get; private set; }
		public nint HookedFunctionAddress { get; private set; }

		public X64EngineProvider(nint targetFuncAddr, nint hookedFuncAddr)
        {
			nint gatewayStubAddr = AllocateSinglePageNearAddress(targetFuncAddr);

			if (CreateGatewayStub(gatewayStubAddr, hookedFuncAddr) == 0)
				throw new Exception($"Failed to create gateway stub at: 0x{gatewayStubAddr:X}");
			else
            {
				TargetFunctionAddress = targetFuncAddr;
				HookedFunctionAddress = hookedFuncAddr;

				OriginalTargetFunctionInstructions = new byte[5];

				fixed (byte* p = OriginalTargetFunctionInstructions)
					DetourEngine.MemCpy((nint)p, targetFuncAddr, OriginalTargetFunctionInstructions.Length);

				BuildHook(gatewayStubAddr);
			}
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

		private void BuildHook(nint gatewayStubAddr)
        {
			NativeImport.NativeStructs.VirtualProtectionType oldProt;

			if (!NativeImport.VirtualProtect(TargetFunctionAddress, (UIntPtr)5, NativeImport.NativeStructs.VirtualProtectionType.ExecuteReadWrite, out oldProt))
				throw new Exception($"Failed to change page protection to ExecuteReadWrite at: 0x{TargetFunctionAddress:X}");

			RelativeJmpInstructions = new byte[]
		    {
			   0xE9,               //jmp [DWORD]
               0x0, 0x0, 0x0, 0x0 // DWORD
            };

			fixed (byte* allocInstructions = &RelativeJmpInstructions[0])
            {
				nint relAddr = gatewayStubAddr - (TargetFunctionAddress + RelativeJmpInstructions.Length);

				*(nint*)((nint)allocInstructions + 1) = relAddr;
			}

			Console.WriteLine("Successfully built X64 Hook");
		}

		private unsafe nuint CreateGatewayStub(nint gatewayStubAddr, nint addrToJmpTo)
        {
			X64AbsoluteJmpInstructions = new byte[]
		    {
			   0x49, 0xBA,                                            //movabs r10
			   0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,        //[QWORD]   
			   0x41, 0xFF, 0xE2                                       //jmp r10
		    };

			fixed (byte* allocInstructions = &X64AbsoluteJmpInstructions[0])
            {
				*(nint*)((nint)allocInstructions + 2) = addrToJmpTo; //Write hooked QWORD function address to third byte/second instruction

				DetourEngine.MemCpy(gatewayStubAddr, (nint)allocInstructions, X64AbsoluteJmpInstructions.Length); //Write instructions to the gateway stub address
			}

			return (nuint)X64AbsoluteJmpInstructions.Length;
        }

		private nint AllocateSinglePageNearAddress(nint targetAddr)
		{
			var sysInfo = new NativeImport.NativeStructs.SYSTEM_INFO();
			NativeImport.GetSystemInfo(ref sysInfo);

			nuint pageSize = sysInfo.dwPageSize;

			nuint startAddr = ((nuint)targetAddr & ~(pageSize - 1));
			nuint minAddr = (nuint)Math.Min((long)(startAddr - 0x7FFFFF00), sysInfo.lpMinimumApplicationAddress.ToInt64());
			nuint maxAddr = (nuint)Math.Min((long)(startAddr - 0x7FFFFF00), sysInfo.lpMaximumApplicationAddress.ToInt64());

			nuint startPage = (startAddr - (startAddr % pageSize));

			nuint pageOffset = 1;

			while (true)
			{
				nuint byteOffset = pageOffset * pageSize;
				nuint highAddr = startPage + byteOffset;
				nuint lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

				bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

				if (highAddr < maxAddr)
				{
					IntPtr outAddr = NativeImport.VirtualAlloc((nint)highAddr, pageSize, NativeImport.NativeStructs.AllocationType.Commit | NativeImport.NativeStructs.AllocationType.Reserve,
															   NativeImport.NativeStructs.MemoryProtection.ExecuteReadWrite);
					if (outAddr != IntPtr.Zero)
						return outAddr;
				}

				if (lowAddr > minAddr)
				{
					IntPtr outAddr = NativeImport.VirtualAlloc((nint)lowAddr, pageSize, NativeImport.NativeStructs.AllocationType.Commit | NativeImport.NativeStructs.AllocationType.Reserve,
															   NativeImport.NativeStructs.MemoryProtection.ExecuteReadWrite);
					if (outAddr != IntPtr.Zero)
						return outAddr;
				}

				pageOffset++;

				if (needsExit) break;
			}

			return 0;
		}
	}
}
