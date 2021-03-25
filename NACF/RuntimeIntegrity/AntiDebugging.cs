using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NACF.RuntimeIntegrity
{
    public class AntiDebugging
    {
        //https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-ntglobalflag
        //https://www.virusbulletin.com/virusbulletin/2010/05/anti-unpacker-tricks-part-eight

        public static bool IsUsermodeDebuggerAttached
        {
            get
            {
                int flagCount = 0;

                var pebX86 = UnmanagedProviders.PEBContextManager.GetX86PEB();
                var pebX64 = UnmanagedProviders.PEBContextManager.GetX64PEB();
                var isProcX64 = Environment.Is64BitProcess;

                //Kernel32!IsDebuggerPresent()
                //Kernel32!CheckRemoteDebuggerPresent() -> Self Process
                //NtDll!NtSetDebugFilterState()
                //NtDll!RtlQueryProcessHeapInformation()

                if ((isProcX64 ? pebX64.BeingDebugged : pebX86.BeingDebugged) == 1)
                    flagCount++;

                if ((isProcX64 ? pebX64.NtGlobalFlag : pebX86.NtGlobalFlag) == 0x70)
                    flagCount++;

                //https://rvsec0n.wordpress.com/2019/09/13/routines-utilizing-tebs-and-pebs/
                if ((isProcX64 ? pebX64.ProcessHeap.Flags : pebX86.ProcessHeap.Flags) > 2
                    || (isProcX64 ? pebX64.ProcessHeap.ForceFlags : pebX86.ProcessHeap.ForceFlags) > 0)
                    flagCount++;

                return flagCount >= 1;
            }
        }
    }
}
