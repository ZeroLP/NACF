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
                var peb = UnmanagedProviders.PEBContextManager.GetPEB();

                //Kernel32!IsDebuggerPresent()
                //Kernel32!CheckRemoteDebuggerPresent() -> Self Process
                //NtDll!NtSetDebugFilterState()
                //NtDll!RtlQueryProcessHeapInformation()

                if (peb.BeingDebugged == 1 
                || peb.NtGlobalFlag == 0x70 
                || peb.ProcessHeap.Flags > 2 
                || peb.ProcessHeap.ForceFlags > 0)
                    return true;

                return false;
            }
        }
    }
}
