# Experimental Research .NET Anti-Cheat Framework (NACF)

Experimental Research .NET Anti-Cheat Framework Source Code

Copyright (c) ZeroLP. All rights reserved.
***
NACF is an experimental research project on .NET Anti-Cheat to demonstrate how extensive an anti-cheat software and its features can get in .NET and it's native implementation. 

The primary runtime of the framework is on .NET 5, however it is backward compatible to the lower versions of .NET runtime and .NET Framework where it supports relevant .NET and C# features used. 
The framework supports for builds both x86 and x64. In regards to the cross-platform support, it is unknown at this stage of the development and research; however, it may be explored in the future.

Current supporting features are:
 - Trampoline/Detour Hook (x86 & x64) 
 - Requesting PEB via an inline assembly call (x86 & x64)
 - Basic Anti-Debugging Check (BeingDebugged, NtGlobalFlag, ProcessHeap: Flags & ForceFlags)


# Hooks
**Trampoline/Detour Hook**
- For x86 version of the hook, it uses the standard relative E9 JMP instruction patching, and for x64 version, it uses a combination of r10 absolute JMP and the standard relative E9 JMP instruction patching for a gateway transition. R10 register was used due to it being labelled as a volatile register by the [Windows x64 Calling Convention](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160#calling-convention-defaults).

# Process Environment Block (PEB)
Pretty much ready to use. Although some extended structs are missing, it will be added along as the project goes.
This is cool, because it was my first encounter in using a function pointer on C#9, and it's also inlined too.
