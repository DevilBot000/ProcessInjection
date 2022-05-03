# Classic DLL Injection

List of files:

- [Overview](classic_dll_injection/README.md): Notes regarding the inners of this technique
- [C++ code](classic_dll_injection/code/cpp): Folder containing the C++ code

## Theory

At a high level, this technique is based on the creation of a thread, inside a victim process, that loads an arbitrary DLL library.

If you were to try to implement it using the Win32 API, you would have to follow the steps below:

1. Get a handle to the victim process, e.g. using `OpenProcess`
2. Allocate some space (for the next step) inside the memory space of the victim process, e.g. by means of `VirtualAllocEx`
3. Write the path of the DLL library inside the allocated memory, e.g. using `WriteProcessMemory`
4. Create a new thread inside the victim process to load the library and execute the malicious code, using functions such as `CreateRemoteThread` and `LoadLibrary`

## Dynamic-Link Library

As mentioned in the previous section, we need a DLL (or *Dynamic-Link Library*) to inject in the victim proces. Since we want something evident, so we're able to determine whether the technique was performed successfully or not, we'll be using a DLL file that spawns a message box.

Follows the source code of this file:

```cpp
#include "pch.h"

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // Handle to DLL module
    DWORD fdwReason,     // Reason for calling function
    LPVOID lpReserved)  // Reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
        // Initialize once for each new process.
        // Return FALSE if you want to have the loading of the DLL fail.
    case DLL_PROCESS_ATTACH:

        // Do thread-specific initialization.
    case DLL_THREAD_ATTACH:

        MessageBoxA(NULL, "Classic DLL Injection", "rbct", 0);
        break;

        // Do thread-specific cleanup.
    case DLL_THREAD_DETACH:
        break;

        // Perform any necessary cleanup.
    case DLL_PROCESS_DETACH:
        break;
    }

    // Successful DLL_PROCESS_ATTACH.
    return TRUE;
}
```

## Remarks

If you were to search for *DLL Injection* on the Internet, you yould probably stumble upon examples of source code which code don't use functions like `CreateToolhelp32Snapshot` and `Module32First`, or `EnumProcessModules` ([reference](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)).

Instead, they simply get the offset of function `LoadLibraryA` in the local process, by means of functions such as `GetProcAddress` and `GetModuleHandle`.

This approach happens to work most of the time, while failing in two particular cases:

|                          | Remote Process (32-bit) | Remote Process (64-bit) |
| ------------------------ | ----------------------- | ----------------------- |
| Current Process (32-bit) |    :heavy_check_mark:   |        :x:              |
| Current Proces (64-bit)  |          :x:            | :heavy_check_mark:      |

As shown in the table right above, the process injection will fail if the bitness of the remote process is different.

## References

- [Windows Process Injection in 2019](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)
- [Ten process injection techniques: A technical survey of common and trending process injection techniques](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
- [bearparser](https://github.com/hasherezade/bearparser)
- [Using CreateRemoteThread for DLL injection on Windows](https://resources.infosecinstitute.com/topic/using-createremotethread-for-dll-injection-on-windows/)
- [DLL Injection with CreateRemoteThread](https://stackoverflow.com/questions/22750112/dll-injection-with-createremotethread)
- [Portable Executable File Format](https://blog.kowalczyk.info/articles/pefileformat.html)
- [A dive into the PE file format - PE file structure - Part 4: Data Directories, Section Headers and Sections](https://0xrick.github.io/win-internals/pe5/)
