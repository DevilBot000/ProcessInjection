#include "pch.h"

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // Handle to DLL module
	DWORD fdwReason,     // Reason for calling function
	LPVOID lpReserved)   // Reserved
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
