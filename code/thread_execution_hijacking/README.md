# Thread Execution Hihacking

List of files:

- [Overview](thread_execution_hijacking/README.md): Notes regarding the inners of this technique
- [C++ code](thread_execution_hijacking/code/cpp): Folder containing the C++ code

## Theory

Mapped by the MITRE ATT&CK framework as [T1055.003](https://attack.mitre.org/techniques/T1055/003/), this technique is very similar to *Process Hollowing*, as they're both based on three steps:

1. *suspend*
2. *overwrite*
3. *resume*

However, the main difference between the two techniques is that, while Process Hollowing creates another process, *Thread Execution Hijacking* simply targets another process, suspending, overwriting, and resuming one of its threads.

### First step - Suspend

Given a malware that implements this technique, the first thing it tries to do is enumerate the processes, using API calls such as:

- `CreateToolhelp32Snapshot` from the DLL library `Tlhelp32.h`
- `EnumProcesses` from the DLL library `Psapi.h`

Alternatively, an attacker may pass the *Process Identifier* (PID) of the victim process as an *evironment variable* or a command-line argument (`argv`), if they already known the PID of the target process.

Once the attacker has chosen the victim process, they need to get a *HANDLE* to that process, which can be accomplished using the API call `OpenProcess`.

After that, the malware performs the following actions in order to suspend the target thread:

1. list the threads of the process using API calls such as `CreateToolhelp32Snapshot` (with the parameter `TH32CS_SNAPTHREAD`)
2. get the *HANDLE* of the interested thread using `Thread32First` and `Thread32First`
3. suspend the thread using the API call `SuspendThread`

### Second step - Overwrite

Once the first step (*suspend*) is accomplished, it's time move onto the second one: *overwrite*, which consists in the malware **allocating** some space in the memory of the suspended thread and then **writing** the malicious code in the allocated memory space, thus performing Process Injection.

The allocation is usually performed by means of the function `VirtualAllocEx`, while you can use the API call `WriteProcessMemory` in order to copy the bytes of the malicious code in the allocated memory space.

### Third step - Resume

Before actually resuming the thread, the malware needs to *hijack the execution* of the thread, as suggested by the name of the technique. This means chaning the address stored inside the *Instruction Pointer*, i.e. `RIP` on 64-bit systems or `EIP` on 32-bit systems.

If you were to resume the execution of the thread without changing the instruction pointer, then the thread would continue to execute the original code, never executing the malicious code you just injected.

For that reason, the malware would hijack the instruction pointer by means of an API call such as `SetThreadContext`, which allows you to easily modify the value of the registers, hence `EIP` and `RIP` too.

Once the hijacking part is performed, what's left is to resume the execution of the thread using the API call `ResumeThread`. At this point the malicious code would be finally executed, in our case spawning a *MessageBox* or receiving a reverse shell.
