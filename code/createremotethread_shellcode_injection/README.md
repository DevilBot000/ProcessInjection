# CreateRemoteThread Shellcode Injection

List of files:

- [Overview](createremotethread/README.md): Notes regarding the inners of this technique
- [C++ code](createremotethread/code/cpp): Folder containing the C++ code

## Theory

At a high level, this technique is based on the following list of steps:

- allocate some memory in a target process
- write the shellcode we want to execute
- use the function `CreateRemoteThread` to execute the shellcode

## Remarks

The shellcode you inject in the victim process must use `ExitThread` instead of `ExitProcess` at the end, in order to avoid crashing the main thread and, as a consequence, the whole process.
