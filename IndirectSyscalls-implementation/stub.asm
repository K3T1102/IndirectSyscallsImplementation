.data
extern g_NtAllocateVirtualMemorySSN:DWORD
extern g_NtAllocateVirtualMemorySyscall:QWORD
extern g_NtWriteVirtualMemorySSN:DWORD
extern g_NtWriteVirtualMemorySyscall:QWORD
extern g_NtCreateThreadExSSN:DWORD
extern g_NtCreateThreadExSyscall:QWORD
extern g_NtWaitForSingleObjectSSN:DWORD
extern g_NtWaitForSingleObjectSyscall:QWORD
extern g_NtCloseSSN:DWORD
extern g_NtCloseSyscall:QWORD

.code

NtAllocateVirtualMemory PROC

    mov r10, rcx
    mov eax, g_NtAllocateVirtualMemorySSN
    jmp qword ptr [g_NtAllocateVirtualMemorySyscall]

NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC

    mov r10, rcx
    mov eax, g_NtWriteVirtualMemorySSN
    jmp qword ptr [g_NtWriteVirtualMemorySyscall]

NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC

    mov r10, rcx
    mov eax, g_NtCreateThreadExSSN
    jmp qword ptr [g_NtCreateThreadExSyscall]

NtCreateThreadEx ENDP

NtWaitForSingleObject PROC

    mov r10, rcx
    mov eax, g_NtWaitForSingleObjectSSN
    jmp qword ptr [g_NtWaitForSingleObjectSyscall]

NtWaitForSingleObject ENDP

NtClose PROC

    mov r10, rcx
    mov eax, g_NtCloseSSN
    jmp qword ptr [g_NtCloseSyscall]

NtClose ENDP

END