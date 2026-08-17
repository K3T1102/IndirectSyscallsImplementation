.data
wSSN DWORD 0
wSyscall QWORD 0

.code

MeowGate PROC

    mov wSSN, ecx
    mov wSyscall, rdx
    ret

MeowGate ENDP


MeowDescent PROC

    mov r10, rcx
    mov eax, wSSN
    jmp qword ptr [wSyscall]

MeowDescent ENDP

END