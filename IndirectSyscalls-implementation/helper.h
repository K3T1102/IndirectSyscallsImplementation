#pragma once

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

//PEB Walking
PBYTE GetNtdllBase(void);
PVOID GetProcAddressPeb(PBYTE hModule, LPCSTR procName);

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef unsigned __int64 QWORD;

// Definições dos bytes
#define PATTERN_MOV_R10_RCX_0 0x4C
#define PATTERN_MOV_R10_RCX_1 0x8B
#define PATTERN_MOV_R10_RCX_2 0xD1

#define PATTERN_MOV_EAX_IMM32 0xB8

#define PATTERN_SYSCALL_0 0x0F
#define PATTERN_SYSCALL_1 0x05

#define PATTERN_RET 0xC3

#define PATTERN_JMP_REL32 0xE9
#define PATTERN_JMP_QWORD 0xFF

// Estrutura para armazenar informações sobre syscalls
enum
{
    SYSCALL_ALLOCATE,
    SYSCALL_WRITE_PROCESS,
    SYSCALL_CREATE_REMOTE_THREAD,
    SYSCALL_WAITFOR_SINGLE_OBJECT,
    SYSCALL_CLOSE,
    SYSCALL_COUNT
};

// Variáveis globais que vão passar para o asembly armazenando SSN e endereço do gadget
extern "C" {
    extern DWORD g_NtAllocateVirtualMemorySSN;
    extern QWORD g_NtAllocateVirtualMemorySyscall;
    extern DWORD g_NtWriteVirtualMemorySSN;
    extern QWORD g_NtWriteVirtualMemorySyscall;
    extern DWORD g_NtCreateThreadExSSN;
    extern QWORD g_NtCreateThreadExSyscall;
    extern DWORD g_NtWaitForSingleObjectSSN;
    extern QWORD g_NtWaitForSingleObjectSyscall;
    extern DWORD g_NtCloseSSN;
    extern QWORD g_NtCloseSyscall;
}
// Struct que armazena as syscalls
struct SYSCALL_ENTRY
{
    const char* Name;
    DWORD SSN;
    PVOID Gadget;
    BOOL IsHooked;
};

extern SYSCALL_ENTRY Syscalls[SYSCALL_COUNT];

// Funções da resolve_syscalls
DWORD ExtractSSN(_In_ PBYTE stubAddr, _Out_ BOOL* isHooked);
BOOL ResolveSSNFromNeighbor(_In_ PBYTE stubAddr, _Out_ DWORD* outSSN);
PVOID FindSyscallGadget(_In_ PBYTE stubAddr);
BOOL ResolveAllSyscalls(const char* funcName, SYSCALL_ENTRY* Syscall);
BOOL InitializeSycallTable(void);
BOOL GetSSNFromSyscallTable(const char* Name, DWORD* NtfunctionSSN);
BOOL GetGadgetFromSyscallTable(const char* Name, QWORD* NtfunctionSyscall);

// Declarações das funções nativas
extern "C" NTSTATUS NtAllocateVirtualMemory(
    _In_      HANDLE ProcessHandle,
    _Inout_   PVOID* BaseAddress,
    _In_      ULONG ZeroBits,
    _Inout_   PSIZE_T RegionSize,
    _In_      ULONG AllocationType,
    _In_      ULONG Protect
);

extern "C" NTSTATUS NtWriteVirtualMemory(
    _In_      HANDLE ProcessHandle,
    _In_      PVOID BaseAddress,
    _In_      PVOID Buffer,
    _In_      SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

extern "C" NTSTATUS NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_  ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  HANDLE ProcessHandle,
    _In_  PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_  ULONG CreateFlags,
    _In_  SIZE_T ZeroBits,
    _In_  SIZE_T StackSize,
    _In_  SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
);

extern "C" NTSTATUS NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

extern "C" NTSTATUS NtClose(
    _In_ HANDLE Handle
);