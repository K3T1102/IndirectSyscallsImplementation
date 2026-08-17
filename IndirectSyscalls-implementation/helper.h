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

// Enumeração para indicar como a syscall foi resolvida


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
DWORD GetSSNFromSyscallTable(const char* Name);
PVOID GetGadgetFromSyscallTable(const char* Name);

