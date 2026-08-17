#include "helper.h"

PBYTE GetNtdllBase(void) {
    PPEB peb = (PPEB)__readgsqword(0x60);


    if (!peb || !peb->Ldr) {
        return NULL;
    }
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Length > 0 && entry->FullDllName.Buffer) {
            if (entry->FullDllName.Length >= 9 * sizeof(WCHAR)) {
                PWCHAR buf = entry->FullDllName.Buffer;
                PWCHAR filename = buf;
                for (int i = 0; i < (int)(entry->FullDllName.Length / sizeof(WCHAR)); i++) {
                    if (buf[i] == L'\\' || buf[i] == L'/') {
                        filename = &buf[i + 1];
                    }
                }
                if (_wcsicmp(filename, L"ntdll.dll") == 0) {
                    printf("[*] Peguei a Ntdll\n");
                    return (PBYTE)entry->DllBase;
                }
            }
        }

        curr = curr->Flink;
    }
    return NULL;
}

PVOID GetProcAddressPeb(PBYTE hModule, LPCSTR procName) {
    if (!hModule) return nullptr;

    auto dosHeader = (PIMAGE_DOS_HEADER)hModule;
    auto ntHeaders = (PIMAGE_NT_HEADERS)(hModule + dosHeader->e_lfanew);
    auto exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (!exportDirRVA) return nullptr;

    auto exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
    auto names = (DWORD*)(hModule + exportDir->AddressOfNames);
    auto ordinals = (WORD*)(hModule + exportDir->AddressOfNameOrdinals);
    auto functions = (DWORD*)(hModule + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        LPCSTR name = (LPCSTR)(hModule + names[i]);
        if (_stricmp(name, procName) == 0)
        {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];
            printf("[*] Peguei a função\n");
            return (PVOID)(hModule + funcRVA);
        }
    }

    return nullptr;
}
