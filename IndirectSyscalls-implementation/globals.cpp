#include "helper.h"

extern "C" {

	DWORD g_NtAllocateVirtualMemorySSN = 0;
	QWORD g_NtAllocateVirtualMemorySyscall = 0;

	DWORD g_NtWriteVirtualMemorySSN = 0;
	QWORD g_NtWriteVirtualMemorySyscall = 0;

	DWORD g_NtCreateThreadExSSN = 0;
	QWORD g_NtCreateThreadExSyscall = 0;

	DWORD g_NtWaitForSingleObjectSSN = 0;
	QWORD g_NtWaitForSingleObjectSyscall = 0;

	DWORD g_NtCloseSSN = 0;
	QWORD g_NtCloseSyscall = 0;

}