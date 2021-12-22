#include "memory.h"
#include "shellcode.h"

ULONG64 getPte(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = getPteBase();
	return ((VirtualAddress >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 getPde(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = getPteBase();
	ULONG64 pte = getPte(VirtualAddress);
	return ((pte >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 getPdpte(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = getPteBase();
	ULONG64 pde = getPde(VirtualAddress);
	return ((pde >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 getPml4e(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = getPteBase();
	ULONG64 ppe = getPdpte(VirtualAddress);
	return ((ppe >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 getPteBase()
{
	static ULONG64 pte_base = NULL;
	if (pte_base) return pte_base;

	// 获取os版本
	ULONG64 versionNumber = 0;
	versionNumber = getOsVersionNumber();
	KdPrintEx((77, 0, "系统版本%lld\r\n", versionNumber));

	// win7或者1607以下
	if (versionNumber == 7601 || versionNumber == 7600 || versionNumber < 14393)
	{
		pte_base = 0xFFFFF68000000000ull;
		return pte_base;
	}
	else // win10 1607以上
	{
		//取PTE（第一种）
		UNICODE_STRING unName = { 0 };
		RtlInitUnicodeString(&unName, L"MmGetVirtualForPhysical");
		PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&unName);
		pte_base = *(PULONG64)(func + 0x22);
		return pte_base;
	}

	return pte_base;
}

PVOID AllocateMemory(HANDLE pid, ULONG64 size)
{
	PEPROCESS Process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	// 如果当前找到的进程已经退出
	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		return NULL;
	}

	KAPC_STATE kapc_state = { 0 };
	KeStackAttachProcess(Process, &kapc_state);

	PVOID BaseAddress = NULL;

	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &size, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	//写入shellcode
	//RtlMoveMemory(BaseAddress, shellcode, sizeof(shellcode);
	PVOID temp = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 10 - 0X100, 'ZYC');
	//RtlMoveMemory(BaseAddress, shellcode, PAGE_SIZE * 10 - 0x100);
	RtlMoveMemory(temp, shellcode, sizeof(shellcode));
	RtlMoveMemory(BaseAddress, temp, PAGE_SIZE * 10 - 0x200);

	// 修改可执行
	SetExecutePage(BaseAddress, size);

	

	KeUnstackDetachProcess(&kapc_state);

	return BaseAddress;
}

BOOLEAN SetExecutePage(ULONG64 VirtualAddress, ULONG size)
{
	ULONG64 startAddress = VirtualAddress & (~0xFFF); // 起始地址
	ULONG64 endAddress = (VirtualAddress + size) & (~0xFFF); // 结束地址 

	for (ULONG64 curAddress = startAddress; curAddress <= endAddress; curAddress += PAGE_SIZE)
	{
		//PMDL pMdl = IoAllocateMdl(curAddress, PAGE_SIZE, FALSE, FALSE, NULL);
		//MmProbeAndLockPages(pMdl, UserMode, IoReadAccess);

		PHardwarePte pde = getPde(curAddress);

		KdPrintEx((77, 0, "修改之前pde = %llx ", *pde));

		if (MmIsAddressValid(pde) && pde->valid == 1)
		{
			pde->no_execute = 0;
			pde->write = 1;
		}

		PHardwarePte pte = getPte(curAddress);
		KdPrintEx((77, 0, "pte = %llx\r\n", *pte));
		if (MmIsAddressValid(pte) && pte->valid == 1)
		{
			pte->no_execute = 0;
			pte->write = 1;
		}

		KdPrintEx((77, 0, "pde = %p pte = %p address = %p\r\n", pde, pte, curAddress));
		KdPrintEx((77, 0, "修改之后pde = %llx pte = %llx\r\n", *pde, *pte));
	}

	return TRUE;
}