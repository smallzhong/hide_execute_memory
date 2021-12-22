#include <ntifs.h>
#include "Memory.h"

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	KdPrintEx((77, 0, "driver unload\r\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	KdPrintEx((77, 0, "driver entry\r\n"));

	KdPrintEx((77, 0, "PTE_BASE = %p\r\n", getPteBase()));

	PVOID base = AllocateMemory(2180, PAGE_SIZE * 10);
	DbgPrintEx(77, 0, "[db]:%p\r\n", base);

	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}