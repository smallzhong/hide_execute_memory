#pragma once

#include <stdio.h>
#include <ntifs.h>
#include "structures.h"

PVOID AllocateMemory(HANDLE pid, ULONG64 size);
BOOLEAN SetExecutePage(ULONG64 VirtualAddress, ULONG size);
ULONG64 getPteBase();
ULONG getOsVersionNumber();
ULONG64 getPte(ULONG64 VirtualAddress);
ULONG64 getPde(ULONG64 VirtualAddress);
ULONG64 getPdpte(ULONG64 VirtualAddress);
ULONG64 getPml4e(ULONG64 VirtualAddress);