# windows64位分页机制分析-隐藏可执行内存方法

+ 之前一直没发过文章，只是一直看文章，这次也想分享一些东西出来。由于本人的水平有限，也是初学者，因此如果有一些错误还望海涵。

+ 在32位系统下，windows有两种分页机制，2-9-9-12分页以及10-10-12分页，而在64位下只有一种分页机制，那就是9-9-9-9-12分页。在64位下，线性地址的结构如下图所示

  ![img](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/162118543952835.png)

  在x64体系中，只有48位是用来确定虚拟地址的，前面的16位成为符号拓展位，这16位只有为全1或者为全0两种情况。除了这两种情况之外的地址都是不合法的。这16为为全1时表示这个地址是一个内核空间的地址，而为全0时表示这个地址是一个用户空间的地址。而在windows操作系统中，由于种种原因，又只用了这48位线性地址中的 **44位** 。也就是说windows分配的线性地址前20位都是要么为全0，要么为全1。而CPU没有这个规定。所以我们其实可以找到一块windows永远不会使用，而又合法的线性地址空间。可以利用这块空间做一些事情而不用害怕被分配出去。这里不展开说。

+ 在64位下，存在三种不同大小的页面，分别为大页、中页、小页。其大小分别为1GB、2MB、4KB。

+ 探索系统的分页机制最好的办法是对内核中的 `MiIsAddressValid` 函数的实现进行分析。win7和win10的64位系统下使用的是两种不同的查找 `pte` 、 `pde` 、 `pdpte` 、 `pml4e` 的方式。接下来分别对两个系统的该函数进行相应的分析

## win7 64位 `MiIsAddressValid` 函数分析

+ win7 64位下的 `MiIsAddressValid` 如下

  ![image-20211222191909910](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/image-20211222191909910.png)

  首先通过移位，查看前16位是否为全0或者全1，如果不是，返回不合法。然后通过移位分别分出9-9-9-9-12这5部分，然后加上相应的基址，找到对应的 `pte,pde,pdpte,pml4e` ，并判断P位是否为0。如果为0返回不合法。

  该函数较为简单，将减去的数值取反加一可以得到对应的基址

  ```cpp
  printf("%llx", ~0x98000000000 + 1);
  >>> fffff68000000000
  ```

  可得在win7 64位下，其 `PTE_BASE` 为 `fffff68000000000` 。

## win10 64位 `MiIsAddressValid` 函数分析

+ 在 `win10 1607` 以上版本，微软为分页基址加上了随机页目录基址，这让定位 `pte` 变得更加困难。 `PTE_BASE` 不再是之前写死的值，而是每次开机都会随机在一定的范围内挑选一个值。而在 `win10 64` 位下的 `MmIsAddressValidEx` 函数中，其更换了另外一套寻找 `pte,pde,pdpte,pml4e` 的方法，如下

  ![image-20211222192618338](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/image-20211222192618338.png)

+ 可以看到这里计算 `pte,pde,pdpte,pml4e` 的时候用的都只有一个 `pte_base` ，不再像win7那样求每个值的时候都使用一个不同的基址。而可以验证，在win7下，使用这样的方法来获取 `pte,pde,pdpte,pml4e` 一样可行。

## 通过修改pde和pte属性隐藏可执行内存

+ 这是一个由来已久的方法，在申请一块不可执行的内存后通过修改 `pte` 与 `pde` 手动将页面设置为可执行，达到隐藏可执行内存的目的。在编写这样的驱动的过程中也能巩固对x64分页机制的认识。

+ 首先写一个用来验证的程序，程序本身很简单，跳转到我们输入的地址来验证我们写入程序中的shellcode是否可执行。如下

  ```cpp
  DWORD addr;
  scanf("%x", &addr);
  __asm
  {
      jmp addr
  }
  ```

  如果跳转到的地址是不可执行的，那么shellcode不会被执行，程序会异常退出。

+ 接下来开始驱动的编写，主要要实现的是一个分配内存的 `AllocateMemory` 函数，可以往指定pid的进程中写入shellcode，并隐藏其可执行属性，使这块内存在vad树中看来是不可执行的。

  ![image-20211222193451300](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/image-20211222193451300.png)

+ 在函数中进行进程的挂靠，然后通过 `ZwAllocateMemory` 在函数中分配一块保护为 `PAGE_READWRITE` 属性的内存。

  ![image-20211222193618802](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/image-20211222193618802.png)

  最后写入shellcode，并在写入shellcode后将申请的内存全部设置为可执行。

  ![image-20211222193657746](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/image-20211222193657746.png)

  代码如下

  ```cpp
  #include "memory.h"
  #include "shellcode.h"
  
  ULONG getOsVersionNumber()
  {
  		/*
  		 Windows 10（20H2）	19042
  		 Windows 10（2004)  19041
  		 Windows 10（1909）	18363
  		 Windows 10（1903）	18362
  		 Windows 10（1809）	17763
  		 Windows 10（1803）	17134
  		 Windows 10（1709）	16299
  		 Windows 10（1703）	15063
  		 Windows 10（1607）	14393
  		 Windows 10（1511）	10586
  		 Windows 10	(1507)	10240
  		 
  		 Windows 8.1（更新1）	MajorVersion = 6 MinorVersion = 3 BuildNumber = 9600
  		 Windows 8.1			MajorVersion = 6 MinorVersion = 3 BuildNumber = 9200
  		 Windows 8				MajorVersion = 6 MinorVersion = 2 BuildNumber = 9200
  	*/
  	RTL_OSVERSIONINFOEXW version = {0};
  	
  	NTSTATUS status = RtlGetVersion(&version);
  
  	if (!NT_SUCCESS(status))
  	{
  		return 0;
  	}
  
  	return version.dwBuildNumber;
  }
  
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
  	RtlMoveMemory(BaseAddress, shellcode, sizeof(shellcode);
  
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
  ```

+ 最后进行实验，查看代码是否可行。首先开启我们的验证进程，查看其vad树，如下

  ![image-20211222194244271](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/image-20211222194244271.png)

+ 接下来加载驱动，可看到其在对应进程中申请的内存地址为 `12f0000` 。而且从输出中可以看出 `shellcode` 所在的地址的 `pte` 的最高位（no_execute）从之前的1被修改为了0。

  ![image-20211222194527707](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/image-20211222194527707.png)

+ 重新查看其vad树，发现 `12f0000` 出多出了一块 `PAGE_READWRITE` 属性的内存，从vad树中看其是不可执行的。但是在程序中输入地址，可以看到 `shellcode` 成功执行，验证成功。

  ![image-20211222194724486](https://raw.githubusercontent.com/smallzhong/new_new_picgo_picbed/main/image-20211222194724486.png)