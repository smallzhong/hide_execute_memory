#include "memory.h"

ULONG getOsVersionNumber()
{
		/*
		 Windows 10£¨20H2£©	19042
		 Windows 10£¨2004)  19041
		 Windows 10£¨1909£©	18363
		 Windows 10£¨1903£©	18362
		 Windows 10£¨1809£©	17763
		 Windows 10£¨1803£©	17134
		 Windows 10£¨1709£©	16299
		 Windows 10£¨1703£©	15063
		 Windows 10£¨1607£©	14393
		 Windows 10£¨1511£©	10586
		 Windows 10	(1507)	10240
		 
		 Windows 8.1£¨¸üÐÂ1£©	MajorVersion = 6 MinorVersion = 3 BuildNumber = 9600
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