/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_KMDFDriver5,
    0x534c0a0a,0xfc6d,0x4d1a,0xa5,0x8f,0x48,0xf3,0x54,0xd9,0xc5,0x86);
// {534c0a0a-fc6d-4d1a-a58f-48f354d9c586}
