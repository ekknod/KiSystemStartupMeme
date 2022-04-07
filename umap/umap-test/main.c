
#include "stdafx.h"

CHAR8 *gEfiCallerBaseName = "boot";
UINT32 _gUefiDriverRevision = 0;

EFI_EXIT_BOOT_SERVICES ExitBootServicesOriginal;

UINT8 ImgArchStartBootApplicationOriginal[JMP_SIZE];
IMG_ARCH_START_BOOT_APPLICATION ImgArchStartBootApplication;

UINT8 BlImgAllocateImageBufferOriginal[JMP_SIZE];
BL_IMG_ALLOCATE_IMAGE_BUFFER BlImgAllocateImageBuffer;

UINT8 OslFwpKernelSetupPhase1Original[JMP_SIZE];
OSL_FWP_KERNEL_SETUP_PHASE_1 OslFwpKernelSetupPhase1;

struct {
    VOID *Base;
    UINT32 Size;

    // For 64-bit UEFI platforms, this naming is misleading as the boot process is
    // always in long mode (ignoring AP startup). The point is that when winload
    // switches to its own custom context, boot services cannot be invoked hence
    // saving the status in a global. /aside
    CHAR16 *ProtectedModeError;
    EFI_STATUS ProtectedModeStatus;
} winload = { NULL };

struct {
    VOID *AllocatedBuffer;
    EFI_STATUS AllocatedBufferStatus;
} mapper = { NULL };






UINT64 ntoskrnl_base = 0;


VOID* gNotifyEvent;
VOID EFIAPI SetVirtualAddressMapEvent(
        IN EFI_EVENT Event,
        IN VOID* Context
)
{
        gNotifyEvent = NULL;



}

// UEFI entrypoint
EFI_STATUS EFIAPI UefiMain(EFI_HANDLE imageHandle,
    EFI_SYSTEM_TABLE *systemTable) {
    gST->ConOut->ClearScreen(gST->ConOut);
    gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);

    // Locate the Windows EFI bootmgr
    EFI_DEVICE_PATH *bootmgrPath = GetWindowsBootmgrDevicePath();
    if (!bootmgrPath) {
        Print(L"Failed to find the Windows EFI bootmgr\n");
        gBS->Stall(SEC_TO_MICRO(2));

        return EFI_NOT_FOUND;
    }

    EFI_STATUS status = SetBootCurrentToWindowsBootmgr();
    if (EFI_ERROR(status)) {
        Print(L"Failed to set BootCurrent to Windows EFI bootmgr\n");
        gBS->Stall(SEC_TO_MICRO(2));

        FreePool(bootmgrPath);
        return status;
    }

    // Load the Windows EFI bootmgr
    EFI_HANDLE bootmgrHandle;
    status =
        gBS->LoadImage(TRUE, imageHandle, bootmgrPath, NULL, 0, &bootmgrHandle);

    if (EFI_ERROR(status)) {
        Print(L"Failed to load the Windows EFI bootmgr: %r\n", status);
        gBS->Stall(SEC_TO_MICRO(2));

        FreePool(bootmgrPath);
        return status;
    }

    FreePool(bootmgrPath);

    // Setup the hook chain
    status = SetupHooks(bootmgrHandle);
    if (EFI_ERROR(status)) {
        Print(L"Failed to setup hooks: %r\n", status);
        gBS->Stall(SEC_TO_MICRO(2));

        gBS->UnloadImage(bootmgrHandle);
        return status;
    }

    const EFI_GUID VirtualGuid = { 0x13FA7698, 0xC831, 0x49C7, { 0x87, 0xEA, 0x8F, 0x43, 0xFC, 0xC2, 0x51, 0x96 } };
    if (EFI_ERROR(gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, SetVirtualAddressMapEvent, NULL, &VirtualGuid, &gNotifyEvent))) {
            Print(L"initialization failed\n");
            return EFI_INVALID_PARAMETER;
    }

    // Start the Windows EFI bootmgr
    status = gBS->StartImage(bootmgrHandle, NULL, NULL);
    if (EFI_ERROR(status)) {
        Print(L"Failed to start the Windows EFI bootmgr: %r\n", status);
        gBS->Stall(SEC_TO_MICRO(2));

        gBS->UnloadImage(bootmgrHandle);
        return status;
    }

    return EFI_SUCCESS;
}

// Sets up the hook chain from bootmgr -> winload -> ntoskrnl
EFI_STATUS EFIAPI SetupHooks(EFI_HANDLE bootmgrHandle) {
    // Get the bootmgr image from the image handle
    EFI_LOADED_IMAGE *bootmgr;
    EFI_STATUS status = gBS->HandleProtocol(
        bootmgrHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&bootmgr);

    if (EFI_ERROR(status)) {
        Print(L"Failed to get the boot manager image: %r\n", status);
        return status;
    }

    // Hook ImgArchStartBootApplication to setup winload hooks
    VOID *func = FindPattern(bootmgr->ImageBase, bootmgr->ImageSize,
        "\x48\x8B\xC4\x48\x89\x58\x20\x44\x89\x40\x18\x48"
        "\x89\x50\x10\x48\x89\x48\x08\x55\x56\x57\x41\x54",
        "xxxxxxxxxxxxxxxxxxxxxxxx");

    if (!func) {
        Print(L"Failed to find ImgArchStartBootApplication\n");
        return EFI_NOT_FOUND;
    }

    ImgArchStartBootApplication =
        (IMG_ARCH_START_BOOT_APPLICATION)TrampolineHook(
            (VOID *)ImgArchStartBootApplicationHook, func,
            ImgArchStartBootApplicationOriginal);

    return EFI_SUCCESS;
}

// Called from bootmgr to start the winload image

EFI_STATUS EFIAPI ImgArchStartBootApplicationHook(VOID *appEntry,
    VOID *imageBase,
    UINT32 imageSize,
    UINT8 bootOption,
    VOID *returnArguments) {

    TrampolineUnHook((VOID *)ImgArchStartBootApplication,
        ImgArchStartBootApplicationOriginal);

    winload.Base = imageBase;
    winload.Size = imageSize;

    /*
    // Find and hook OslFwpKernelSetupPhase1 to get a pointer to ntoskrnl
    VOID *funcCall =
        FindPattern(imageBase, imageSize,
            "\x74\x07\xE8\x00\x00\x00\x00\x8B\xD8", "xxx????xx");

    if (!funcCall) {
        Print(L"Failed to find OslExecuteTransition\n");
        gBS->Stall(SEC_TO_MICRO(2));

        return ImgArchStartBootApplication(appEntry, imageBase, imageSize,
            bootOption, returnArguments);
    }

    funcCall = FindPattern(RELATIVE_ADDR((UINT8 *)funcCall + 2, 5), 0x4F,
        "\x48\x8B\xCF\xE8", "xxxx");

    if (!funcCall) {
        Print(L"Failed to find OslFwpKernelSetupPhase1\n");
        gBS->Stall(SEC_TO_MICRO(2));

        return ImgArchStartBootApplication(appEntry, imageBase, imageSize,
            bootOption, returnArguments);
    }

    OslFwpKernelSetupPhase1 = (OSL_FWP_KERNEL_SETUP_PHASE_1)TrampolineHook(
        (VOID *)OslFwpKernelSetupPhase1Hook,
        RELATIVE_ADDR((UINT8 *)funcCall + 3, 5),
        OslFwpKernelSetupPhase1Original);
    */
    // Hook BlImgAllocateImageBuffer to allocate the mapper's buffer
    VOID *funcCall =
        FindPattern(imageBase, imageSize,
            "\xE8\x00\x00\x00\x00\x4C\x8B\x6D\x60", "x????xxxx");

    if (!funcCall) {
        Print(L"Failed to find BlImgAllocateImageBuffer\n");
        gBS->Stall(SEC_TO_MICRO(2));

        TrampolineUnHook((VOID *)OslFwpKernelSetupPhase1,
            OslFwpKernelSetupPhase1Original);

        return ImgArchStartBootApplication(appEntry, imageBase, imageSize,
            bootOption, returnArguments);
    }

    BlImgAllocateImageBuffer = (BL_IMG_ALLOCATE_IMAGE_BUFFER)TrampolineHook(
        (VOID *)BlImgAllocateImageBufferHook, RELATIVE_ADDR(funcCall, 5),
        BlImgAllocateImageBufferOriginal);

    // Hook ExitBootServices
    ExitBootServicesOriginal = gBS->ExitBootServices;
    gBS->ExitBootServices = ExitBootServicesHook;

    return ImgArchStartBootApplication(appEntry, imageBase, imageSize,
        bootOption, returnArguments);
}




// Called by winload to allocate image buffers in winload context, use it to
// allocate the mapper's buffer as well Hooking this instead of calling it
// within another hook alleviates some tedious setup (credits to sa413x)
EFI_STATUS EFIAPI BlImgAllocateImageBufferHook(VOID **imageBuffer,
    UINTN imageSize,
    UINT32 memoryType,
    UINT32 attributes, VOID *unused,
    UINT32 flags) {

    TrampolineUnHook((VOID *)BlImgAllocateImageBuffer,
        BlImgAllocateImageBufferOriginal);

    EFI_STATUS status = BlImgAllocateImageBuffer(
        imageBuffer, imageSize, memoryType, attributes, unused, flags);

    if (!EFI_ERROR(status) && memoryType == BL_MEMORY_TYPE_APPLICATION) {

        
        mapper.AllocatedBufferStatus = BlImgAllocateImageBuffer(
            &mapper.AllocatedBuffer, 0x10000, memoryType,
            BL_MEMORY_ATTRIBUTE_RWX, unused, 0);

        if (EFI_ERROR(mapper.AllocatedBufferStatus)) {
            mapper.AllocatedBuffer = NULL;
        }
        

    

        // Don't hook the function again
        return status;
    }

    TrampolineHook((VOID *)BlImgAllocateImageBufferHook,
        (VOID *)BlImgAllocateImageBuffer,
        BlImgAllocateImageBufferOriginal);

    return status;
}

// Called by winload with a valid LPB in winload context before calling
// ExitBootServices
EFI_STATUS EFIAPI
OslFwpKernelSetupPhase1Hook(LOADER_PARAMETER_BLOCK *loaderParameterBlock) {
    TrampolineUnHook((VOID *)OslFwpKernelSetupPhase1,
        OslFwpKernelSetupPhase1Original);

 

    return OslFwpKernelSetupPhase1(loaderParameterBlock);
}


inline void PressAnyKey()
{
        EFI_STATUS         Status;
        EFI_EVENT          WaitList;
        EFI_INPUT_KEY      Key;
        UINTN              Index;
        Print(L"Press F11 key to continue . . .");
        do {
                WaitList = gST->ConIn->WaitForKey;
                Status = gBS->WaitForEvent(1, &WaitList, &Index);
                gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
                if (Key.ScanCode == SCAN_F11)
                        break;
        } while (1);
        gST->ConOut->ClearScreen(gST->ConOut);
        gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
}

typedef void(__stdcall* BlpArchSwitchContext_t)(int target);
BlpArchSwitchContext_t BlpArchSwitchContext;

enum WinloadContext
{
        ApplicationContext,
        FirmwareContext
};

UINT64 ResolveRelativeAddress(
        UINT64 Instruction,
        UINT32 OffsetOffset,
        UINT32 InstructionSize
)
{

        UINT64 Instr = (UINT64)Instruction;
        UINT32 RipOffset = *(UINT32*)(Instr + OffsetOffset);
        UINT64 ResolvedAddr = (UINT64)(Instr + InstructionSize + RipOffset);

        return ResolvedAddr;
}
#pragma warning (disable : 4244)




// Called by winload to unload boot services
EFI_STATUS EFIAPI ExitBootServicesHook(EFI_HANDLE imageHandle, UINTN mapKey)
{
        
        

        // https://github.com/SamuelTulach/rainbow
        UINT64 returnAddress = (UINT64)_ReturnAddress();
        while (*(unsigned short*)returnAddress != IMAGE_DOS_SIGNATURE)
                returnAddress = returnAddress - 1;



        /*
         * Idea for the project is to implement own KiSystemStartup,
         * because hooking original ntoskrnl KiSystemStartup causes PG bluescreen.
         * Own KiSystemStartup allows to make own modifications to kernel, before it's completely started up.
         * 
         * Windows 10 1809 LTSC currently supported only, because this project is still "under development" / POC
         *
         */


        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)returnAddress;
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((char*)dos + dos->e_lfanew);
        UINT32 imageSize = nt->OptionalHeader.SizeOfImage;
        unsigned char bytes_0[] = { 'x','x','x','x','x','x','x','x','x',0 };
        BlpArchSwitchContext = (BlpArchSwitchContext_t)(FindPattern((VOID*)(returnAddress), imageSize, "\x40\x53\x48\x83\xEC\x20\x48\x8B\x15", bytes_0));
        UINT64 OslEntryPoint = (UINT64)FindPattern((VOID*)returnAddress, imageSize, "\x48\x8B\x0E\x48\x89\x05\x00\x00\x00\x00", "xxxxxx????");

        OslEntryPoint = ResolveRelativeAddress(OslEntryPoint + 3, 3, 7);



        int total_rip = 0;

        

        

        // 1809 
        unsigned char bytes_1809[] = { 'x','x','x','?','?','?','?','x','x','x',0 };
        UINT64 loaderBlockScan = (UINT64)FindPattern((unsigned char*)returnAddress, imageSize, "\x48\x8B\x3D\x00\x00\x00\x00\x48\x8B\xCF", bytes_1809);
        UINT64 resolvedAddress = *(UINT64*)((loaderBlockScan + 7) + *(int*)(loaderBlockScan + 3));
        BlpArchSwitchContext(ApplicationContext);
        LOADER_PARAMETER_BLOCK* loaderBlock = (LOADER_PARAMETER_BLOCK*)(resolvedAddress);





        

        KLDR_DATA_TABLE_ENTRY* ntoskrnl = GetModuleEntry(&loaderBlock->LoadOrderListHead, L"ntoskrnl.exe");
        // KLDR_DATA_TABLE_ENTRY* hal = GetModuleEntry(&loaderBlock->LoadOrderListHead, L"hal.dll");

        UINT64 DbgPrint = GetExport(ntoskrnl->ImageBase, "DbgPrint");
        (DbgPrint);

        ntoskrnl_base = (UINT64)ntoskrnl->ImageBase;
        UINT64 ntoskrnl_entry = (UINT64)ntoskrnl->EntryPoint;
        UINT64 runtimeaddy = ntoskrnl_entry;



        int function_length = 0;
        {
                unsigned char* temporary_counter = (char*)ntoskrnl_entry;
                while (1) {


                        if (temporary_counter[0] == 0xC3 && temporary_counter[1] == 0xCC)
                                break;

                        temporary_counter++;

                }
                function_length = (int)((char*)temporary_counter - (char*)ntoskrnl_entry);

                function_length = function_length + 1;
        }


        VOID *ret_address = mapper.AllocatedBuffer;

        for (UINT64 i = function_length; i--;)
                ((unsigned char*)ret_address)[i] = ((unsigned char*)ntoskrnl_entry)[i];




        unsigned char resolveBase[1000];
        for (UINT64 i = function_length; i--;)
                ((unsigned char*)resolveBase)[i] = ((unsigned char*)ntoskrnl_entry)[i];



        char* asm_payload = (unsigned char*)ret_address;
        void *new_base = (void*)ret_address;

        UINT64 KiIdleLoop = 0;
        for (int i = 0; i < function_length; i++) {
                int current_offset = i;

                // call normal / negative
                if (CheckMask(&resolveBase[i], "\xE8\x00\x00\x00\x00", "x???x") || CheckMask(&resolveBase[i], "\xE8\x00\x00\x00\xFF", "x???x")) {
                        int inst_length = 5;
                        unsigned long long offset = (unsigned long long)&asm_payload[i];
                        signed int dst = *(signed int*)(offset + 1);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length;
                        *(signed int*)((UINT64)new_base + current_offset + 1) = new_destination;
                        KiIdleLoop = original_destination;
                        total_rip++;
                }

                // xor reg, relative
                if (CheckMask(&resolveBase[i], "\x48\x33\x00\x00\x00\x00\xFF", "xx????x")) {
                        int inst_length = 7;
                        unsigned long long offset = (unsigned long long) &asm_payload[i];
                        signed int dst = *(signed int*)(offset + 3);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length;
                        *(signed int*)((UINT64)new_base + current_offset + 3) = new_destination;
                        total_rip++;
                }
                
                // mov DWORD reg, relative
                if (CheckMask(&resolveBase[i], "\x8b\x0d\x00\xae\xfd\xff", "xx?xxx")) {
                        int inst_length = 6;
                        unsigned long long offset = (unsigned long long) & asm_payload[i];
                        signed int dst = *(signed int*)(offset + 2);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length;
                        *(signed int*)((UINT64)new_base + current_offset + 2) = new_destination;
                        total_rip++;
                }

                // mov reg, relative
                if (CheckMask(&resolveBase[i], "\x48\x8B\x00\x00\x00\x00\xFF", "xx????x")) {
                        int inst_length = 7;
                        unsigned long long offset = (unsigned long long) &asm_payload[i];
                        signed int dst = *(signed int*)(offset + 3);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length;
                        *(signed int*)((UINT64)new_base + current_offset + 3) = new_destination;
                        total_rip++;
                }

                // mov relative, reg
                if (CheckMask(&resolveBase[i], "\x48\x89\x00\x00\x00\x00\xFF", "xx????x")) {
                        int inst_length = 7;
                        unsigned long long offset = (unsigned long long) &asm_payload[i];
                        signed int dst = *(signed int*)(offset + 3);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length;
                        *(signed int*)((UINT64)new_base + current_offset + 3) = new_destination;
                        total_rip++;
                }

                // lea reg, relative
                if (CheckMask(&resolveBase[i], "\x48\x8D\x00\x00\x00\x00\xFF", "xx????x")) {
                        int inst_length = 7;
                        unsigned long long offset = (unsigned long long) &asm_payload[i];
                        signed int dst = *(signed int*)(offset + 3);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length;
                        *(signed int*)((UINT64)new_base + current_offset + 3) = new_destination;
                        total_rip++;
                }

                // cmp relative DWORD PTR, val
                if (CheckMask(&resolveBase[i], "\x83\x3D\x00\x00\x00\x00\x00", "xx????x")) {
                        int inst_length = 7;
                        unsigned long long offset = (unsigned long long) &asm_payload[i];
                        signed int dst = *(signed int*)(offset + 2);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length;
                        *(signed int*)((UINT64)new_base + current_offset + 2) = new_destination;
                        total_rip++;
                }

                // test relative BYTE PTR, val
                if (CheckMask(&resolveBase[i], "\xF6\x05\x00\x00\x00\xFF\x00", "xx???x?")) {
                        int inst_length = 7;
                        unsigned long long offset = (unsigned long long) &asm_payload[i];
                        signed int dst = *(signed int*)(offset + 2);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length;
                        *(signed int*)((UINT64)new_base + current_offset + 2) = new_destination;
                        total_rip++;
                }

        }





        
        
        asm_payload = asm_payload + (function_length + /*12*/50); // 12, size of JMP
        new_base    = (void*)asm_payload;
        runtimeaddy = KiIdleLoop;

        function_length = 0;
        int function_cutpos = 0;
        {
                unsigned char* temporary_counter = (char*)runtimeaddy;
                while (1) {
                        if (temporary_counter[0] == 0x74 && temporary_counter[1] == 0x02)
                                function_cutpos = (int)((char*)temporary_counter - (char*)runtimeaddy);     

                        if (temporary_counter[0] == 0xC3 && temporary_counter[1] == 0xCC)
                                break;

                        temporary_counter++;

                }
                function_length = (int)((char*)temporary_counter - (char*)runtimeaddy);

                function_length = function_length + 1;
        }




        UINT64 null_sub = (UINT64)asm_payload + (function_length + 12);


        if (DbgPrint)
        {
                unsigned char null_sub_func[] = { 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x14, 0x25, 0x88, 0x01,
                        0x00, 0x00, 0x4C, 0x8B, 0x82, 0x40, 0x06, 0x00, 0x00, 0x48, 0xB8, 0x00, 0xB0, 0x60, 0x4B,
                        0x07, 0xF8, 0xFF, 0xFF, 0x48, 0xB9, 0x00, 0xB0, 0x60, 0x4B, 0x07, 0xF8, 0xFF, 0xFF, 0xFF,
                        0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3 };
                *(UINT64*)(null_sub_func + 0x14 + 2) = DbgPrint;
                *(UINT64*)(null_sub_func + 0x1E + 2) = null_sub + 200;

                char hello_world[] = "[+] System Idle Process (Thread: 0x%llx, ID: %lld)\n";
                MemCopy((void*)(null_sub + 200), hello_world, sizeof(hello_world));
                MemCopy((void*)null_sub, null_sub_func, sizeof(null_sub_func));
                
        } else
                ((unsigned char*)null_sub)[0] = 0xC3; // ret







        unsigned char extra_call[] = { 0x48, 0xB8, 0x00, 0x00, 0xA0, 0x35, 0x00, 0xF8, 0xFF, 0xFF, 0xFF, 0xD0 };
        *(UINT64*)(extra_call + 2) = null_sub;


        unsigned char modifiedIdleLoop[1000];
        
        {
                for (UINT64 i = function_cutpos; i--;)
                        ((unsigned char*)modifiedIdleLoop)[i] = ((unsigned char*)KiIdleLoop)[i];


                for (UINT64 i = sizeof(extra_call); i--;)
                        ((unsigned char*)modifiedIdleLoop + function_cutpos)[i] = ((unsigned char*)extra_call)[i];


                for (UINT64 i = function_length - (function_cutpos); i--;)
                        ((unsigned char*)modifiedIdleLoop + function_cutpos + 12)[i] = ((unsigned char*)KiIdleLoop + function_cutpos)[i];
        }


        for (UINT64 i = function_length + 12; i--;)
                ((unsigned char*)asm_payload)[i] = ((unsigned char*)modifiedIdleLoop)[i];
        


        
        for (int i = 0; i < function_length + 12; i++) {

                int current_offset = i;

                int extra_length = 0;
                if (i > function_cutpos)
                        extra_length = 12;

                // call normal
                if (CheckMask(&modifiedIdleLoop[i], "\xE8\x00\x00\x00\x00", "x???x") || CheckMask(&modifiedIdleLoop[i], "\xE8\x00\x00\x00\xFF", "x???x")) {
                        int inst_length = 5;
                        unsigned long long offset = (unsigned long long) & asm_payload[i];
                        signed int dst = *(signed int*)(offset + 1);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length - extra_length;
                        *(signed int*)((UINT64)new_base + current_offset + 1) = new_destination;
                }

                // cmp byte relative, value
                if (CheckMask(&modifiedIdleLoop[i], "\x80\x3D", "xx")) {
                        int inst_length = 7;
                        unsigned long long offset = (unsigned long long) & asm_payload[i];
                        signed int dst = *(signed int*)(offset + 2);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length - extra_length;
                        *(signed int*)((UINT64)new_base + current_offset + 2) = new_destination;
                }

                // test dword relative, reg
                if (CheckMask(&modifiedIdleLoop[i], "\x85\x35", "xx")) {
                        int inst_length = 6;
                        unsigned long long offset = (unsigned long long) & asm_payload[i];
                        signed int dst = *(signed int*)(offset + 2);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length - extra_length;
                        *(signed int*)((UINT64)new_base + current_offset + 2) = new_destination;
                }

                // test dword relative, value
                if (CheckMask(&modifiedIdleLoop[i], "\xF7\x05", "xx")) {
                        int inst_length = 10;
                        unsigned long long offset = (unsigned long long) & asm_payload[i];
                        signed int dst = *(signed int*)(offset + 2);
                        UINT64 original_destination = (runtimeaddy + current_offset) + dst + inst_length;
                        signed int new_destination = original_destination - (UINT64)new_base - current_offset - inst_length - extra_length;
                        *(signed int*)((UINT64)new_base + current_offset + 2) = new_destination;
                }


                // JMP
                {
                        if (CheckMask(&modifiedIdleLoop[i], "\xE9\x00\x00\xFF\xFF", "x??xx")) {

                                unsigned long long offset = (unsigned long long) & asm_payload[i];
                                signed int dst = *(signed int*)(offset + 1);
                                *(signed int*)((UINT64)new_base + current_offset + 1) = dst - extra_length;
                                total_rip++;
                        }
                }

                // JE
                {
                        if (CheckMask(&modifiedIdleLoop[i], "\x0F\x84", "xx")) {

                                unsigned long long offset = (unsigned long long) & asm_payload[i];
                                signed int dst = *(signed int*)(offset + 2);
                                if (dst < 0)
                                        *(signed int*)((UINT64)new_base + current_offset + 2) = dst - extra_length;
                                total_rip++;
                        }
                        if (CheckMask(&modifiedIdleLoop[i], "\x74", "x")) {

                                unsigned long long offset = (unsigned long long) & asm_payload[i];
                                signed char dst = *(signed char*)(offset + 1);
                                if (dst < 0)
                                        *(signed char*)((UINT64)new_base + current_offset + 1) = dst - extra_length;
                                total_rip++;
                        }
                }

                // JNE
                {
                        if (CheckMask(&modifiedIdleLoop[i], "\x75", "x")) {
                        }
                }

                // JB
                {

                        if (CheckMask(&modifiedIdleLoop[i], "\x72", "x")) {
                        }
                }



        }


        for (UINT64 i = function_length + 12; i--;)
                ((unsigned char*)modifiedIdleLoop)[i] = ((unsigned char*)asm_payload)[i];


        

        UINT64 target_address = (UINT64)ret_address;
        target_address += 0x284;



        unsigned char KiSystemStartupPayload[] = { 0x48, 0xB8, 0x00, 0xA0, 0x81, 0x44, 0x04, 0xF8, 0xFF, 0xFF, 0xFF, 0xD0 };
        *(UINT64*)(KiSystemStartupPayload + 2) = (UINT64)asm_payload;
        for (int i = 0; i < sizeof(KiSystemStartupPayload); i++)
                ((unsigned char*)target_address)[i] = KiSystemStartupPayload[i];


        BlpArchSwitchContext(FirmwareContext);


        // Replace OslEntryPoint with our modified system entry point
        *(UINT64*)OslEntryPoint = (UINT64)ret_address;
        Print(L"OslEntryPoint: %llx\n", *(UINT64*)OslEntryPoint);
        // Print(L"OslEntryPoint: %llx\n", OslEntryPoint - returnAddress);

        PressAnyKey();

        gBS->ExitBootServices = ExitBootServicesOriginal;
        return gBS->ExitBootServices(imageHandle, mapKey);
}

// Locates the device path for the Windows bootmgr
EFI_DEVICE_PATH *EFIAPI GetWindowsBootmgrDevicePath() {
    UINTN handleCount;
    EFI_HANDLE *handles;
    EFI_DEVICE_PATH *devicePath = NULL;

    // Retrieve filesystem handles
    EFI_STATUS status =
        gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid,
            NULL, &handleCount, &handles);

    if (EFI_ERROR(status)) {
        Print(L"Failed to get filesystem handles: %r\n", status);
        return devicePath;
    }

    // Check each FS for the bootmgr
    for (UINTN i = 0; i < handleCount && !devicePath; ++i) {
        EFI_FILE_IO_INTERFACE *fileSystem;
        status = gBS->OpenProtocol(
            handles[i], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&fileSystem,
            gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);

        if (EFI_ERROR(status)) {
            continue;
        }

        EFI_FILE_HANDLE volume;
        status = fileSystem->OpenVolume(fileSystem, &volume);
        if (!EFI_ERROR(status)) {
            EFI_FILE_HANDLE file;
            status = volume->Open(volume, &file, WINDOWS_BOOTMGR_PATH,
                EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

            if (!EFI_ERROR(status)) {
                volume->Close(file);

                devicePath = FileDevicePath(handles[i], WINDOWS_BOOTMGR_PATH);
            }
        }

        gBS->CloseProtocol(handles[i], &gEfiSimpleFileSystemProtocolGuid,
            gImageHandle, NULL);
    }

    gBS->FreePool(handles);
    return devicePath;
}

// Sets BootCurrent to Windows bootmgr option
EFI_STATUS EFIAPI SetBootCurrentToWindowsBootmgr() {
    // Query boot order array
    UINTN bootOrderSize = 0;
    EFI_STATUS status =
        gRT->GetVariable(EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid,
            NULL, &bootOrderSize, NULL);

    if (status != EFI_BUFFER_TOO_SMALL) {
        return status;
    }

    UINT16 *bootOrder = AllocatePool(bootOrderSize);
    if (!bootOrder) {
        return EFI_OUT_OF_RESOURCES;
    }

    status =
        gRT->GetVariable(EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid,
            NULL, &bootOrderSize, bootOrder);

    if (EFI_ERROR(status)) {
        FreePool(bootOrder);
        return status;
    }

    // Try each boot option to find Windows boot manager
    BOOLEAN found = FALSE;
    for (UINTN i = 0; i < bootOrderSize / sizeof(bootOrder[0]) && !found; ++i) {
        CHAR16 variableName[0xFF];
        UnicodeSPrint(variableName, sizeof(variableName), L"Boot%04x",
            bootOrder[i]);

        UINTN bufferSize = 0;
        status = gRT->GetVariable(variableName, &gEfiGlobalVariableGuid, NULL,
            &bufferSize, NULL);

        if (status != EFI_BUFFER_TOO_SMALL) {
            break;
        }

        UINT8 *buffer = AllocatePool(bufferSize);
        if (!buffer) {
            status = EFI_OUT_OF_RESOURCES;
            break;
        }

        status = gRT->GetVariable(variableName, &gEfiGlobalVariableGuid, NULL,
            &bufferSize, buffer);

        if (EFI_ERROR(status)) {
            FreePool(buffer);
            break;
        }

        // Check the option file path list
        EFI_LOAD_OPTION *bootOption = (EFI_LOAD_OPTION *)buffer;
        CHAR16 *bootOptionDescription =
            (CHAR16 *)(buffer + sizeof(EFI_LOAD_OPTION));

        EFI_DEVICE_PATH_PROTOCOL *bootOptionPaths =
            (EFI_DEVICE_PATH_PROTOCOL *)(bootOptionDescription +
                StrLen(bootOptionDescription) + 1);

        if (bootOption->FilePathListLength) {
            // Only the first path is needed
            CHAR16 *bootOptionPath =
                ConvertDevicePathToText(&bootOptionPaths[0], FALSE, TRUE);

            if (bootOptionPath) {
                // Convert it to lowercase
                for (CHAR16 *c = bootOptionPath; *c; ++c) {
                    if (*c >= 'A' && *c <= 'Z') {
                        *c += ('a' - 'A');
                    }
                }

                // Check if it contains the bootmgr path
                if (StrStr(bootOptionPath, WINDOWS_BOOTMGR_PATH)) {
                    // If so, update BootCurrent to this option
                    status = gRT->SetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
                        &gEfiGlobalVariableGuid,
                        EFI_VARIABLE_BOOTSERVICE_ACCESS |
                        EFI_VARIABLE_RUNTIME_ACCESS,
                        sizeof(UINT16), &bootOrder[i]);

                    if (!EFI_ERROR(status)) {
                        found = TRUE;
                    }
                }

                FreePool(bootOptionPath);
            }
        }

        FreePool(buffer);
    }

    FreePool(bootOrder);

    if (!EFI_ERROR(status) && !found) {
        status = EFI_NOT_FOUND;
    }

    return status;
}

EFI_STATUS EFIAPI UefiUnload(EFI_HANDLE imageHandle) { return EFI_SUCCESS; }

