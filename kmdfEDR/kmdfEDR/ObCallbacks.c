#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>
#include "ntddk.h"

#include "Driver.h"

//https://github.com/microsoft/Windows-driver-samples/blob/main/general/obcallback/driver/callback.c#L260

NTSTATUS InspectProcessMemory(HANDLE Pid, PVOID Address, PVOID Buffer, SIZE_T Size) {
    UNREFERENCED_PARAMETER(Pid);
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}

void ExampleInspectMemory(HANDLE Pid, PVOID VirtualAddress, SIZE_T Size) {
    // Allocate buffer to hold the copied memory
    PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, 'memT');
    if (Buffer == NULL) {
        DbgPrint("Failed to allocate buffer\n");
        return;
    }

    // Inspect the memory
    NTSTATUS Status = InspectProcessMemory(Pid, VirtualAddress, Buffer, Size);
    if (NT_SUCCESS(Status)) {
        // Do something with the memory, for example, print the first few bytes
        DbgPrint("Memory contents: %.*s\n", (int)Size, (char*)Buffer);
    } else {
        DbgPrint("Failed to inspect memory: 0x%X\n", Status);
    }

    // Free the buffer
    ExFreePoolWithTag(Buffer, 'memT');
}


PVOID pCBRegistrationHandle = NULL;

OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
OB_OPERATION_REGISTRATION CBOperationRegistrations[2] = { { 0 }, { 0 } };
UNICODE_STRING CBAltitude = { 0 };
TD_CALLBACK_REGISTRATION CBCallbackRegistration = { 0 };

PVOID GetThreadEntryPoint(PETHREAD Thread) {
    // The following is a simplified example. The actual structure and field names can vary.
    // You might need to use a kernel debugger to find the correct offsets for your Windows version.

    // Assuming the thread's start address is stored at an offset from the ETHREAD structure
    // Note: This offset can change between different versions of Windows.
    PVOID StartAddress = NULL;// PsGetThreadStartAddress(Thread);

    return StartAddress;
}

OB_PREOP_CALLBACK_STATUS
CBTdPreOperationCallback(    _In_ PVOID RegistrationContext,    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo) {

    UNREFERENCED_PARAMETER(RegistrationContext);

    //PUNICODE_STRING pname = NULL;
    if (PreInfo->ObjectType == *PsProcessType) {

        //GetProcessImageFileName(PreInfo->ObjectType, pname);
       DbgPrint("[NotSoDumbEDR] [Obcallback process] Object: \n");

    }
    else if (PreInfo->ObjectType == *PsThreadType) {
        DbgPrint("[NotSoDumbEDR] [Obcallback thread] Thread name: %p\n", PreInfo->Object);

        PETHREAD thread = (PETHREAD)PreInfo->Object;
        // Inspect the thread's memory here
        //CLIENT_ID ThreadClientId = Thread->Cid;
        HANDLE pid = PsGetThreadProcessId(thread);
        HANDLE tid = PsGetThreadId(thread);

        DbgPrint("Thread PID:%p TID: %p\n", pid, tid);
        //ExampleInspectMemory(pid, NULL, 0x20);
        PVOID entrypoint = GetThreadEntryPoint(thread);
        DbgPrint("Thread entrypoint: TID: %p\n", entrypoint);




    }
    else {
        DbgPrint("[NotSoDumbEDR] ObCallbackTest: CBTdPreOperationCallback: unexpected object type\n");
        goto Exit;
    }


Exit:

    return OB_PREOP_SUCCESS;

}


VOID
CBTdPostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION PostInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(PostInfo);
    //PTD_CALLBACK_REGISTRATION CallbackRegistration = (PTD_CALLBACK_REGISTRATION)RegistrationContext;



}

NTSTATUS TdProtectNameCallback()
{
    NTSTATUS Status = STATUS_SUCCESS;

    // Setup the Ob Registration calls

    CBOperationRegistrations[0].ObjectType = PsProcessType;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    CBOperationRegistrations[0].PreOperation = CBTdPreOperationCallback;
    CBOperationRegistrations[0].PostOperation = CBTdPostOperationCallback;

    CBOperationRegistrations[1].ObjectType = PsThreadType;
    CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
    CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    CBOperationRegistrations[1].PreOperation = CBTdPreOperationCallback;
    CBOperationRegistrations[1].PostOperation = CBTdPostOperationCallback;


    RtlInitUnicodeString(&CBAltitude, L"1000");

    CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    CBObRegistration.OperationRegistrationCount = 2;
    CBObRegistration.Altitude = CBAltitude;
    CBObRegistration.RegistrationContext = &CBCallbackRegistration;
    CBObRegistration.OperationRegistration = CBOperationRegistrations;


    Status = ObRegisterCallbacks(
        &CBObRegistration,
        &pCBRegistrationHandle       // save the registration handle to remove callbacks later
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[NotSoDumbEDR] ObCallbackTest: installing OB callbacks failed  status 0x%x\n", Status);
    }


    return Status;
}

void RemoveObCallbacks() {
    
    DbgPrint("[NotSoDumbEDR] Removing OB callback\n");
    ObUnRegisterCallbacks(pCBRegistrationHandle);
    
}




void InstallObCallbacks() {
    DbgPrint("[NotSoDumbEDR] Installing ob Callback\n");
    TdProtectNameCallback();
}