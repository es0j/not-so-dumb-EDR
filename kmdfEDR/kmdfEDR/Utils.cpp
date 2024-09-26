#include <ntddk.h>
#include <wdf.h>

/*
typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );

QUERY_INFO_PROCESS ZwQueryInformationProcess;


NTSTATUS GetProcessImageFileName(PEPROCESS Process, PUNICODE_STRING ImageFileName) {
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    ULONG returnLength = 0;

    // Query for the process image file name
    status = ZwQueryInformationProcess(NtCurrentProcess(),
        ProcessImageFileName,
        NULL,
        0,
        &returnLength);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    bufferSize = returnLength;
    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryInformationProcess(NtCurrentProcess(),
        ProcessImageFileName,
        buffer,
        bufferSize,
        &returnLength);

    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(ImageFileName, (PCWSTR)buffer);
    }
    else {
        ExFreePool(buffer);
    }

    return status;
}
*/