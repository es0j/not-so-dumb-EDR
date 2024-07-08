#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "Driver.h"



int inject_dll(int pid) {

    wchar_t response[MESSAGE_SIZE] = { 0 };
    wchar_t pid_to_inject[MESSAGE_SIZE] = { 0 };
    swprintf_s(pid_to_inject, MESSAGE_SIZE, L"%d\0", pid);

    NTSTATUS status = ReadWritePipe(L"\\??\\pipe\\dumbedr-analyzer", pid_to_inject, response);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector unreachable. Allowing.\n");
        return 0;
    }
    if (wcscmp(response, L"OK\0") == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector: OK\n", response);
        return 0;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector: KO\n", response);
        return 1;
    }
}

/*
This function is sending the path as well as the name of the binary being launched
to the DumbEDRAnalyzer agent running in userland
*/
int analyze_binary(wchar_t* binary_file_path)
{
    wchar_t response[MESSAGE_SIZE] = { 0 };

    NTSTATUS status = ReadWritePipe(L"\\??\\pipe\\dumbedr-analyzer", binary_file_path, response);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            StaticAnalyzer unreachable. Allowing.\n");
        return 0;
    }
    if (wcscmp(response, L"OK\0") == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            StaticAnalyzer: OK\n", response);
        return 0;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            StaticAnalyzer: KO\n", response);
        return 1;
    }


}