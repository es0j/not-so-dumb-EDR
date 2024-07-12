#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>
#include "ntddk.h"

#include "Driver.h"


NTSTATUS NTAPI MmCopyVirtualMemory
(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize

);

NTSTATUS ZwQueryInformationThread(
    _In_      HANDLE          ThreadHandle,
    _In_      THREADINFOCLASS ThreadInformationClass,
    _In_      PVOID           ThreadInformation,
    _In_      ULONG           ThreadInformationLength,
    _Out_opt_ PULONG          ReturnLength
);
void sCreateProcessNotifyRoutineEx(PEPROCESS parent_process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
    UNREFERENCED_PARAMETER(parent_process);

    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;

    PsLookupProcessByProcessId(pid, &process);
    SeLocateProcessImageName(process, &processName);

    // Never forget this if check because if you don't, you'll end up crashing your Windows system ;P
    if (createInfo != NULL) {
        createInfo->CreationStatus = STATUS_SUCCESS;

        // Retrieve parent process ID and process name
        PsLookupProcessByProcessId(createInfo->ParentProcessId, &parent_process);
        PUNICODE_STRING parent_processName = NULL;
        SeLocateProcessImageName(parent_process, &parent_processName);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ created\n", processName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d\n", pid);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            Created by: %wZ\n", parent_processName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ImageBase: %ws\n", createInfo->ImageFileName->Buffer);

        POBJECT_NAME_INFORMATION objFileDosDeviceName;
        IoQueryFileDosDeviceName(createInfo->FileObject, &objFileDosDeviceName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            DOS path: %ws\n", objFileDosDeviceName->Name.Buffer);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            CommandLine: %ws\n", createInfo->CommandLine->Buffer);

        // Compare the image base of the launched process to the dump_lasss string
        if (wcsstr(createInfo->ImageFileName->Buffer, L"ShellcodeInject.exe") != NULL) {

            // Checks if the notepad keyword is found in the CommandLine
            if (wcsstr(createInfo->CommandLine->Buffer, L"notepad.exe") != NULL) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: DENIED command line\n");
                createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }

            if (createInfo->FileOpenNameAvailable && createInfo->ImageFileName) {
                int analyzer_ret = analyze_binary(objFileDosDeviceName->Name.Buffer);
                if (analyzer_ret == 0) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: Sending to injector\n");
                    int injector_ret = inject_dll((int)(intptr_t)pid);
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: return injector '%d'\n", injector_ret);

                    if (injector_ret == 0) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: PROCESS ALLOWED\n");
                        createInfo->CreationStatus = STATUS_SUCCESS;
                        return;
                    }
                    else {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: PROCESS DENIED\n");
                        //createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                        return;
                    }
                }
                else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: Denied by StaticAnalyzer\n");
                    //createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    return;
                }
            }
        }
    }
    // Logical bug here, if the agent is not running, the driver will always allow the creation of the process
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ killed\n", processName);
    }
}

/*
// handle incoming notifications about new/terminated processes
void sCreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
    if (create)
    {
        PEPROCESS process = NULL;
        PUNICODE_STRING parentProcessName = NULL, processName = NULL;

        PsLookupProcessByProcessId(ppid, &process);
        SeLocateProcessImageName(process, &parentProcessName);

        PsLookupProcessByProcessId(pid, &process);
        SeLocateProcessImageName(process, &processName);

        DbgPrint("%d %wZ\n\t\t%d %wZ", ppid, parentProcessName, pid, processName);
    }
    else
    {
        DbgPrint("Process %d lost child %d", ppid, pid);
    }
}
*/

void sLoadImageNotifyRoutine(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo)
{
    UNREFERENCED_PARAMETER(imageInfo);
    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;
    PsLookupProcessByProcessId(pid, &process);
    SeLocateProcessImageName(process, &processName);

    DbgPrint("%wZ (%d) loaded %wZ", processName, pid, imageName);
}

// Function to dump memory at a specified address
void DumpMemory(PVOID Address, SIZE_T Size)
{
    CHAR buffer[256];
    SIZE_T bytesRead;

    if (Size > sizeof(buffer)) {
        Size = sizeof(buffer);
    }

    if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), Address, PsGetCurrentProcess(), buffer, Size, KernelMode, &bytesRead))) {
        for (SIZE_T i = 0; i < bytesRead; i++) {
            DbgPrint("%02X ", (UCHAR)buffer[i]);
            if ((i + 1) % 16 == 0) {
                DbgPrint("\n");
            }
        }
        DbgPrint("\n");
    }
    else {
        DbgPrint("Failed to read memory at address %p\n", Address);
    }
}

// Function to get thread entry point and dump its memory
void GetThreadEntryPointAndDumpMemory(HANDLE ThreadId)
{
    size_t  ThreadInformation=NULL;
    NTSTATUS status;
    size_t returnLen;

    // Get the start address from the ETHREAD structure
    status = ZwQueryInformationThread(ThreadId, ThreadQuerySetWin32StartAddress, &ThreadInformation,sizeof(size_t),&returnLen);
    if (NT_SUCCESS(status)) {
        DbgPrint("Thread entry point: %p\n", ThreadInformation);
    }
    else {
        DbgPrint("NtQueryInformationThread FAILED\n");
    }
        
    //DumpMemory(startAddress, 256);  // Dump 256 bytes of memory from the entry point

    

}

void sCreateThreadNotifyRoutine(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    if (create)
    {
        DbgPrint("%d created thread %d", pid, tid);
        PETHREAD pThread;
        NTSTATUS status = PsLookupThreadByThreadId(tid, &pThread);
        if (NT_SUCCESS(status)) {
            // Assume we have the ETHREAD structure and its StartAddress field.
            GetThreadEntryPointAndDumpMemory(tid);

            //DbgPrint("Thread entry point: %p\n", startAddress);
            //DumpMemory(startAddress, 256);
            // Dereference the thread object
            ObDereferenceObject(pThread);
        }
        else {
            DbgPrint("Failed to lookup thread: %d\n", status);
        }

    }
    else
    {
        DbgPrint("Thread %d of process %d exited", tid, pid);
    }
}



void RemoveCallbacks() {
	// Unset the callback
    PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, TRUE);
    //PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, TRUE);

    PsRemoveLoadImageNotifyRoutine(sLoadImageNotifyRoutine);
    PsRemoveCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);

}

void CheckStatus(NTSTATUS s) {
    if (s == STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Driver launched successfully\n");
    }
    else if (s == STATUS_INVALID_PARAMETER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Invalid parameter\n");
    }
    else if (s == STATUS_ACCESS_DENIED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Access denied\n");
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Access denied\n");
    }
}


void InstallCallbacks() {
        
    CheckStatus(PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, FALSE));
    //CheckStatus(PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, FALSE));

    CheckStatus(PsSetLoadImageNotifyRoutine(sLoadImageNotifyRoutine));
    CheckStatus(PsSetCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine));
    
}