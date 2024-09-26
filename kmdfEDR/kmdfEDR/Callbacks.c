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

        POBJECT_NAME_INFORMATION objFileDosDeviceName;
        IoQueryFileDosDeviceName(createInfo->FileObject, &objFileDosDeviceName);


        // Compare the image base of the launched process to the dump_lasss string
        if (strstr(createInfo->ImageFileName->Buffer, L"evil") != NULL) {

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] [NotifyRoutineEx] Process %wZ created\n", processName);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d\n", pid);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            Created by: %wZ\n", parent_processName);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ImageBase: %ws\n", createInfo->ImageFileName->Buffer);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            DOS path: %ws\n", objFileDosDeviceName->Name.Buffer);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            CommandLine: %ws\n", createInfo->CommandLine->Buffer);

            
            if (createInfo->FileOpenNameAvailable && createInfo->ImageFileName) {
                int analyzer_ret = analyze_binary(objFileDosDeviceName->Name.Buffer);
                if (analyzer_ret != 0) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: Denied by StaticAnalyzer\n");
                    createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    return;
                }
                int injector_ret = inject_dll((int)(intptr_t)pid);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: return injector '%d'\n", injector_ret);

                
            }
            createInfo->CreationStatus = STATUS_SUCCESS;
        }
    }
    // Logical bug here, if the agent is not running, the driver will always allow the creation of the process
    else {
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ killed\n", processName);
    }
}

void sLoadImageNotifyRoutine(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo)
{
    UNREFERENCED_PARAMETER(imageInfo);
    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;
    PsLookupProcessByProcessId(pid, &process);
    SeLocateProcessImageName(process, &processName);

    DbgPrint("[NotSoDumbEDR] [LoadImageNotify] %wZ (%d) loaded %wZ", processName, pid, imageName);
}



void sCreateThreadNotifyRoutine(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    if (create)
    {
        DbgPrint("[NotSoDumbEDR] [CreateThreadNotify] %d created thread %d", pid, tid);
        PETHREAD pThread;
        NTSTATUS status = PsLookupThreadByThreadId(tid, &pThread);
        if (NT_SUCCESS(status)) {
            // Assume we have the ETHREAD structure and its StartAddress field.
            //GetThreadEntryPointAndDumpMemory(tid);

            //DbgPrint("Thread entry point: %p\n", startAddress);
            //DumpMemory(startAddress, 256);
            // Dereference the thread object
            ObDereferenceObject(pThread);
        }
        else {
            DbgPrint("[NotSoDumbEDR] Failed to lookup thread: %d\n", status);
        }

    }
    else
    {
        DbgPrint("[NotSoDumbEDR] Thread %d of process %d exited", tid, pid);
    }
}



void RemoveCallbacks() {
	// Unset the callback
    PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, TRUE);
    //PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, TRUE);

    //PsRemoveLoadImageNotifyRoutine(sLoadImageNotifyRoutine);
    //PsRemoveCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);

}

void CheckStatus(NTSTATUS s) {
    if (s == STATUS_SUCCESS) {
        DbgPrint("[NotSoDumbEDR] Driver launched successfully\n");
    }
    else if (s == STATUS_INVALID_PARAMETER) {
        DbgPrint("[NotSoDumbEDR] Invalid parameter\n");
    }
    else if (s == STATUS_ACCESS_DENIED) {
        DbgPrint("[NotSoDumbEDR] Access denied\n");
    }
    else {
        DbgPrint("[NotSoDumbEDR] Access denied\n");
    }
}


void InstallCallbacks() {
        
    CheckStatus(PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, FALSE));
    //CheckStatus(PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, FALSE));

    //CheckStatus(PsSetLoadImageNotifyRoutine(sLoadImageNotifyRoutine));
    //CheckStatus(PsSetCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine));
    
}