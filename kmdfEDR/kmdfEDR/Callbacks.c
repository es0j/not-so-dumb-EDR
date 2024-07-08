#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "Driver.h"

void CreateProcessNotifyRoutine(PEPROCESS parent_process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
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
                        createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                        return;
                    }
                }
                else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: Denied by StaticAnalyzer\n");
                    createInfo->CreationStatus = STATUS_ACCESS_DENIED;
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

void RemoveCallbacks() {
	// Unset the callback
	PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateProcessNotifyRoutine, TRUE);
}

void InstallCallbacks() {

    NTSTATUS ret = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);

    if (ret == STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Driver launched successfully\n");
    }
    else if (ret == STATUS_INVALID_PARAMETER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Invalid parameter\n");
    }
    else if (ret == STATUS_ACCESS_DENIED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Access denied\n");
    }


}