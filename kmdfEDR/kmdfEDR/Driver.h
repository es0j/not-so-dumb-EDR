#pragma once

void InstallCallbacks();

void RemoveCallbacks();


int analyze_binary(wchar_t* binary_file_path);


int inject_dll(int pid);

NTSTATUS ReadWritePipe(PCWSTR pipeString, PVOID sendBuf, PVOID recvBuf);

NTSTATUS LogWrite(char* logMessage);


void InstallObCallbacks();
void RemoveObCallbacks();

NTSTATUS GetProcessImageFileName(PEPROCESS Process, PUNICODE_STRING ImageFileName);

// Maximum size of the buffers used to communicate via Named Pipes
#define MESSAGE_SIZE 2048










typedef struct _TD_CALLBACK_PARAMETERS {
    ACCESS_MASK AccessBitsToClear;
    ACCESS_MASK AccessBitsToSet;
}
TD_CALLBACK_PARAMETERS, * PTD_CALLBACK_PARAMETERS;



typedef struct _TD_CALLBACK_REGISTRATION {

    //
    // Handle returned by ObRegisterCallbacks.
    //

    PVOID RegistrationHandle;

    //
    // If not NULL, filter only requests to open/duplicate handles to this
    // process (or one of its threads).
    //

    PVOID TargetProcess;
    HANDLE TargetProcessId;


    //
    // Currently each TD_CALLBACK_REGISTRATION has at most one process and one
    // thread callback. That is, we can't register more than one callback for
    // the same object type with a single ObRegisterCallbacks call.
    //

    TD_CALLBACK_PARAMETERS ProcessParams;
    TD_CALLBACK_PARAMETERS ThreadParams;

    ULONG RegistrationId;        // Index in the global TdCallbacks array.

}
TD_CALLBACK_REGISTRATION, * PTD_CALLBACK_REGISTRATION;