#pragma once

void InstallCallbacks();

void RemoveCallbacks();


int analyze_binary(wchar_t* binary_file_path);


int inject_dll(int pid);

NTSTATUS ReadWritePipe(PCWSTR pipeString, PVOID sendBuf, PVOID recvBuf);

NTSTATUS LogWrite(char* logMessage);

// Maximum size of the buffers used to communicate via Named Pipes
#define MESSAGE_SIZE 2048