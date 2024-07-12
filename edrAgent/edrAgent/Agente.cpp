#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <comdef.h>
#include <filesystem>

#include "Agent.h"


#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")


BOOL allowExecution(wchar_t *target_binary_file) {
    printf("\n\n[EDR AGENT] Received binary file %ws \n", target_binary_file);
    int res = 0;

    BOOL isSeDebugPrivilegeStringPresent = lookForSeDebugPrivilegeString(target_binary_file);
    BOOL isDangerousFunctionsFound = ListImportedFunctions(target_binary_file);
    BOOL isSigned = VerifyEmbeddedSignature(target_binary_file);
    BOOL isMalware = DefenderScan(target_binary_file);

    if (isSigned == TRUE) {
        printf("StaticAnalyzer allows (signed)\n");
        return TRUE;
    }
    if (isDangerousFunctionsFound || isSeDebugPrivilegeStringPresent || isMalware) {
        printf("StaticAnalyzer denies\n");
        return FALSE;
    }
    printf("Exec allowed (default)\n");
    return TRUE;


}

void kernelMode() {

    LPCWSTR pipeName = PIPE_NAME;
    DWORD bytesRead = 0;
    wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };

    printf("Launching analyzer named pipe server\n");

    // Creates a named pipe
    HANDLE hServerPipe = CreateNamedPipe(
        pipeName,                 // Pipe name to create
        PIPE_ACCESS_DUPLEX,       // Whether the pipe is supposed to receive or send data (can be both)
        PIPE_TYPE_MESSAGE,        // Pipe mode (whether or not the pipe is waiting for data)
        PIPE_UNLIMITED_INSTANCES, // Maximum number of instances from 1 to PIPE_UNLIMITED_INSTANCES
        MESSAGE_SIZE,             // Number of bytes for output buffer
        MESSAGE_SIZE,             // Number of bytes for input buffer
        0,                        // Pipe timeout 
        NULL                      // Security attributes (anonymous connection or may be needs credentials. )
    );

    while (TRUE) {

        // ConnectNamedPipe enables a named pipe server to start listening for incoming connections
        BOOL isPipeConnected = ConnectNamedPipe(
            hServerPipe, // Handle to the named pipe
            NULL         // Whether or not the pipe supports overlapped operations
        );

        wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };
        if (isPipeConnected) {
            // Read from the named pipe
            ReadFile(
                hServerPipe,         // Handle to the named pipe
                &target_binary_file, // Target buffer where to stock the output
                MESSAGE_SIZE,        // Size of the buffer
                &bytesRead,          // Number of bytes read from ReadFile
                NULL                 // Whether or not the pipe supports overlapped operations
            );

            BOOL allow = allowExecution(target_binary_file);

            wchar_t response[MESSAGE_SIZE] = { 0 };
            if (allow == TRUE) {
                swprintf_s(response, MESSAGE_SIZE, L"OK\0");
            }
            else {
                swprintf_s(response, MESSAGE_SIZE, L"KO\0");
            }

            DWORD bytesWritten = 0;
            // Write to the named pipe
            WriteFile(
                hServerPipe,   // Handle to the named pipe
                response,      // Buffer to write from
                MESSAGE_SIZE,  // Size of the buffer 
                &bytesWritten, // Numbers of bytes written
                NULL           // Whether or not the pipe supports overlapped operations
            );
        }

        // Disconnect
        DisconnectNamedPipe(
            hServerPipe // Handle to the named pipe
        );

        printf("\n\n");
    }
}

const wchar_t* GetWC(const char* c)
{
    const size_t cSize = strlen(c) + 1;
    wchar_t* wc = new wchar_t[cSize];

    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, wc, cSize, c, _TRUNCATE);


    return wc;
}

int main(int argc,char **argv) {
    if (argc < 2) {
        printf("Starting agent in kernel\n");
        kernelMode();
    }
    else {
        
        
        

        TCHAR fullFilename[MAX_PATH];

        GetFullPathName(GetWC(argv[1]), MAX_PATH, fullFilename, nullptr);
        allowExecution(fullFilename);
        
    }


    
    return 0;
}