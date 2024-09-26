#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "Driver.h"



NTSTATUS ReadWritePipe(PCWSTR pipeString, PVOID sendBuf, PVOID recvBuf) {



    UNICODE_STRING pipeName; // String containing the name of the named
    // Initialize a UNICODE_STRING structure containing the name of the named pipe
    RtlInitUnicodeString(
        &pipeName,                      // Variable in which we will store the UNICODE_STRING structure
        pipeString  // Wide string containing the name of the named pipe
    );

    HANDLE hPipe;                     // Handle that we will use to communicate with the named pipe
    OBJECT_ATTRIBUTES fattrs = { 0 }; // Objects Attributes used to store information when calling ZwCreateFile
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Initialize an OBJECT_ATTRIBUTE structure pointing to our named pipe
    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);

    // Reads from the named pipe
    NTSTATUS status = ZwCreateFile(
        &hPipe,                                         // Handle to the named pipe
        FILE_WRITE_DATA | FILE_READ_DATA | SYNCHRONIZE, // File attribute (we need both read and write)
        &fattrs,                                        // Structure containing the file attribute
        &io_stat_block,                                 // Structure containing the I/O queue
        NULL,                                           // Allocation size, not needed in that case
        0,                                              // Specific files attributes (not needed as well
        FILE_SHARE_READ | FILE_SHARE_WRITE,             // File sharing access
        FILE_OPEN,                                      // Specify the action we want to do on the file 
        FILE_NON_DIRECTORY_FILE,                        // Specifying that the file is not a directory
        NULL,                                           // Always NULL
        0                                               // Always zero
    );

    // If we can obtain a handle on the named pipe then 
    if (!NT_SUCCESS(status)) {
        DbgPrint("[NotSoDumbEDR] Unable to create: KO\n");
        return status;
    }

    // Now we'll send the binary path to the userland agent
    status = ZwWriteFile(
        hPipe,            // Handle to the named pipe
        NULL,             // Optionally a handle on an even object
        NULL,             // Always NULL
        NULL,             // Always NULL
        &io_stat_block,   // Structure containing the I/O queue
        sendBuf, // Buffer in which is stored the binary path
        MESSAGE_SIZE,     // Maximum size of the buffer
        NULL,             // Bytes offset (optional)
        NULL              // Always NULL
    );

    DbgPrint("[NotSoDumbEDR]        ZwWriteFile: 0x%0.8x\n", status);

    /*
    This function is needed when you are running read/write files operation so that the kernel driver
    makes sure that the reading/writing phase is done and you can keep running the code
    */

    status = ZwWaitForSingleObject(
        hPipe, // Handle the named pipe
        FALSE, // Whether or not we want the wait to be alertable
        NULL   // An optional timeout
    );

    DbgPrint("[NotSoDumbEDR]        ZwWaitForSingleObject: 0x%0.8x\n", status);


    if (recvBuf == NULL) {
        goto clean;
    }

    // Reading the respons from the named pipe (ie: if the binary is malicious or not based on static analysis)
    status = ZwReadFile(
        hPipe,          // Handle to the named pipe
        NULL,           // Optionally a handle on an even object
        NULL,           // Always NULL
        NULL,           // Always NULL
        &io_stat_block, // Structure containing the I/O queue
        &recvBuf,      // Buffer in which to store the answer
        MESSAGE_SIZE,   // Maximum size of the buffer
        NULL,           // Bytes offset (optional)
        NULL            // Always NULL
    );

    DbgPrint("[NotSoDumbEDR]        ZwReadFile: 0x%0.8x\n", status);

    // Waiting again for the operation to be completed
    status = ZwWaitForSingleObject(
        hPipe,
        FALSE,
        NULL
    );

    DbgPrint("[NotSoDumbEDR]         ZwWaitForSingleObject: 0x%0.8x\n", status);

    clean:
    // Used to close a connection to the named pipe
    ZwClose(
        hPipe // Handle to the named pipe
    );
    
    return status;
}

NTSTATUS LogWrite2(char* logMessage, PCWSTR pipeString) {
    
    ULONG bufferSize = (ULONG)strlen(logMessage);

    UNICODE_STRING filePath; // String containing the name of the named
    // Initialize a UNICODE_STRING structure containing the name of the named pipe
    RtlInitUnicodeString(
        &filePath,                      // Variable in which we will store the UNICODE_STRING structure
        pipeString  // Wide string containing the name of the named pipe
    );

    HANDLE              hFile;
    OBJECT_ATTRIBUTES   ObjectAttributes;
    IO_STATUS_BLOCK     IoStatusBlock;

    InitializeObjectAttributes(&ObjectAttributes, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS Status = ZwCreateFile(&hFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &ObjectAttributes,
        &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[NotSoDumbEDR] Creating file error");
        return Status;
    }

    Status = ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, (PVOID)logMessage, bufferSize, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[NotSoDumbEDR] Writing file error");
        return Status;
    }

    ZwClose(hFile);
    return Status;
}

NTSTATUS LogWrite(char * logMessage) {
    return LogWrite2(logMessage,L"\\??\\C:\\edr_log.txt");
}