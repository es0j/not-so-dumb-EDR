#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

//https://github.com/sensepost/mydumbedr/tree/main
// 
// Needs to be set on the project properties as well
#pragma comment(lib, "FltMgr.lib")

#include "Driver.h"

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\MyDumbEDR"); // Internal driver device name, cannot be used userland
UNICODE_STRING SYM_LINK = RTL_CONSTANT_STRING(L"\\??\\MyDumbEDR");        // Symlink used to reach the driver, can be used userland



void UnloadMyDumbEDR(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrint("[NotSoDumbEDR] Unloading routine called\n");
    

    RemoveCallbacks();

    //RemoveObCallbacks();

    // Delete the driver device 
    IoDeleteDevice(DriverObject->DeviceObject);
    // Delete the symbolic link
    IoDeleteSymbolicLink(&SYM_LINK);
    LogWrite("Unloaded driver");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    // Prevent compiler error such as unreferenced parameter (error 4)
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[NotSoDumbEDR] Initializing the EDR's driver v0.02\n");

    // Variable that will store the output of WinAPI functions
    NTSTATUS status;

    // Setting the unload routine to execute
    DriverObject->DriverUnload = UnloadMyDumbEDR;

    // Initializing a device object and creating it
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING deviceName = DEVICE_NAME;
    UNICODE_STRING symlinkName = SYM_LINK;
    status = IoCreateDevice(
        DriverObject,		   // our driver object,
        0,					   // no need for extra bytes,
        &deviceName,           // the device name,
        FILE_DEVICE_UNKNOWN,   // device type,
        0,					   // characteristics flags,
        FALSE,				   // not exclusive,
        &DeviceObject		   // the resulting pointer
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[NotSoDumbEDR] Device creation failed\n");
        return status;
    }

    // Creating the symlink that we will use to contact our driver
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[NotSoDumbEDR] Symlink creation failed\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }

    InstallCallbacks();
    //InstallObCallbacks();
    LogWrite("Installed driver");

    return 0;
}