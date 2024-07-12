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

BOOL VerifyEmbeddedSignature(const wchar_t* binaryPath) {
    LONG lStatus;
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = binaryPath;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initializing necessary structures
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID and Wintrust_Data.
    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    BOOL isSigned;
    switch (lStatus) {
        // The file is signed and the signature was verified
    case ERROR_SUCCESS:
        isSigned = TRUE;
        break;

        // File is signed but the signature is not verified or is not trusted
    case TRUST_E_SUBJECT_FORM_UNKNOWN || TRUST_E_PROVIDER_UNKNOWN || TRUST_E_EXPLICIT_DISTRUST || CRYPT_E_SECURITY_SETTINGS || TRUST_E_SUBJECT_NOT_TRUSTED:
        isSigned = TRUE;
        break;

        // The file is not signed
    case TRUST_E_NOSIGNATURE:
        isSigned = FALSE;
        break;

        // Shouldn't happen but hey may be!
    default:
        isSigned = FALSE;
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    printf("VerifyEmbeddedSignature %ls isSigned? %i\n", binaryPath, isSigned);
    return isSigned;
}

static const char* InsecureFunctions[] = {
    "OpenProcess",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    NULL
};

static BOOL IsInsecureFunction(IMAGE_IMPORT_BY_NAME* importByName){
    for (const char** funName = InsecureFunctions; *funName != NULL; funName++) {
        if (strcmp(importByName->Name, *funName) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static int GetDLLInsecureFunCount(const char* moduleName, HMODULE hModule, IMAGE_IMPORT_DESCRIPTOR* importDesc) {
    int InsecureFunctionCount = 0;

    // Loop over the functions of the DLL
    IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->OriginalFirstThunk);
    while (thunk->u1.AddressOfData != 0) {
        if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
            // printf("\tOrdinal: %llu\n", IMAGE_ORDINAL(thunk->u1.Ordinal));
        }
        else {
            IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hModule + thunk->u1.AddressOfData);
            // printf("\tFunction: %s\n", importByName->Name);
            // Checks if the following functions are used by the binary
            InsecureFunctionCount += IsInsecureFunction(importByName);
            printf("Imported: %s\n", importByName->Name);
        }
        thunk++;
    }
    printf("Module: %s \t-%i Insecure function\n", moduleName, InsecureFunctionCount);
    return InsecureFunctionCount;
}

BOOL ListImportedFunctions(const wchar_t* binaryPath) {
    int InsecureFunctionCount = 0;
    BOOL classification = FALSE;
    IMAGE_NT_HEADERS* ntHeaders;
    IMAGE_IMPORT_DESCRIPTOR* importDesc;

    // Load the target binary so that we can parse its content
    HMODULE hModule = LoadLibraryEx(binaryPath, NULL, DONT_RESOLVE_DLL_REFERENCES );
    if (hModule == NULL) {
        DWORD error = ::GetLastError();
        std::string message = std::system_category().message(error);
        printf("Unable to get hModule %s\n", message.c_str());
        goto end2;
    }

    // Get NT headers from the binary
    ntHeaders = ImageNtHeader(hModule);
    if (ntHeaders == NULL) {
        DWORD error = ::GetLastError();
        std::string message = std::system_category().message(error);
        printf("Unable to get ntHeaders %s\n", message.c_str());
        goto end1;
    }
    // Locate the IAT
    importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Loop over the DLL's
    while (importDesc->Name != 0) {
        const char* moduleName = (const char*)((BYTE*)hModule + importDesc->Name);

        InsecureFunctionCount+=GetDLLInsecureFunCount(moduleName, hModule, importDesc);
        importDesc++;
    }
    
    if (InsecureFunctionCount >3) {
        classification = TRUE;
    }

end1:

    FreeLibrary(hModule);

end2:
    printf("binary: %i Insecure function count: Deny? %i\n", InsecureFunctionCount, classification);
    return classification;
}



BOOL lookForSeDebugPrivilegeString(const wchar_t* filename) {
    FILE* file;
    BOOL result = FALSE;
    _wfopen_s(&file, filename, L"rb");
    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);
        char* buffer = (char*)malloc(file_size);
        if (buffer != NULL) {
            if (fread(buffer, 1, file_size, file) == file_size) {
                const char* search_string = "SeDebugPrivilege";
                size_t search_length = strlen(search_string);
                int i, j;
                int found = 0;
                for (i = 0; i <= file_size - search_length; i++) {
                    for (j = 0; j < search_length; j++) {
                        if (buffer[i + j] != search_string[j]) {
                            break;
                        }
                    }
                    if (j == search_length) {
                        result = TRUE;
                        break;
                    }
                }
            }
            free(buffer);
        }
        fclose(file);
    }
    printf("lookForSeDebugPrivilegeString %ls isDebugPrivilege? %i\n", filename, result);

    return result;
}
