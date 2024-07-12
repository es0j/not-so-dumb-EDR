#pragma once

#define PIPE_NAME L"\\\\.\\pipe\\dumbedr-analyzer"

#define MESSAGE_SIZE 2048

BOOL DefenderScan(const wchar_t* fname);

BOOL VerifyEmbeddedSignature(const wchar_t* binaryPath);

BOOL ListImportedFunctions(const wchar_t* binaryPath);


BOOL lookForSeDebugPrivilegeString(const wchar_t* filename);


