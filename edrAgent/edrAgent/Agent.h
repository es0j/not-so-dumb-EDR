#pragma once

#define PIPE_NAME L"\\\\.\\pipe\\dumbedr-analyzer"

#define MESSAGE_SIZE 2048

void Scan(const wchar_t* fname);