#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#using <System.dll>



using namespace System;
using namespace System::Diagnostics;

void Exec(String^ fname) {

    // Create a new ProcessStartInfo object
    ProcessStartInfo^ startInfo = gcnew ProcessStartInfo();
    
    // Set the executable file name
    startInfo->FileName = L"C:\\Program Files\\Windows Defender\\MpCmdRun.exe";

    // Set arguments (in this case, we execute a simple command)
    startInfo->Arguments = L"-Scan -ScanType 3 -File " + fname +L" -DisableRemediation -Trace -Level 0x10";

    // Redirect standard output and error
    startInfo->RedirectStandardOutput = true;
    startInfo->RedirectStandardError = true;
    startInfo->UseShellExecute = false;
    startInfo->CreateNoWindow = true;

    // Create a new process
    Process^ process = gcnew Process();
    process->StartInfo = startInfo;

    // Start the process
    process->Start();
    process->WaitForExit(5000);

    // Read the output and error streams
    String^ output = process->StandardOutput->ReadToEnd();
    String^ error = process->StandardError->ReadToEnd();

    // Wait for the process to exit
    process->WaitForExit();

    // Print the output and error
    Console::WriteLine("Output:");
    Console::WriteLine(output);
    Console::WriteLine("Error:");
    Console::WriteLine(error);

    // Get the exit code (optional)
    int exitCode = process->ExitCode;
    Console::WriteLine("Process exited with code: {0}", exitCode);

}

void Scan(const wchar_t* fname) {

    String^ mfname = gcnew String(fname);
    Exec(mfname);
}
