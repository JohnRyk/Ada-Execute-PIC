#include "addresshunter.h"
#include <stdio.h>
#include <inttypes.h>

// kernel32.dll exports
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE);
typedef HANDLE(WINAPI* GETCURRENTPROCESS)();
typedef BOOL(WINAPI* WRITEFILE)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FLUSHFILEBUFFERS)(HANDLE);
typedef int(WINAPI* WIDECHARTOMULTIBYTE)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

// advapi32.dll exports
typedef BOOL(WINAPI* OPENPROCESSTOKEN)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI* GETTOKENINFORMATION)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL(WINAPI* LOOKUPPRIVILEGENAMEW)(LPCWSTR,  PLUID, LPWSTR, LPDWORD);

// msvcrt.dll exports
typedef void*(WINAPI* CALLOC)(size_t num, size_t size);
typedef int(WINAPI* SPRINTF)(char* buf, const char* fmt, ...);

/*
 * hWrite: the write handle of anonymous pipe, pass it from CreateThread's lpParameter in runsc.c
 */
void getprivs(HANDLE hWrite) {
    //dlls to dynamically load during runtime
    UINT64 kernel32dll, msvcrtdll, advapi32dll;
    //symbols to dynamically resolve from dll during runtime
    UINT64 LoadLibraryAFunc, CloseHandleFunc,
        OpenProcessTokenFunc, GetCurrentProcessFunc, GetTokenInformationFunc, LookupPrivilegeNameWFunc,
        callocFunc, sprintfFunc, WriteFileFunc, FlushFileBuffersFunc, WideCharToMultiByteFunc;

    // kernel32.dll exports
    kernel32dll = GetKernel32();

    CHAR loadlibrarya_c[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);

    CHAR getcurrentprocess_c[] = {'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0};
    GetCurrentProcessFunc = GetSymbolAddress((HANDLE)kernel32dll, getcurrentprocess_c);

    CHAR closehandle_c[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0};
    CloseHandleFunc = GetSymbolAddress((HANDLE)kernel32dll, closehandle_c);

    CHAR writefile_c[] = {'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 0};
    WriteFileFunc = GetSymbolAddress((HANDLE)kernel32dll, writefile_c);

    CHAR flushfilebuffers_c[] = {'F', 'l', 'u', 's', 'h', 'F', 'i', 'l', 'e', 'B', 'u', 'f', 'f', 'e', 'r', 's', 0};
    FlushFileBuffersFunc = GetSymbolAddress((HANDLE)kernel32dll, flushfilebuffers_c);

    CHAR widechartomultibyte_c[] = {'W', 'i', 'd', 'e', 'C', 'h', 'a', 'r', 'T', 'o', 'M', 'u', 'l', 't', 'i', 'B', 'y', 't', 'e', 0};
    WideCharToMultiByteFunc = GetSymbolAddress((HANDLE)kernel32dll, widechartomultibyte_c);

    // advapi32.dll exports
    CHAR advapi32_c[] = {'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0};
    advapi32dll = (UINT64) ((LOADLIBRARYA)LoadLibraryAFunc)(advapi32_c);
    CHAR openprocesstoken_c[] = {'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 'T', 'o', 'k', 'e', 'n', 0};
    OpenProcessTokenFunc = GetSymbolAddress((HANDLE)advapi32dll, openprocesstoken_c);
    CHAR gettokeninformation_c[] = { 'G', 'e', 't', 'T', 'o', 'k', 'e', 'n', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 0 };
    GetTokenInformationFunc = GetSymbolAddress((HANDLE)advapi32dll, gettokeninformation_c);
    CHAR lookupprivilegenamew_c[] = {'L', 'o', 'o', 'k', 'u', 'p', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 'N', 'a', 'm', 'e', 'W', 0};
    LookupPrivilegeNameWFunc = GetSymbolAddress((HANDLE)advapi32dll, lookupprivilegenamew_c);

    // msvcrt.dll exports
    CHAR msvcrt_c[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0};
    msvcrtdll = (UINT64) ((LOADLIBRARYA)LoadLibraryAFunc)(msvcrt_c);
    CHAR calloc_c[] = {'c', 'a', 'l', 'l', 'o', 'c', 0};
    callocFunc = GetSymbolAddress((HANDLE)msvcrtdll, calloc_c);
    CHAR sprintf_c[] = {'s', 'p', 'r', 'i', 'n', 't', 'f', 0};
    sprintfFunc = GetSymbolAddress((HANDLE)msvcrtdll, sprintf_c);

    if (hWrite == NULL || hWrite == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD cbSize = sizeof(TOKEN_ELEVATION), tpSize, length;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION Elevation;
    PTOKEN_PRIVILEGES tPrivs = NULL;
    WCHAR name[256];
    char nameA[256];
    char line[512];
    DWORD wrote = 0;

    CHAR fmt_enabled[]  = {'[', '+', ']', ' ', '%', '-', '5', '0', 's', ' ', 'E', 'n', 'a', 'b', 'l', 'e', 'd', ' ', '(', 'D', 'e', 'f', 'a', 'u', 'l', 't', ')', '\n', 0};
    CHAR fmt_adjusted[] = {'[', '+', ']', ' ', '%', '-', '5', '0', 's', ' ', 'E', 'n', 'a', 'b', 'l', 'e', 'd', ' ', '(', 'A', 'd', 'j', 'u', 's', 't', 'e', 'd', ')', '\n', 0};
    CHAR fmt_disabled[] = {'[', '-', ']', ' ', '%', '-', '5', '0', 's', ' ', 'D', 'i', 's', 'a', 'b', 'l', 'e', 'd', '\n', 0};
    CHAR str_elevated[]  = {'[', '+', ']', ' ', 'E', 'l', 'e', 'v', 'a', 't', 'e', 'd', '\n', 0};
    CHAR str_restricted[] = {'[', '-', ']', ' ', 'R', 'e', 's', 't', 'r', 'i', 'c', 't', 'e', 'd', '\n', 0};

    if (((OPENPROCESSTOKEN)OpenProcessTokenFunc)(((GETCURRENTPROCESS)GetCurrentProcessFunc)(), TOKEN_QUERY, &hToken)) {
        ((GETTOKENINFORMATION)GetTokenInformationFunc)(hToken, TokenPrivileges, tPrivs, 0, &tpSize);
        tPrivs = (PTOKEN_PRIVILEGES)((CALLOC)callocFunc)(tpSize+1, sizeof(TOKEN_PRIVILEGES));

        if (tPrivs) {
            if (((GETTOKENINFORMATION)GetTokenInformationFunc)(hToken, TokenPrivileges, tPrivs, tpSize, &tpSize)) {
                for(int i=0; i<tPrivs->PrivilegeCount; i++){
                    length=256;
                    ((LOOKUPPRIVILEGENAMEW)LookupPrivilegeNameWFunc)(NULL, &tPrivs->Privileges[i].Luid, name, &length);

                    /* WCHAR → UTF-8，write result to nameA */
                    ((WIDECHARTOMULTIBYTE)WideCharToMultiByteFunc)(CP_UTF8, 0, name, -1, nameA, sizeof(nameA), NULL, NULL);

                    if (tPrivs->Privileges[i].Attributes == 3) {
                        ((SPRINTF)sprintfFunc)(line, fmt_enabled, nameA);
                    } else if (tPrivs->Privileges[i].Attributes == 2) {
                        ((SPRINTF)sprintfFunc)(line, fmt_adjusted, nameA);
                    } else if (tPrivs->Privileges[i].Attributes == 0) {
                        ((SPRINTF)sprintfFunc)(line, fmt_disabled, nameA);
                    } else {
                        continue;
                    }

                    /* Write this line to pipe */
                    DWORD lineLen = 0;
                    for(; line[lineLen]; lineLen++);   /* alternate strlen */
                    ((WRITEFILE)WriteFileFunc)(hWrite, line, lineLen, &wrote, NULL);
                }
            }
        }

        if (((GETTOKENINFORMATION)GetTokenInformationFunc)(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            if (Elevation.TokenIsElevated) {
                DWORD len = 0;
                for(; str_elevated[len]; len++);
                ((WRITEFILE)WriteFileFunc)(hWrite, str_elevated, len, &wrote, NULL);
            } else {
                DWORD len = 0;
                for(; str_restricted[len]; len++);
                ((WRITEFILE)WriteFileFunc)(hWrite, str_restricted, len, &wrote, NULL);
            }
        }
        ((CLOSEHANDLE)CloseHandleFunc)(hToken);
    }

    /* Flush and close write end, trigger the ReadFile in the read end to return ERROR_BROKEN_PIPE (The EOF single)
     * CloseHandle is EOF Single
     */
    ((FLUSHFILEBUFFERS)FlushFileBuffersFunc)(hWrite);
    ((CLOSEHANDLE)CloseHandleFunc)(hWrite);
}
