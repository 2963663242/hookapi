#include "hook.hpp"
#define DLLNAME "kernel32.dll"
#define WRITEFILE "WriteFile"
hook hk;
FARPROC g_writefile = GetProcAddress(GetModuleHandleA(DLLNAME), WRITEFILE);


typedef BOOL(WINAPI* PFWriteFile)(
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    );
BOOL WINAPI  MyWriteFile(
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped) {
    PBYTE ptr = (PBYTE)g_writefile;
    //unhook_by_code(g_writefile, g_pOrgBytes);
    BOOL ret = TRUE;
    char* pc = (char*)lpBuffer;
    while (*pc)
    {
        if (*pc >= 'a' && *pc <= 'z') {
            *pc -= 0x20;
        }
        pc++;
    }
    ret = ((PFWriteFile)(ptr + 6))(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);//原入口偏移+6处是修正的原jmp指令
    //hook_by_code(g_writefile, (PROC)MyWriteFile, g_pOrgBytes);
    return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hk.hook_by_code(g_writefile, (PROC)MyWriteFile);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        hk.unhook_by_code();
        break;
    }
    return TRUE;
}
