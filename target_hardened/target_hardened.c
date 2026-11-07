/*
 * target_hardened.c -- a target process that turns on DLL-load mitigations,
 *                      so we can prove an unsigned DLL can no longer be
 *                      loaded into it.
 *
 * Two mitigations are relevant to DLL loading:
 *
 *   ProcessSignaturePolicy / MicrosoftSignedOnly
 *       Only images signed by Microsoft may be loaded.  This is the one that
 *       blocks our unsigned payload.dll.
 *
 *   ProcessImageLoadPolicy / NoRemoteImages
 *       Refuses to load images from a remote (UNC / network) path.
 *
 * Both are applied at runtime with SetProcessMitigationPolicy() and then read
 * back with GetProcessMitigationPolicy() to confirm they really took effect.
 *
 * Build (x64, VS2022):
 *     cl /nologo /O2 /W4 /Fe:target_hardened.exe target_hardened.c
 *
 * Usage:
 *     target_hardened.exe [--signature] [--remote] [--all]
 *                         [--try-load <path\to\payload.dll>]
 *
 *     --signature   enable MicrosoftSignedOnly   (default)
 *     --remote      enable NoRemoteImages
 *     --all         enable both
 *     --try-load    after hardening, attempt LoadLibraryA on <path> and
 *                   report the result (handy for a self-contained demo)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */

static void PrintLastError(const char *what)
{
    DWORD err = GetLastError();
    char  msg[512] = { 0 };

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   msg, (DWORD)sizeof(msg), NULL);

    while (msg[0] != '\0') {
        size_t n = strlen(msg);
        if (n == 0)
            break;
        if (msg[n - 1] == '\r' || msg[n - 1] == '\n')
            msg[n - 1] = '\0';
        else
            break;
    }

    fprintf(stderr, "[-] %s failed (error %lu): %s\n",
            what, (unsigned long)err, msg);
}

/* ------------------------------------------------------------------ */
/* mitigation helpers                                                  */
/* ------------------------------------------------------------------ */

static BOOL EnableSignaturePolicy(void)
{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY p;

    ZeroMemory(&p, sizeof(p));
    p.MicrosoftSignedOnly = 1;

    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &p, sizeof(p))) {
        PrintLastError("SetProcessMitigationPolicy(ProcessSignaturePolicy)");
        return FALSE;
    }
    printf("[+] MicrosoftSignedOnly enabled\n");
    return TRUE;
}

static BOOL EnableNoRemoteImages(void)
{
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY p;

    ZeroMemory(&p, sizeof(p));
    p.NoRemoteImages = 1;

    if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &p, sizeof(p))) {
        PrintLastError("SetProcessMitigationPolicy(ProcessImageLoadPolicy)");
        return FALSE;
    }
    printf("[+] NoRemoteImages enabled\n");
    return TRUE;
}

static void ShowMitigationState(void)
{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig;
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY        img;

    ZeroMemory(&sig, sizeof(sig));
    ZeroMemory(&img, sizeof(img));

    printf("[*] current mitigation state:\n");

    if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy,
                                   &sig, sizeof(sig)))
        printf("      MicrosoftSignedOnly : %u\n", sig.MicrosoftSignedOnly);
    else
        printf("      MicrosoftSignedOnly : <query failed>\n");

    if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessImageLoadPolicy,
                                   &img, sizeof(img)))
        printf("      NoRemoteImages      : %u\n", img.NoRemoteImages);
    else
        printf("      NoRemoteImages      : <query failed>\n");
}

/* ------------------------------------------------------------------ */

static void TryLoad(const char *path)
{
    HMODULE h;

    printf("[*] attempting LoadLibraryA(\"%s\") ...\n", path);

    h = LoadLibraryA(path);
    if (h == NULL) {
        printf("[+] LoadLibraryA was BLOCKED\n");
        PrintLastError("LoadLibraryA");
    } else {
        printf("[!] LoadLibraryA SUCCEEDED (module @ 0x%p) - mitigation "
               "did not block it\n", (void *)h);
    }
}

static void Usage(const char *exe)
{
    fprintf(stderr,
            "usage: %s [--signature] [--remote] [--all] [--try-load <dll>]\n",
            exe);
}

int main(int argc, char **argv)
{
    BOOL wantSignature = FALSE;
    BOOL wantRemote    = FALSE;
    const char *tryLoad = NULL;
    int  i;

    for (i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--signature") == 0) {
            wantSignature = TRUE;
        } else if (_stricmp(argv[i], "--remote") == 0) {
            wantRemote = TRUE;
        } else if (_stricmp(argv[i], "--all") == 0) {
            wantSignature = TRUE;
            wantRemote    = TRUE;
        } else if (_stricmp(argv[i], "--try-load") == 0 && i + 1 < argc) {
            tryLoad = argv[++i];
        } else {
            Usage(argv[0]);
            return 2;
        }
    }

    /* default: the mitigation that actually blocks an unsigned DLL */
    if (!wantSignature && !wantRemote)
        wantSignature = TRUE;

    printf("target_hardened.exe running, pid = %lu\n",
           (unsigned long)GetCurrentProcessId());

    if (wantSignature && !EnableSignaturePolicy())
        return 1;
    if (wantRemote && !EnableNoRemoteImages())
        return 1;

    ShowMitigationState();

    if (tryLoad != NULL)
        TryLoad(tryLoad);

    printf("[*] waiting for injection attempts - press Ctrl+C to exit\n");
    fflush(stdout);

    for (;;)
        Sleep(1000);
}
