/*
 * target.c -- a harmless process to inject into while testing.
 *
 * It prints its own pid and then just sits there until you kill it.
 *
 * Build (x64, VS2022):
 *     cl /nologo /O2 /W4 /Fe:target.exe target.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main(void)
{
    printf("target.exe running, pid = %lu\n",
           (unsigned long)GetCurrentProcessId());
    printf("press Ctrl+C to exit\n");
    fflush(stdout);

    for (;;)
        Sleep(1000);
}
