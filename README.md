# dll_load — remote DLL injection test tool

A minimal, self-contained Windows C test harness that proves a DLL can be
loaded into **another** process. Three pieces:

| Component | Source | Output | Purpose |
|---|---|---|---|
| Payload | `payload/payload.c` | `build/payload.dll` | The injectable DLL. On `DLL_PROCESS_ATTACH` it writes a marker file to `C:\data`. |
| Injector | `injector/injector.c` | `build/injector.exe` | Performs the remote `LoadLibraryA` injection. |
| Target | `target/target.c` | `build/target.exe` | A harmless process to inject into while testing. |
| Hardened target | `target_hardened/target_hardened.c` | `build/target_hardened.exe` | Same, but enables DLL-load mitigations so injection is blocked. |

## Build

Requires Visual Studio 2022 with the *Desktop development with C++* workload.
`build.bat` finds VS2022 itself via `vswhere` and calls `vcvars64.bat`, so you
can run it from a plain `cmd` prompt:

```bat
build.bat
```

Or compile by hand from a *x64 Native Tools Command Prompt*:

```bat
cl /nologo /LD /O2 /W4 /Fe:payload.dll  payload\payload.c
cl /nologo /O2 /W4 /Fe:target.exe        target\target.c
cl /nologo /O2 /W4 /Fe:target_hardened.exe target_hardened\target_hardened.c
cl /nologo /O2 /W4 /Fe:injector.exe      injector\injector.c
```

## Run

Automated smoke test (builds, starts the target, injects, prints the marker
file, kills the target):

```bat
run_test.bat
```

Manual run:

```bat
build\target.exe
rem note the pid it prints, then in another window:
build\injector.exe <pid> C:\Data\defender-2026-autumn\dll_load\build\payload.dll
type C:\data\dll_load_<pid>.txt
```

## How the injection works

`injector.exe` performs the classic `LoadLibrary` technique:

1. `OpenProcess` — request `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
   PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`.
2. `VirtualAllocEx` — reserve `PAGE_READWRITE` memory in the target for the
   DLL path string.
3. `WriteProcessMemory` — copy the absolute DLL path (including the NUL) in.
4. `GetModuleHandleA("kernel32.dll")` + `GetProcAddress(..., "LoadLibraryA")` —
   resolve the loader entry point. `kernel32` is loaded at the same base in
   every process of the same bitness, so this address is valid in the target.
5. `CreateRemoteThread` — start a thread in the target whose entry point is
   `LoadLibraryA` and whose argument is the remote path buffer.
6. `WaitForSingleObject` + `GetExitCodeThread` — the thread's exit code is the
   `HMODULE` returned by `LoadLibraryA`; `0` means the load failed.
7. `VirtualFreeEx(MEM_RELEASE)` — free the remote buffer, then close handles.

The payload's `DllMain` runs under the loader lock, so it deliberately does
nothing but a short file write.

## Blocking the injection (DLL-load mitigations)

`target_hardened.exe` turns on process mitigations that stop an unsigned DLL
from being loaded, then we re-run the same injector against it:

```bat
run_test_hardened.bat
```

Two mitigations matter for DLL loading, both applied at runtime with
`SetProcessMitigationPolicy`:

| Policy | Field | Effect |
|---|---|---|
| `ProcessSignaturePolicy` | `MicrosoftSignedOnly` | Only Microsoft-signed images may load. Blocks our unsigned `payload.dll`. |
| `ProcessImageLoadPolicy` | `NoRemoteImages` | Refuses images loaded from a UNC / network path. |

The target reads the flags back with `GetProcessMitigationPolicy` to prove they
took effect, and can also self-test with `--try-load`:

```bat
build\target_hardened.exe --signature --try-load build\payload.dll
```

Observed result — the load is refused with **error 577**
(`ERROR_INVALID_IMAGE_HASH`, "Windows cannot verify the digital signature for
this file"):

```
[+] MicrosoftSignedOnly enabled
[*] current mitigation state:
      MicrosoftSignedOnly : 1
      NoRemoteImages      : 0
[*] attempting LoadLibraryA("build\payload.dll") ...
[+] LoadLibraryA was BLOCKED
[-] LoadLibraryA failed (error 577): Windows cannot verify the digital signature ...
```

And via the injector, `LoadLibraryA` returns `NULL` inside the target, so the
injector exits non-zero and **no marker file is written**:

```
[+] CreateRemoteThread ok
[-] LoadLibraryA returned NULL inside the target (DLL failed to load)
[*] injector exit code = 1   (non-zero = blocked, as expected)
[+] no marker file - the DLL was NOT loaded. mitigation works.
```

Note the mitigation is enforced by the *loader inside the target*, not by the
injector — the remote thread is created and runs fine, it is `LoadLibraryA`
itself that refuses the image. A signed DLL would still load.

## Notes / gotchas

- **Bitness must match.** A 64-bit injector cannot inject a 32-bit DLL into a
  64-bit process. `build.bat` builds everything x64.
- **`SeDebugPrivilege`.** The injector tries to enable it and warns if it
  can't. Injecting into a process owned by *another* user (or a protected
  process) requires running the injector **as Administrator**; injecting into
  your own process does not.
- **Absolute path required.** `LoadLibraryA` resolves relative paths against
  the *target's* working directory, so the injector normalises the path with
  `GetFullPathNameA` first.
- **`C:\data` must be writable** by the target process for the marker file to
  appear. The payload creates the directory if missing.
- This is a test tool for your own processes. Injecting into processes you do
  not own or control is not something to do.
