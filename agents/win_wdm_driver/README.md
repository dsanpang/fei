# LayeredGuard — Windows WDM driver (layered protection framework)

Windows kernel endpoint of the Fei platform: a pure WDM driver (no
KMDF/UMDF) built with VS2010 + WDK 7600.16385.1 for Windows 7 SP1
through Windows 11, x86 and x64. Seven cooperating submodules:

| Module | Capability |
|--------|------------|
| RegConfig | 5-second registry polling; hot rule updates (no restart) |
| PidSpoof | matched processes report PID 4 (System) |
| NetHide | nsiproxy IRP hook filters the TCP table — x64 native, x86 native and WoW64 all filter |
| PathHide | MiniFilter: hidden files/directory trees blocked on CREATE and removed from enumeration |
| RegHide | CmRegisterCallback: hidden keys return NOT_FOUND, subkey tree included, enumeration filtered |
| WriteBack | .sys image cached at load, rewritten on shutdown/hibernate |
| DriverObjectSpoof | DRIVER_OBJECT + LDR entry clone of \Driver\Null |

## Build

Open `LayeredGuard.sln` in VS2010 with WDK 7600.16385.1 installed at
`C:\WinDDK\7600.16385.1\` (adjust `WDKDir` in the .vcxproj otherwise).
Build Win32/x64; the PostBuild step signs with the test certificate.

First-time signing setup (admin):

```
tools\CreateTestCert.cmd
bcdedit /set testsigning on   & reboot
```

## Deploy

Run `Install.bat` from an elevated prompt (creates the `filesys` service,
Instances keys and a sample Config rule set, then starts it). Rule
updates: edit `HKLM\SYSTEM\CurrentControlSet\Services\LayeredGuard\Config`
values (`Process` / `IP` / `Port` / `Path` / `RegPath`, semicolon
separated) — effective within 5 seconds, no driver restart. Changing the
`Process` value restores previously spoofed PIDs before re-spoofing;
other value changes never touch spoofed PIDs.

## Hardening implemented relative to the reference design (§0.1)

- x86 native and WoW64 share the 0x3C NSI completion routine; Win32
  builds filter the TCP table too (no x64-only pass-through)
- `OutstandingIrp` increments only after a completion routine is on the
  IRP; every completion exit path (including SEH) decrements; cleanup
  restores DeviceControl first, then drains up to 3 s
- directory filter publishes `IoStatus.Information` after compaction
- path and registry matching hide the whole sub-tree (`hidden + '\'`), not
  just the exact key/file
- Instances key and Config path derive from DriverEntry's RegistryPath —
  no hard-coded service names anywhere
- every same-named process in the snapshot is spoofed, not just the first
- PID spoof restore only on Process-value change (including first run)
- the 18-char HKLM prefix compare consumes a following backslash
- IRP_MJ_SHUTDOWN pointer saved before install and restored on cleanup
  (NULL if there was none); the dispatch never chains to a predecessor
- submodule headers include only `ntifs.h`
- PostDirCtrl checks `FLTFL_POST_OPERATION_DRAINING` at entry, before
  `FltDoCompletionProcessingWhenSafe`
- `.` / `..` skipped by content **and** length together


## C2 integration (automatic)

The Fei userland agent merges its own identity into the Config rules
at startup (and after every sandbox respawn) through sandbox command
0x08:

- **Process**: the agent image name + `sandbox.exe` - task manager and process enumerators see PID 4 (System)
- **IP**: the gateway address - `netstat` no longer
  shows the C2 link (x64 native, x86 native and WoW64)
- **Path**: the agent's own directory - the whole tree disappears
  from `dir` and cannot be opened

Existing rules are preserved (semicolon-merged, deduplicated). When
the driver is not deployed the registry write is skipped entirely -
no `LayeredGuard` key is ever created on a
driver-less host. The console can also push rules remotely with
`SendCommand protect [image, dir, ip]` (see
`tools/cmdprobe -protect`).

Deployment order: driver first (`Install.bat`), then the agent.

## Acceptance checklist

See the checklist in the implementation spec (`azure-wdm-agent-prompt.md`
§15): sc create/start with an arbitrary service name, PID spoofing with
5-second restore on Process shrink, netstat filtering on x64 **and** x86,
directory-tree hiding, regedit subkey hiding, hot rule reload, write-back
after shutdown, clean `sc stop` unload, `!drvobj` showing the spoofed
name in release builds.

## Disclaimer

> This project is a learning artifact of Windows kernel-driver
> programming within an authorized red-team research platform. It is
> limited to testing in virtual machines / authorized lab environments
> and MUST NOT be used for illegal purposes.
