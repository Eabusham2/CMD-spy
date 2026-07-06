# CMD-spy

[![build](https://github.com/Eabusham2/CMD-spy/actions/workflows/build.yml/badge.svg)](https://github.com/Eabusham2/CMD-spy/actions/workflows/build.yml)

**Catch every Command Prompt window — even the ones that flash for a millisecond — and log everything about them.**

Some programs (installers, scripts, scheduled tasks, and occasionally malware)
spawn a `cmd.exe` window that appears and disappears too fast to read. CMD-spy
watches for those popups in real time. By default it watches **every known
console, terminal and script host** — `cmd.exe`, `powershell.exe`, `pwsh.exe`,
`conhost.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, and the Windows
Terminal app (`wt.exe`, `WindowsTerminal.exe`, `OpenConsole.exe`) — and records,
for each one:

- **Task info** — process name, PID, image path, user and session
- **Command line** — the full command that ran inside the window
- **Cause** — the parent process that spawned it (name, PID, path, its own command line)
- **Actions** — child processes the popup launched while it was alive
- **Networking** — TCP/UDP connections owned by the process (best-effort snapshot)
- **Time** — local and UTC timestamps
- **From bootup time** — how long after the machine booted the popup appeared, plus the boot time and system uptime
- **Lifetime** — exactly how many milliseconds the window existed, and its exit code

Everything is written to **log files** and shown live in the **GUI**.

---

## How it catches a millisecond-lived window

Polling the process list cannot see a process that lives for one millisecond —
it is gone before the next poll. CMD-spy instead uses **real-time, event-driven**
detection:

1. **ETW kernel process trace (primary).** CMD-spy opens an Event Tracing for
   Windows kernel session — the same mechanism Sysmon and Process Monitor use.
   The kernel delivers a *process-start* event containing the **command line and
   parent PID at the moment of creation**, so the popup is fully recorded before
   it can vanish. A matching *process-stop* event gives the exact lifetime and
   exit code. **Requires Administrator.**

2. **WMI process-start trace (fallback).** If an ETW session can't be opened
   (usually because CMD-spy isn't elevated), it falls back to
   `Win32_ProcessStartTrace` / `Win32_ProcessStopTrace`. These are also
   event-driven (not polling), so short-lived processes are still seen, but they
   don't carry the command line — CMD-spy recovers it best-effort from WMI.

For the highest fidelity, **run CMD-spy as Administrator.**

---

## Project layout

```
CmdSpy.sln
src/
  CmdSpy.Core/        Reusable capture engine (no UI)
    Models/           CmdEvent, ProcessInfo, NetworkConnectionInfo
    Monitoring/       ETW + WMI watchers, network inspector, boot-time helper
    Logging/          EventStore (JSON-lines + human-readable .log)
    Formatting/       Text renderer shared by the log and GUI
    CmdSpyEngine.cs   Orchestrator: detect -> filter -> enrich -> store
    CmdSpyOptions.cs  Configuration (targets, network, log directory, ...)
  CmdSpy.App/         WinForms GUI dashboard  (build output: CmdSpy.exe)
```

---

## Building

CMD-spy targets **.NET 8** and **Windows** (`net8.0-windows`). WinForms, ETW and
WMI are Windows-only, so the app runs only on Windows.

### On Windows (normal path)

Install the [.NET 8 SDK](https://dotnet.microsoft.com/download), then:

```powershell
dotnet build CmdSpy.sln -c Release
```

Or open `CmdSpy.sln` in Visual Studio 2022 and build.

### Cross-compiling on Linux/CI

The projects compile on a non-Windows host (they won't *run* there) if you add
`EnableWindowsTargeting`:

```bash
dotnet build CmdSpy.sln -c Release -p:EnableWindowsTargeting=true
```

---

## Running

```powershell
# Right-click -> "Run as administrator" for full ETW fidelity
src\CmdSpy.App\bin\Release\net8.0-windows\CmdSpy.exe
```

The app requests elevation via its manifest. It starts monitoring automatically
and shows a live table of captured popups. Select a row to see the full details
(command line, cause, actions, networking, timing). Toolbar:

- **Start / Stop** monitoring
- **Targets ▾** — every console/terminal/script host is watched by default
  (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `conhost.exe`, `wscript.exe`,
  `cscript.exe`, `mshta.exe`, `wt.exe`, `WindowsTerminal.exe`,
  `OpenConsole.exe`); untick any you don't want, and toggle network /
  child-process capture
- **Filter** — live substring search over command line, process, parent and user
- **Open log folder** / **Export…** (text report or JSON lines)
- Status bar shows monitoring source, event count, boot time and live uptime

---

## Where the logs go

By default, CMD-spy writes to:

```
%ProgramData%\CmdSpy\logs\
    cmdspy-YYYYMMDD.jsonl   one JSON object per line (machine-readable)
    cmdspy-YYYYMMDD.log     formatted, human-readable blocks
```

Files roll by date. The `.jsonl` file writes a full object when a popup is first
captured, then re-writes the full object each time it gains detail (a child
process, a new connection, or its exit + lifetime). Keep the **last line per
event `id`** to get the complete, final record. The `.log` file gets a block when
the popup is first seen and a finalized block when it exits.

### Example `.log` entry

```
============================================================
#42  CMD POPUP CAPTURED   (id 7f3c...)
============================================================
-- Time --------------------------------------------------
  Local time        : 2026-07-06 14:03:11.284 -07:00
  UTC time          : 2026-07-06 21:03:11.284
  System boot time  : 2026-07-06 08:15:02
  Since bootup      : 05:48:09.282
  System uptime     : 20889.3 s
-- Task info ---------------------------------------------
  Process           : cmd.exe  (PID 9184)
  Image path        : C:\Windows\System32\cmd.exe
  User              : DESKTOP-ABC\alice
  Session           : 1
  Detected via      : ETW
-- Command line ------------------------------------------
  cmd.exe /c "ping -n 1 example.com >nul & whoami"
-- Cause (parent process) --------------------------------
  Parent            : powershell.exe  (PID 6012)
  Parent image      : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Parent cmdline    : powershell.exe -File .\deploy.ps1
-- Lifetime ----------------------------------------------
  Exited at (UTC)   : 2026-07-06 21:03:11.331
  Lived for         : 47 ms
  Exit code         : 0
-- Actions (child processes) -----------------------------
  * [9210] whoami.exe
  * [9211] PING.EXE
-- Networking --------------------------------------------
  (no connections captured)
```

---

## Notes & limitations

- **Windows only.** ETW, WMI and the IP Helper API don't exist on other OSes.
- **Administrator recommended.** Without elevation, CMD-spy falls back to WMI and
  may miss command lines for the very shortest-lived processes.
- **Network capture is a snapshot.** A window that exits in a millisecond usually
  hasn't opened a socket yet, so its network list is often empty — that's
  expected. Longer-lived popups and their children are captured more fully.
- This is a **defensive / diagnostic** tool: it observes and logs process
  activity on the local machine. It does not block, kill, or modify anything.
