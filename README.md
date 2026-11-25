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
- **Cause** — the parent process that spawned it (name, PID, path, its own command line) — kept even if the parent exits instantly
- **Actions** — child processes the popup launched while it was alive, and *their* children (with depth), each with its exit
- **Networking** — TCP/UDP connections captured live as they happen (kernel network events), plus a snapshot
- **Time** — local and UTC timestamps
- **From bootup time** — how long after the machine booted the popup appeared, plus the boot time and system uptime
- **Lifetime** — exactly how many milliseconds the window existed, and its exit code

Then it **investigates** every popup automatically (see [Investigation](#investigation-what-cmd-spy-works-out-for-every-popup)):
who really launched it, what the command does in plain words, which processes it
refers to, whether the programs involved are genuine, which scheduled task is
behind it, what the Windows event logs say, and an evidence-based risk verdict.

Everything is written to **log files** and shown live in the **GUI**. CMD-spy
lives in the **notification area (tray)** — closing the window keeps it
monitoring, and it alerts you when a popup looks suspicious — and it can
**start with Windows** in several ways at once (a boot service that captures
before anyone logs in, plus an elevated, high-priority logon start), so it is
there first. Only one copy ever runs.

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

Reliability is tested, not assumed: CI runs an **ETW stress test** that launches
150 command windows which exit within milliseconds and checks that every one was
captured with its *complete* command line and its exit. You can run the same
check on your own machine with **Investigate ▸ Run capture self-test**.

---

## Investigation: what CMD-spy works out for every popup

Each capture is analysed on a background thread (so capture itself stays fast
enough for millisecond-lived windows). The finalized log record is written once
the analysis is done, so it contains everything below.

| Question | How CMD-spy answers it |
|---|---|
| **Who launched it?** | Full launch chain: parent → grandparent → … → original launcher (e.g. `explorer.exe`, a service, Task Scheduler). Every process seen is remembered — including ones running before monitoring started — so the chain survives parents that exit instantly, and recycled PIDs are rejected by start time. Gaps are filled from Security 4688 / Sysmon when available, and an incomplete chain is reported as incomplete. |
| **Which scheduled task?** | Task Scheduler history (event 129) gives a *Confirmed* match; otherwise the task definitions are matched against the program and arguments (*Likely* / *Possible*), with the task's author, triggers and account. |
| **Which processes does the command refer to?** | PIDs and names inside the command (`ProcessId=…` WQL filters, `Get-Process -Id`, `taskkill /PID`, `/IM`, MiniDump, …) are resolved to the executable, path, vendor and whether it was still running — as of the moment the command ran. |
| **What does the command do?** | A plain-language explanation: interpreter, decoded `-EncodedCommand` payloads, nested `cmd → powershell` chains, each statement explained, and a classification: **Read-only query**, **Makes changes or launches activity**, or **Could not fully determine**. |
| **Is anything suspicious?** | ~40 rules mapped to MITRE ATT&CK: encoded/hidden PowerShell, download-and-run cradles, abused Windows tools (certutil, mshta, regsvr32, rundll32, bitsadmin…), credential dumping, shadow-copy deletion, log wiping, Defender/firewall tampering, persistence (Run keys, services, tasks, WMI, IFEO, Winlogon), obfuscation, odd parent→child launches (Office/PDF/browser → shell), masquerading system names. |
| **Are the programs genuine?** | Authenticode signature (embedded or Windows catalog), publisher, issuer, thumbprint, SHA-256, and version info for the popup, every ancestor, its actions and referenced processes. |
| **What do the Windows logs say?** | Security 4688, Sysmon 1, PowerShell 400/4104 (script blocks) and Task Scheduler records for the popup and its chain. **Investigate ▸ Import past popups** brings in launches from *before* CMD-spy was running. |
| **Should I be worried?** | A risk verdict — **High risk**, **Suspicious**, **Unknown**, **Low risk** — with a score, confidence, what raised it, what lowered it and what is still unknown. |

### CMD-spy never declares a computer "clean"

A harmless-looking command is not proof of a clean machine: a read-only WMI
query is not malicious in itself, but the program that launched it still needs
verification. So **Low risk** is only given when the command shows nothing
suspicious *and* the launcher and the program itself are verified (validly
signed); otherwise the verdict is **Unknown**, with the open questions listed.
One strong indicator (a download cradle, backup deletion, credential dumping…)
is enough for **High risk**. Every verdict carries the reminder that it is an
automated, evidence-based estimate — not a guarantee.

Example (the command from a real investigation):

```
-- Investigation -----------------------------------------
  PowerShell execution (Windows PowerShell) detected — Read-only query
  Launcher          : Not yet identified — requires parent-process evidence.
-- Processes referenced by the command -------------------
  PID      Process                    Status             Vendor / path
  37868    asus_framework.exe         running            ASUSTeK COMPUTER INC.
  39508    asus_framework.exe         running            ASUSTeK COMPUTER INC.
  ...
-- Command analysis --------------------------------------
  Analysis          : Windows PowerShell runs a WMI query that reads information about 5 specific
                      processes (PIDs 37868, 39508, 39524, 39924, 28500 — all asus_framework.exe):
                      creation time, parent process ID, CPU and memory usage, executable path and
                      command line. Read-only: no modification is evident in this command.
-- Risk assessment ---------------------------------------
  Verdict           : Unknown  (score 0/100, confidence Low)
  Still unknown     : The program that launched it could not be identified (no parent-process evidence).
  Note              : Automated, evidence-based estimate — not a guarantee. A harmless-looking command
                      does not mean the computer is clean: the program that launched it must still be verified...
```

### Windows logging (optional, recommended)

CMD-spy captures popups itself while it runs. Windows' own logs add history
(launches from before CMD-spy started) and fill gaps. **Investigate ▸ Windows
logging status** shows what is on; **Investigate ▸ Turn on recommended Windows
logging** enables process-creation auditing (4688) with command lines, Task
Scheduler history and PowerShell script-block logging.

---

## Boot service: monitor before login

**Boot service ▸ Install & start** installs CMD-spy as a Windows service that
starts automatically at boot — before anyone logs in — so popups during start-up
and logon are captured too. It copies CMD-spy to `%ProgramFiles%\CmdSpy` first
(an admin-only folder, so the SYSTEM service can't be tampered with), restarts
automatically if it ever stops, and writes to the same log files. While the
service runs, the GUI shows its captures live instead of capturing separately.
Start, stop and uninstall it from the same menu; its own status messages go to
`cmdspy-service.log` next to the logs.

---

## Start with Windows — fast, first, and more than one way

**Startup ▸ Start with Windows — every method** sets up both of these:

1. **Boot service** (above) — starts with Windows itself, before the log-on
   screen, at high priority for its first minutes, so popups during start-up
   are captured.
2. **Logon task** — opens CMD-spy in the notification area the instant you log
   in: elevated without a UAC prompt, at **high priority** and with **no
   delay**, ahead of the usual start-up programs (Windows won't auto-start
   Administrator programs from the Run key or Startup folder, so a Task
   Scheduler task is used). If CMD-spy is closed or crashes, the same task
   brings it back when you unlock or reconnect.

Each can also be switched on or off on its own from the **Startup ▾** menu (or
**Don't start with Windows** to remove both). Both run the copy installed in
`%ProgramFiles%\CmdSpy`. Releases are precompiled (ReadyToRun) so CMD-spy starts
quickly, and capture begins before the start-up process snapshot finishes.

The logon task uses the Windows Task Scheduler API first. If that registration
fails, CMD-spy keeps the `schtasks` compatibility method and supplies the same
task definition through a protected temporary XML file. Both methods preserve
the current user's account, elevation, priority and triggers; a successful
registration is not repeated through the other method.

## Tray mode and single instance

- CMD-spy shows an icon in the notification area. **Closing the window keeps it
  monitoring there** (turn this off under Startup ▾); right-click the icon to
  open it, pause/resume monitoring, change start-up, or exit.
- **Alerts**: when a popup is analysed as **High risk** or **Suspicious**, a
  notification shows what ran and what launched it — click it to jump to that
  popup. (Startup ▾ / tray menu → *Alert me about suspicious popups*.)
- **Only one copy runs.** Starting CMD-spy again just brings the running window
  forward, so there is never a second capture writing the same logs. To update
  to a new release, exit CMD-spy from the tray, run the new version and choose
  **Startup ▸ Start with Windows — every method** again (it replaces the
  installed copy).

---

## Project layout

```
CmdSpy.sln
src/
  CmdSpy.Core/        Reusable capture engine (no UI)
    Models/           CmdEvent, ProcessInfo, NetworkConnectionInfo, Investigation, ...
    Monitoring/       ETW (process + network) and WMI watchers, process history,
                      signatures, scheduled tasks, Windows event logs, boot-time helper
    Analysis/         Command parser, explainer, referenced-PID extractor,
                      suspicious-command rules, risk assessment
    Logging/          EventStore (JSON-lines + human-readable .log), LogFollower
    Formatting/       Text renderer shared by the log and GUI
    CmdSpyEngine.cs   Orchestrator: detect -> filter -> enrich -> store
    Investigator.cs   Background analysis of each capture
    CmdSpyOptions.cs  Configuration (targets, network, log directory, ...)
  CmdSpy.App/         WinForms GUI dashboard + boot service  (build output: CmdSpy.exe)
tests/
  CmdSpy.Core.Tests/  xUnit tests: analysis, process history, engine, logging,
                      formatting, plus Windows integration tests (ETW stress test)
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

### Tests

```powershell
dotnet test CmdSpy.sln -c Release
```

The test project covers the platform-independent logic — target matching, the
log round trip (including detail captured *after* the initial write), the
display formatting, command analysis, detection rules, the risk verdict, the
process history (parents that exit, recycled PIDs) and the engine end to end.
On Windows with Administrator rights it also runs integration tests against
the real kernel: the capture stress test, referenced-PID resolution, a launcher
that exits immediately, live network capture and signature verification. CI
runs everything on every push, and each push to `main` publishes a downloadable
release.

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

The app **runs elevated**: its manifest requests Administrator, and if it is ever
launched without elevation (for example via `dotnet CmdSpy.dll`, which ignores
the exe manifest) it re-launches itself with a UAC prompt. It starts monitoring
automatically and shows a live table of captured popups. Select a row to see the
full details (command line, cause, actions, networking, timing). Toolbar:

- **Start / Stop** monitoring
- **Targets ▾** — every console/terminal/script host is watched by default
  (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `conhost.exe`, `wscript.exe`,
  `cscript.exe`, `mshta.exe`, `wt.exe`, `WindowsTerminal.exe`,
  `OpenConsole.exe`); untick any you don't want, and toggle network /
  child-process capture
- **Startup ▾** — start with Windows (boot service and/or tray at log on), keep
  monitoring in the tray when closed, suspicious-popup alerts
- **Investigate ▾** — re-analyse or copy the report of the selected popup,
  import past popups from the Windows event logs, check/turn on Windows logging,
  run the capture self-test
- **Boot service ▾** — install, start, stop or remove the boot-start service
- **Filter** — live substring search over command line, process, parent, user, risk and launcher
- **Open log folder** / **Export…** (text report or JSON lines)
- The **Risk** and **Launched by** columns show each popup's verdict and original
  launcher (or scheduled task); High-risk rows are red and Suspicious rows amber
- Status bar shows monitoring source, event count, boot-service state, boot time and live uptime

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
event `id`** to get the complete, final record (including its `investigation`).
The `.log` file gets a block when the popup is first seen and a finalized block
— with the full investigation — once it has exited and been analysed. Both files
can be read while CMD-spy is writing them.

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
- **Network capture.** Connections are captured live from kernel network events
  (TCP connect/accept, UDP send) for the popup and its actions, plus a snapshot
  of the connection table. A window that exits in a millisecond usually hasn't
  opened a socket, so its network list is often empty — that's expected.
- **Verdicts are estimates.** The risk assessment is automated and evidence-based;
  it can miss things and never certifies a machine as clean. Use it to decide
  what to look at, together with a full antivirus scan.
- This is a **defensive / diagnostic** tool: it observes and logs process
  activity on the local machine. It does not block, kill, or modify anything.

## Search keywords (ignore)

`cmd-spy`, `windows`, `command-prompt`, `cmd`, `powershell`, `windows-terminal`,
`console-monitoring`, `process-monitoring`, `process-creation`, `process-exit`, `command-line-capture`, `parent-process`,
`process-tree`, `etw`, `event-tracing`, `wmi`, `windows-event-log`, `task-scheduler`,
`scheduled-tasks`, `authenticode`, `digital-signatures`, `sha256`, `network-connections`, `tcp`,
`udp`, `jsonl`, `log-files`, `system-tray`, `boot-service`, `startup-monitoring`,
`risk-assessment`, `defensive-security`, `incident-investigation`, `winforms`, `csharp`, `dotnet`
