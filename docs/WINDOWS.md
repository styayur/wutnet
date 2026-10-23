# Windows commands and operation

[Back to README](../README.md). Run examples in PowerShell 7.2+ from the folder containing the reviewed script.

## Download and verify

Download `whut-net.ps1` and `SHA256SUMS.txt` from [v1.5.0](https://github.com/styayur/wutnet/releases/tag/v1.5.0). Its `whut-net-v1.5.0.ps1` asset is identical. The tracked `whut-net-v1.4.0-fixed.ps1` remains a byte-identical compatibility filename in current source and is not the historical v1.4.0 download; old tags/assets are unchanged. Before running:

```powershell
Get-FileHash ./whut-net.ps1 -Algorithm SHA256
Get-Content ./SHA256SUMS.txt
pwsh -NoProfile -File ./whut-net.ps1 help
```

Compare the complete SHA-256 for the exact filename before execution. Stop on mismatch. Checksums do not provide an independent publisher signature. If using the versioned name, verify it under that name before renaming or substitute it in commands. Review source locally; do not execute a downloaded remote script through a pipeline. If Mark of the Web blocks the reviewed file, use `Unblock-File ./whut-net.ps1` only when local policy permits. The client does not change execution policy.

## Inspection and side effects

`help` is offline and does not create local state. `diagnose` and `status` do not send a password or log in, but they make network probes and can create/append bounded local logs. Commands reading old configuration, including diagnostics/network listing, can automatically migrate v2 or incomplete v3 metadata on disk. `-Json` changes output format, not these side effects. There is no general Dry Run/WhatIf switch.

## Commands

| Command | Purpose |
| --- | --- |
| `setup [-Username <student-id>]` | Save credentials, preserve registrations, and add the current network only after protocol verification |
| `run` (default) | Connect when needed; ask before trusting a new verified network |
| `trust-current [-Label <name>]` | Verify and explicitly register the current physical network |
| `networks [-Json]` | List registered fingerprints, labels and IDs |
| `remove-network -NetworkId <id>` | Remove one registration |
| `setup -AddNetwork` | Explicitly append a physical network without changing the account/password |
| `status` | Check Internet and account state; never log in |
| `login` | Authenticate once if needed, then verify account and Internet |
| `auto` | Automatic mode; exit immediately if already online; otherwise require a registered fingerprint |
| `diagnose` | Inspect discovery, bootstrap, physical fingerprint, API, CSRF and status without sending the password |
| `install` | Register the per-user scheduled task |
| `uninstall` | Remove task, then delete local config, credential and logs; current source preserves state on task-removal failure |
| `help` | Show usage and exit codes |

### Command/parameter contract

| Command | Accepted options |
| --- | --- |
| `run` (default), `login` | `-Json` or `-Yes` |
| `setup` | `-Username`, `-Label`, `-Json`; `-AddNetwork` is the trust-current alias and excludes `-Username` |
| `status`, `auto`, `diagnose`, `networks` | `-Json` |
| `trust-current` | `-Label`, `-Json` |
| `remove-network` | Required `-NetworkId`, optional `-Json` |
| `install`, `uninstall`, `help` | No command-specific options |

PowerShell common parameters remain available. Unsupported options/combinations return exit 50 before command work. `-Yes` only approves interactive Trust & Connect in run/login; JSON mode requires prior explicit registration, so `-Yes -Json` is rejected. Existing public commands, `setup -AddNetwork`, config fields, JSON shapes and exit codes are retained. Local interface errors use 50; PowerShell's own binding errors retain its normal nonzero exit behavior. There is no `-WhatIf`/`-Confirm` contract in this phase.

## Optional automatic login

`install` creates or updates **WHUT-Net AutoLogin**, using the current interactive user's token and least privilege. It stores no Windows account password. Configuration, a saved DPAPI credential and at least one trusted network must already exist.

```text
Windows Task Scheduler
  → logon / network / unlock / resume / daily two-minute recovery
  → wscript.exe //B //NoLogo "...\WHUT-Net\wutnet-hidden.vbs"
  → resolved pwsh.exe -NoLogo -NoProfile -NonInteractive
  → whut-net.ps1 auto
  → verify or authenticate, then exit
```

The generated UTF-16 launcher is managed under `%LOCALAPPDATA%\WHUT-Net`. It contains only executable/script paths and fixed arguments. `WScript.Shell.Run(commandLine, 0, True)` hides the child console, waits, then `WScript.Quit` propagates the child's actual exit code. Task `Settings.Hidden` only controls Scheduler visibility. Paths with spaces and Unicode are quoted and VBScript quotes are escaped.

| Trigger | Native definition |
| --- | --- |
| User logon | Logon type 9, current user, `PT5S` delay |
| Network connection | Event type 0, `Microsoft-Windows-NetworkProfile/Operational`, EventID 10000, `PT3S` delay |
| Session unlock | Session-state-change type 11, StateChange 8 (`SessionUnlock`), current user, `PT3S` delay |
| Resume | Event type 0, System log, provider `Microsoft-Windows-Power-Troubleshooter`, EventID 1, `PT3S` delay |
| Recovery fallback | Daily type 2, installation day's local midnight StartBoundary, DaysInterval 1, no EndBoundary; repeat `PT2M` for `P1D`, StopAtDurationEnd false |

The daily window restarts every day, including after the first day. It is active throughout the day while the user's interactive token is available; it does not wake the computer. `StartWhenAvailable` permits catch-up. Each process has a `PT2M` execution limit, `IgnoreNew` overlapping-instance policy, a local auto mutex, 30-second success cooldown and failure backoff of 30, 120 then 300 seconds. Healthy Internet causes an early exit; unknown networks are never auto-enrolled. No polling loop runs inside PowerShell.

Installation constructs the full task afresh, asks Windows to validate its XML with `TASK_VALIDATE_ONLY`, writes/readback-checks a temporary launcher and safely probes WSH by running only `pwsh -Command "exit 73"`. The distinctive expected result proves child execution even if a blocked host returns zero. It atomically replaces the managed launcher only after that probe passes, then registers with `TASK_CREATE_OR_UPDATE`. WSH/VBScript unavailability, policy blocking or launcher failure stops installation; no direct visible-console fallback is used. An existing launcher survives generation/probe failure. Registration failure reports its actual error and keeps configuration, credentials and the prepared launcher for retry. Resolve the cause and rerun `install`; do not edit a manual VBS in another directory.

Historical reconnect and supplied hidden-window/unlock observations remain separate from new offline and safe local integration results in [field validation](FIELD_VALIDATION.md). They do not establish universal standby compatibility.

The executable resolver prefers `%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe`, then `$PSHOME\pwsh.exe`, then one unambiguous installed application candidate. The Store alias survives package-version changes. Re-run `install` after moving the script.



## Stop automation, remove trust or uninstall

Each invocation is finite and exits. The client has **no logout command**: ending the script, removing trust or uninstalling does not terminate the campus account session. Use the campus portal for server-side logout.

To suspend automation while retaining saved credentials and registrations, inspect the named task, then explicitly disable it:

```powershell
Get-ScheduledTask -TaskName 'WHUT-Net AutoLogin' -ErrorAction SilentlyContinue
Disable-ScheduledTask -TaskName 'WHUT-Net AutoLogin'
# When wanted again:
Enable-ScheduledTask -TaskName 'WHUT-Net AutoLogin'
```

These are Windows Task Scheduler commands, not client subcommands. Confirm the task's action is your WUTNet script first. Disabling prevents future triggers; inspect any currently running invocation separately.

`remove-network -NetworkId '<listed-id>'` forgets one registration and prevents automatic authentication on it; it does not remove the account/password or log out. Use `networks -Json` to select the exact ID.

**Uninstall is destructive.** v1.5.0 first removes `WHUT-Net AutoLogin`, then deletes `%LOCALAPPDATA%/WHUT-Net` (configuration, DPAPI credential, logs, auto state and generated launcher). Only successful deletion or `ERROR_FILE_NOT_FOUND` from task deletion permits state removal. Access denial, service connection failure and ambiguous errors return 1 and preserve all local state for retry. Offline regressions check the order and each outcome. Historical v1.4.0 assets can clear state and return 0 after task-removal failure; they remain unchanged, and their exit 0 is not proof of removal.

Before uninstall, verify/disable the matching task and preserve any local records you need in a private location. Do not point the state directory through a junction or share. Afterward verify in Task Scheduler that the task is gone; resolve permission/COM errors there if it remains. The script file itself remains and can be removed separately once no task points at it:

```powershell
./whut-net.ps1 uninstall
Get-ScheduledTask -TaskName 'WHUT-Net AutoLogin' -ErrorAction SilentlyContinue
```

There is no automatic backup/undo for credential replacement, registration removal or uninstall. Re-run `setup` and explicitly register networks to recreate state. DPAPI `CurrentUser` credentials are not a portable backup for another Windows account or machine. An encrypted credential plus its associated account/network config remains sensitive; never attach them to an issue.

## Troubleshooting and exit codes

| Symptom | Check |
| --- | --- |
| Empty reply from server | Confirm WHUT connectivity and discover a fresh campus session. The portal may be unreachable or the captured URL stale. Do not reuse an old `/api/r/<nasId>?...` URL. |
| `ProtocolChanged` / exit 13 | WHUT frontend/API shape or redirect path may have changed. Run `diagnose`; do not bypass the allowlist. |
| No physical fingerprint | Check WHUT connectivity, multiple physical uplinks and complete IPv4/gateway data. TUN route ownership is excluded from selection; an unmatched campus `userip` fails closed. |
| Different campus/network refused | Connect there and explicitly run `trust-current -Label "WHUT-DORM"` (or `setup -AddNetwork`). No network is trusted merely because its profile name looks familiar. |
| PowerShell not found / task install fails | Verify PowerShell 7 and its Store App Execution Alias at `%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe`. Multiple ambiguous fallback candidates are refused. |
| Hidden launcher validation fails | Verify Windows Script Host/VBScript is available and allowed by local/application-control policy. The installer does not change policy. Normal manual commands do not need WSH. |
| HTTP warning | Expected: DPAPI protects storage, while WHUT's portal itself uses HTTP. |
| Script execution blocked | Use PowerShell 7, inspect the downloaded script and unblock that file; no global policy change is required. |

`diagnose` showing Internet OK means no authentication is needed. Local logs can be inspected with `Get-Content "$env:LOCALAPPDATA\WHUT-Net\whut-net.log" -Tail 50`; review any diagnostic output before sharing.

| Exit | Meaning |
| ---: | --- |
| 0 | Successful command / online / verified login |
| 10 | Account offline |
| 11 | Portal not found or session `nasId` missing |
| 12 | Untrusted network/destination or unsafe API path |
| 13 | Unsupported or changed protocol |
| 14 | New verified WHUT network requires explicit registration |
| 20 | Authentication explicitly rejected |
| 21 | Additional verification required |
| 22 | CSRF/bootstrap request failed |
| 30 | Portal/API unavailable |
| 31 | Discovery exhausted after probe timeouts |
| 40 | Network, task registration or post-authentication verification failure |
| 50 | Local config, credential or executable-resolution error |
