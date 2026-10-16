# Windows commands and operation

[Back to README](../README.md). Run examples in PowerShell 7.2+ from the folder containing the reviewed script.

## Download and verify

Download `whut-net.ps1` and `SHA256SUMS.txt` from [v1.4.0](https://github.com/styayur/wutnet/releases/tag/v1.4.0). The versioned `whut-net-v1.4.0-fixed.ps1` is identical and retained for existing release links; either file is sufficient. Before running:

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


## Optional automatic login

`install` creates **WHUT-Net AutoLogin**, using the current interactive user's token and least privilege. It stores no Windows account password.

```text
Windows Task Scheduler
  → user logon or NetworkProfile EventID 10000
  → pwsh -NoLogo -NoProfile -NonInteractive
  → whut-net.ps1 auto
  → verify or authenticate, then exit
```

There is no polling loop, resident service or daemon. Overlapping task instances are ignored. Reconnect-triggered login has been field-tested without opening a browser.

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

**Uninstall is destructive. Published v1.4.0 has a failure-reporting limitation.** `uninstall` attempts to remove `WHUT-Net AutoLogin`, then recursively deletes `%LOCALAPPDATA%/WHUT-Net` (configuration, DPAPI credential, logs and auto state). Task Scheduler errors are caught and reported like an absent task; the function can delete state and return 0 even when the task was not removed. Current source repairs this: an access/connection/removal failure returns 1 and retains local state; only successful deletion or the specific task-not-found error permits state deletion. Four offline synthetic regressions cover removal, absence, access denial and service connection failure. This repair is not in the published v1.4.0 assets; their exit 0 is not proof of removal.

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
| 40 | Network or post-authentication verification failure |
| 50 | Local config, credential or executable-resolution error |
