# WUTNet

A lightweight Windows PowerShell tool for Wuhan University of Technology campus-network authentication: configure once, verify the network, log in when needed, then exit.

**PowerShell-native · CLI-first · Read-only-first · Reversible operations · Minimal dependencies**

[Windows v1.5.0](https://github.com/styayur/wutnet/releases/tag/v1.5.0) · [中文说明](docs/README.zh-CN.md) · [Windows guide](docs/WINDOWS.md) · [Field evidence](docs/FIELD_VALIDATION.md)

For WHUT account holders who want finite CLI checks/login and optional recovery automation. The Windows client is one script with no third-party runtime modules; optional automation requires Windows Script Host/VBScript. Windows field observations are recorded; the separate Android v1.4.0 client remains experimental. This CLI uses text examples and a source-linked architecture diagram rather than a GUI screenshot.

## Quick start

Use **Windows 10/11 and PowerShell 7.2+ Core** (`pwsh.exe`); field observations cover Windows 11 with PowerShell 7.6.6. Windows PowerShell 5.1 is unsupported.

Download `whut-net.ps1` and `SHA256SUMS.txt` from [v1.5.0](https://github.com/styayur/wutnet/releases/tag/v1.5.0). Keep the script in a stable directory, review it, and compare its complete hash with the matching checksum entry before running:

```powershell
Get-FileHash ./whut-net.ps1 -Algorithm SHA256
Get-Content ./SHA256SUMS.txt
pwsh -NoProfile -File ./whut-net.ps1 help
```

Offline help excerpt (2026-10-23):

```text
WHUT-Net v1.5.0

Default:
  .\whut-net.ps1
      Smart mode: online -> exit; known WHUT -> connect; new verified WHUT ->
      ask once whether to Trust & Connect.
```

`help` creates no state or network request. **WHUT's observed portal uses HTTP. DPAPI protects the saved password at rest only; fingerprints do not cryptographically authenticate the server.** Read [security limits](SECURITY.md) before storing credentials.

While connected to the WHUT network:

```powershell
./whut-net.ps1 diagnose
./whut-net.ps1 setup -Username '<student-id>'
./whut-net.ps1 login
./whut-net.ps1 status
```

Diagnostics/status do not send the password, but make network requests, can write logs and can migrate old configuration. They are not strictly read-only. `setup` prompts securely for the password and saves it for the current Windows user. There is no general Dry Run mode. [Download blocking and verification details](docs/WINDOWS.md#download-and-verify) explain reviewed-file unblocking without changing execution policy.

## Everyday use

```powershell
./whut-net.ps1 networks -Json
# On another verified WHUT network, explicitly register it:
./whut-net.ps1 trust-current -Label 'WHUT-DORM'
# Connect when needed; ask before trusting a new verified network:
./whut-net.ps1 run
```

`setup` preserves existing network registrations; `trust-current` preserves the saved account/password. `auto` never prompts or enrolls a network. Profile/SSID labels alone do not grant trust. Successful login requires account-status and Internet-recovery checks, not just an HTTP POST.

After a successful manual login, explicitly run `./whut-net.ps1 install` to register **WHUT-Net AutoLogin** for logon, network reconnect, session unlock, sleep resume and a daily two-minute recovery schedule. Installation generates `%LOCALAPPDATA%\WHUT-Net\wutnet-hidden.vbs`; `wscript.exe` starts PowerShell invisibly, waits for it, and returns its actual exit code. `Settings.Hidden` only hides the task in Scheduler. Repeated installation replaces the task definition without duplicate triggers; reinstall after moving the script. WSH/policy/launcher validation failure stops installation without a visible-console fallback.

Each `auto` invocation is finite, uses the interactive user's token and exits when already online. A mutex, 30-second success cooldown and 30/120/300-second failure backoff limit attempts. Nothing schedules itself during setup or normal login. See the [command/parameter matrix and exact trigger settings](docs/WINDOWS.md#optional-automatic-login); unsupported parameter combinations return exit 50.

## Stop, remove and recover

Every invocation exits. **No logout command is implemented**; use the campus portal to end the server-side session. You can disable the scheduled task without deleting credentials, or remove one registered network. See [Windows removal and recovery](docs/WINDOWS.md#stop-automation-remove-trust-or-uninstall).

v1.5.0 `uninstall` removes local state, including the launcher, only after task deletion or confirmed absence. Task removal failure returns 1 and retains configuration, credentials, logs and launcher for retry. Verify task removal separately; there is no automatic undo or backup. Historical v1.4.0 assets retain their original limitation: uninstall can delete state and return 0 after task removal failure. Removing script/state does not log out of WHUT.

## Testing and CI

[Windows CI](https://github.com/styayur/wutnet/actions/workflows/windows.yml) retains syntax, dependency-free offline regression and secret/history checks, and gates Error/Warning findings with pinned PSScriptAnalyzer 1.24.0. Its matrix exercises PowerShell 7.2.24 and the Windows runner version. [Local validation](CONTRIBUTING.md) also separates safe WSH exit-code/COM XML integration from synthetic tests; neither authenticates to campus or installs a real task.

Historical authentication/reconnect and supplied v1.4 hidden-window/unlock evidence remain in [field validation](docs/FIELD_VALIDATION.md). New automated coverage does not establish real-device sleep-resume, every standby mode or periodic recovery acceptance.

## Platform scope and limits

| Platform | Delivered behavior | Verification boundary |
| --- | --- | --- |
| Windows | Single PowerShell file, DPAPI storage, manual login and optional scheduled automation | Maintainer-supplied field observations plus offline regression; not universal campus compatibility |
| Android | Separate Wi-Fi-bound client with Keystore storage | Experimental debug-signed APK; JVM/Lint/build evidence, real-device WHUT authentication unverified |

VPN/TUN software can still block or reroute traffic; Windows requests are not socket-bound to the selected physical adapter. Unknown portal shapes, ambiguous interfaces or changed campus infrastructure can stop authentication. The client does not solve CAPTCHAs or manage VPNs. Android signing changes can require uninstall/reinstall and loss of local data; see [Android setup](docs/ANDROID.md).

## Documentation

[Windows commands, checksums, exit codes and troubleshooting](docs/WINDOWS.md) · [Protocol](docs/protocol.md) · [Architecture evidence](docs/architecture/README.md) · [Field validation](docs/FIELD_VALIDATION.md) · [Android device checklist](docs/android-testing.md) · [Release notes](docs/releases/v1.5.0.md)

<a id="commands"></a>
<a id="automatic-login"></a>
<a id="architecture--protocol"></a>

## License, contributing and security

[MIT](LICENSE) · [Contributing and tests](CONTRIBUTING.md) · [Security](SECURITY.md) · [Third-party notices](THIRD_PARTY.md)

Unofficial community project, unaffiliated with WHUT. Reversibility is limited to the documented task/configuration operations; credential deletion and remote sessions require separate handling.
