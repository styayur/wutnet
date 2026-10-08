# WUTNet

[![PowerShell](https://img.shields.io/badge/PowerShell-7.2%2B-5391FE?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Android%208%2B-lightgrey)](#platforms)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A lightweight Windows and Android authenticator for the Wuhan University of Technology (WHUT) captive portal.

Windows retains the single-file PowerShell 7 client, DPAPI and optional Task Scheduler integration. Android adds a native Kotlin client using Android Keystore and network-bound Android Network APIs, with Views/XML, no WebView and no resident service. Both clients dynamically discover WHUT portal sessions and handle CSRF/cookies. The Windows script remains at the repository root so existing commands and Release downloads keep working.

## Platforms

| Platform | Implementation | Credential storage | Automation |
| --- | --- | --- | --- |
| Windows 10/11 | PowerShell 7.2+ Core, root `whut-net.ps1` | DPAPI CurrentUser | Optional per-user Task Scheduler task |
| Android 8+ | Native Kotlin, Views/XML and ViewBinding, `android/` | Android Keystore AES-256-GCM | Foreground network callbacks; compatible system sign-in entry point |

Protocol semantics are documented in [docs/protocol.md](docs/protocol.md). No Windows authentication logic was changed for the Android MVP. MIT remains the first-party licence; see [third-party notices](THIRD_PARTY.md) for build tools and language/binding support.

## Android Quick Start

Android v0.1 is **early/experimental**. The first complete Android authentication against a real unauthenticated WHUT Wi-Fi session is still pending.

Install JDK 21 and Android SDK platform 37.0 / build tools 36.0.0, or open `android/` in a compatible Android Studio (AGP 9.2.1). Configure `ANDROID_HOME` or the ignored `android/local.properties` SDK path. Use the checked-in, checksum-pinned Gradle 9.4.1 wrapper:

```sh
cd android
./gradlew test
./gradlew lint
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

On Windows use `gradlew.bat`. The signed debug APK is installable. Optional `assembleRelease` produces a smaller **unsigned** APK that must be signed before installation; no personal signing key is needed to build it.

1. Connect to trusted WHUT Wi-Fi and open WUTNet.
2. Open Settings, enter your campus account/password, acknowledge the HTTP disclosure, and Save.
3. Run Diagnostics before tapping Login. Diagnostics never submit the saved password.
4. Require account-online confirmation and Internet recovery on the same Wi-Fi. Cellular availability does not count as Wi-Fi success.
5. Clear credential removes the private record and Keystore key.

Permissions are `INTERNET`, `ACCESS_NETWORK_STATE`, and the necessary `ACCESS_LOCAL_NETWORK` runtime permission on Android 17+. Target API 37 requires that permission for direct private-IP portal access; use the explicit **Allow local portal access** button, and denial safely stops portal requests. See [Android local network permission](https://developer.android.com/privacy-and-security/local-network-permission). The app does not scan Wi-Fi or read SSIDs and requests no location, nearby-device, notification or foreground-service permission. Every HTTP/HTTPS request uses the selected Wi-Fi `Network.openConnection(..., Proxy.NO_PROXY)`, with no global process binding or cellular retry. Foreground callbacks stop when the app leaves the foreground; there is no daemon, periodic WorkManager task or background guarantee.

Passwords use an unexportable Android Keystore AES key and AES/GCM/NoPadding. Username, ciphertext and random IV are stored in a versioned app-private record under `noBackupFilesDir`; backups/transfers are disabled. A lost/invalidated key or decryption failure requires re-entry. No plaintext password preference or sensitive log is written. Mutable password and POST buffers are wiped promptly, while immutable ART encoding Strings cannot be reliably zeroed.

**HTTP limitation:** the current WHUT portal is `http://172.30.21.100`; credentials travel without transport encryption. Keystore protects storage only. Strict IP/port/raw-path, config/API and CSRF fingerprints reduce mistakes but cannot cryptographically authenticate a hostile Wi-Fi access point. The app requires explicit acknowledgement before storing a credential. Network Security Config disables cleartext by default, allowing the exact portal IP and credential-free probe hosts. Numeric IP entries are not a firewall and may vary on OEMs; application-level allowlists remain mandatory. No global `usesCleartextTraffic=true` is used.

**System sign-in limitation:** a protected compatibility Activity accepts the official `ACTION_CAPTIVE_PORTAL_SIGN_IN` extras, binds to `EXTRA_NETWORK`, and can attempt login once using a previously acknowledged credential. After verified account/Internet success it calls `reportCaptivePortalDismissed()` when a system handle is present. The Activity requires a signature-level system permission on callers to prevent another app triggering credential use; WUTNet does not request that permission. Many Android/OEM builds explicitly choose their own portal Activity, so declaring a filter does **not** make WUTNet the default sign-in app. Ordinary manual login remains available; there are no Accessibility, VPN, Root or Device Owner workarounds.

See the [device/manual testing checklist](docs/android-testing.md) for cellular coexistence, network loss, credential storage and real system-entry verification. The most valuable next step is real WHUT field validation followed by device-side regression tests; a Quick Settings Tile remains a possible v0.2 addition.

> **Status:** `v0.1.0-alpha.1` is an early, experimental release. Local configuration, PowerShell 7 execution, credential storage and Internet probing have been exercised, but the complete offline → captive portal → authentication → Internet recovery path should still be treated as experimental until field-tested against the current WHUT deployment.

## Windows Features

- Single-file PowerShell 7 implementation
- No Python, browser extension, Docker, service or third-party PowerShell module
- Dynamic captive-portal discovery
- Dynamic `nasId` extraction
- Dynamic API base-path discovery from the WHUT portal configuration
- Cookie-aware CSRF session handling
- Windows DPAPI `CurrentUser` password protection
- Explicit proxy bypass for local portal traffic
- Hard-coded WHUT portal host/path allowlist
- Trusted physical Windows network-profile binding for automatic login
- Optional Task Scheduler integration
- No resident polling loop
- Bounded local logging with no password, cookie or CSRF-token output

## Windows Requirements

- Windows 10 or Windows 11
- PowerShell 7.2 or later (`pwsh.exe`)
- Access to the WHUT campus network

Windows PowerShell 5.1 (`powershell.exe`) is not supported.

Check your version:

```powershell
$PSVersionTable.PSVersion
$PSVersionTable.PSEdition
```

Expected:

```text
7.2+
Core
```

## Windows Quick Start

Clone or download `whut-net.ps1`, then open PowerShell 7 in the script directory.

If Windows has marked the downloaded script as originating from the Internet, remove that file-level mark:

```powershell
Unblock-File .\whut-net.ps1
```

Configure your account while connected to the WHUT network:

```powershell
.\whut-net.ps1 setup -Username <student-id>
```

The password prompt is interactive. The password is stored using Windows DPAPI and is not written to the repository or configuration file in plaintext.

Before attempting login, inspect the current network and portal state:

```powershell
.\whut-net.ps1 diagnose
```

Then test a manual login:

```powershell
.\whut-net.ps1 login
```

Verify the result:

```powershell
.\whut-net.ps1 status
```

Only after manual testing succeeds should automatic login be enabled:

```powershell
.\whut-net.ps1 install
```

## Commands

| Command | Purpose |
| --- | --- |
| `setup [-Username <student-id>]` | Save the username, DPAPI-protected password and current trusted physical network profile |
| `status` | Check Internet and WHUT authentication state without logging in |
| `login` | Authenticate once when required |
| `auto` | Idempotent mode intended for Task Scheduler; exits immediately when already online |
| `diagnose` | Inspect portal discovery, `nasId`, API base, CSRF acquisition and account state without submitting the stored password |
| `install` | Register the per-user automatic-login scheduled task |
| `uninstall` | Remove the scheduled task and all WHUT-Net local state |
| `help` | Show built-in usage information |

## How It Works

```text
Windows network connected
        |
        v
Internet probe
   |          |
 online     captive/offline
   |          |
  exit        v
        Discover WHUT portal
               |
               v
        Validate host + path
               |
               v
          Extract nasId
               |
               v
        Read API base path
               |
               v
       Establish CSRF/cookie
             session
               |
               v
       Check account status
               |
          offline only
               |
               v
      Validate trusted local
        network profile
               |
               v
       Decrypt DPAPI password
               |
               v
          POST login
               |
               v
       Verify account status
               |
               v
        Verify Internet access
```

The script does not keep a background daemon running. When automatic login is installed, Windows Task Scheduler invokes the script on user logon and network-connect events; the process exits after the check or authentication attempt completes.

## Security Model

WHUT-Net deliberately keeps the trust boundary narrow.

### Credentials at rest

The password is stored under:

```text
%LOCALAPPDATA%\WHUT-Net\credential.dat
```

PowerShell's `ConvertFrom-SecureString` uses Windows DPAPI for the current Windows user. Another Windows account cannot normally decrypt the stored value.

The username and trusted Windows network-profile names are stored separately in:

```text
%LOCALAPPDATA%\WHUT-Net\config.json
```

### Portal allowlist

Credentials are only submitted after the discovered captive portal matches the expected WHUT portal host and path.

Dynamic values such as `nasId` may change between sessions, but the authentication destination is not accepted from an arbitrary redirect.

### Trusted local network profile

Automatic login additionally requires a physical Windows network profile captured during `setup`.

This is a defence-in-depth check, not cryptographic server authentication.

### HTTP limitation

The current WHUT captive portal uses HTTP.

DPAPI protects the password **at rest**, but WHUT-Net cannot provide transport encryption that the upstream portal itself does not support. Users should understand this limitation before enabling unattended authentication.

### Logging

WHUT-Net does not intentionally log:

- passwords
- decrypted credential material
- cookies
- CSRF token values
- login request bodies
- usernames and trusted network-profile names
- raw portal response messages or unexpected exception details

The log is stored at:

```text
%LOCALAPPDATA%\WHUT-Net\whut-net.log
```

and is rotated when it reaches approximately 1 MiB.

## Automatic Login

After validating manual login:

```powershell
.\whut-net.ps1 install
```

This registers a per-user Task Scheduler task named:

```text
WHUT-Net AutoLogin
```

The task runs with the current interactive user's token and least privilege. It is triggered by:

- user logon
- Windows Network Profile connection events

The task invokes PowerShell 7 and executes:

```text
whut-net.ps1 auto
```

No Windows account password is stored in Task Scheduler.

To remove the task and local WHUT-Net data:

```powershell
.\whut-net.ps1 uninstall
```

## Exit Codes

| Code | Meaning |
| ---: | --- |
| `0` | Online or authentication succeeded |
| `10` | WHUT portal reached; account offline |
| `11` | WHUT portal not discovered or `nasId` missing |
| `12` | Untrusted portal, network profile or unsafe API path |
| `20` | Authentication failed |
| `21` | Additional verification/code check required |
| `22` | CSRF acquisition failed |
| `30` | WHUT portal/API unavailable |
| `40` | Network failure or post-authentication Internet verification failure |
| `50` | Local configuration or credential error |

These codes are intended to make the script usable from Task Scheduler and other PowerShell automation.

## Troubleshooting

### The script requires PowerShell 7.2

If the error mentions Windows PowerShell 5.1, you launched `powershell.exe` instead of `pwsh.exe`.

Run:

```powershell
pwsh
```

Then retry the command.

### Script execution is blocked

Inspect the current policy:

```powershell
Get-ExecutionPolicy -List
```

For a downloaded copy you have inspected, removing the file's Internet mark is usually preferable to globally weakening PowerShell policy:

```powershell
Unblock-File .\whut-net.ps1
```

### Diagnose reports `Internet: OK`

This means the machine already has Internet access, so WHUT-Net intentionally does not contact the captive portal.

To validate the complete authentication flow, test during a genuine unauthenticated WHUT session.

### Inspect logs

```powershell
Get-Content "$env:LOCALAPPDATA\WHUT-Net\whut-net.log" -Tail 50
```

## Project Scope

WHUT-Net intentionally does **not** aim to become a general campus-network manager.

The project is limited to:

- detecting the WHUT captive portal
- authenticating safely enough within the constraints of the upstream portal
- integrating cleanly with Windows
- exiting when its work is complete

Features such as GUI management, multi-account rotation, bandwidth monitoring, generic multi-campus adapters and persistent background polling are outside the current scope.

## Disclaimer

This is an unofficial community project and is not affiliated with, endorsed by, or maintained by Wuhan University of Technology.

Campus-network infrastructure and authentication APIs may change without notice. Use the script only with an account and network access you are authorised to use.

## License

MIT License.

This follows the repository owner's [License Policy](https://github.com/styayur/styayur/blob/main/LICENSE_POLICY.md), which assigns MIT to small scripts and automation projects.

Third-party materials, if introduced in the future, remain under their respective upstream licences and are not relicensed by this project.
