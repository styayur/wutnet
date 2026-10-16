# Security and data boundary

WUTNet is an unofficial community client. Use only an account and network you are authorized to access. The observed WHUT portal uses **HTTP**: saved-password encryption does not encrypt transport or prove server identity. Network/protocol fingerprints are defence-in-depth.

## Windows

- **Storage:** DPAPI `CurrentUser` protects the password in `%LOCALAPPDATA%\WHUT-Net\credential.dat`. Account and fingerprints are in `config.json`; bounded logs are in `whut-net.log`. Local state filenames are ignored by Git; ignored files are not a substitute for review.
- **Network registrations:** config v3 stores `trustedNetworks[]`. Existing v2 `trustedNetwork` is automatically migrated on read without changing the account or credential. Legacy v1 remains readable but needs explicit setup before automatic login.
- **Trust checks:** auto must match one complete registered IPv4 prefix, gateway, portal host and interface type. Profile/SSID names never enroll networks or grant trust. DHCP host-address and profile suffix changes are tolerated. Interface alias changes are tolerated; interface type changes require a separate registration in both manual and automatic mode.
- **Physical selection:** enumerate active physical adapters, exclude APIPA and `198.18.0.0/15`, and match the bootstrap `userip` exactly when supplied. Otherwise use unambiguous physical candidates/metrics. TUN route ownership alone does not select the fingerprint.
- **Destination:** exact WHUT host/path/port checks apply to bootstrap and login. API bases must be safe relative paths. HTTP proxy use and automatic redirects are disabled.
- **Password lifetime:** decrypt only immediately before the dedicated POST. Clear owned BSTR, character and byte buffers on success/failure. The Windows credential POST avoids deliberately constructing a plaintext password string. PowerShell/.NET cannot guarantee immediate removal of every runtime/HTTP-stack copy.
- **Output:** logging is designed to exclude passwords, account identifiers, cookies, CSRF values, complete user IPs, request bodies and raw server messages. Review diagnostics before sharing; network labels and prefixes can identify your environment. Protocol errors are separate from credential rejection.

WHUT currently uses **HTTP**. DPAPI protects the password **at rest only**. IP/path/protocol/network fingerprints are defence-in-depth, not cryptographic server authentication. This script does not manage VPNs or bind sockets to the selected adapter; a TUN/VPN can still block portal traffic or change routing after a trust check.



## Recovery limits

`help` is offline. Diagnostics/status make requests, may write logs and may migrate old config; they do not submit a password. Network removal/uninstall has no automatic undo. The published v1.4.0 uninstaller can return 0 after task-removal failure. Current source instead returns 1 and retains state on such failure; read [removal and verification](docs/WINDOWS.md#stop-automation-remove-trust-or-uninstall) before use. Preserve private backups yourself where needed.

## Android

The Android APK is experimental and debug-signed. Android Keystore protects local storage, not HTTP transit; real-device WHUT authentication is unverified. See [Android security and setup](docs/ANDROID.md). Removing an app to change signing keys deletes its private credentials and registrations.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/styayur/wutnet/security/advisories/new) when available. Never post credentials, complete portal/session URLs, raw traffic, local configuration or logs without review to a public issue. Report the affected release and sanitized reproduction. There is no guaranteed response time or security certification.
