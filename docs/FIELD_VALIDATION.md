# WUTNet Windows Field Validation

Release: **v1.3.2**. Record consolidated on 2026-10-09 from maintainer-supplied field observations. This is an engineering summary, not a raw terminal dump or a claim that offline tests performed campus authentication.

## Environment

- Windows 11
- PowerShell 7.6.6, PSEdition Core
- Current WHUT captive portal
- Meta/TUN virtual adapter present alongside physical WLAN

## Discovery observation

| Observation | Environment A | Environment B |
| --- | --- | --- |
| Bootstrap | `/api/r/59` | `/api/r/52` |
| Private DHCP address, anonymized | `10.91.x.x` | `10.82.x.x` |
| BRAS name | `WHUT-YQ-Bras-ME60` | `WHUT-Bras-ME60-A` |

The observed redirect was HTTP 302 from a NetEngine server to the exact host `172.30.21.100`. `nasId`, `userip`, `acip`, `acname` and `wlanacname` are session/campus data, not constants. `/api/r/<nasId>` bootstraps the session; `/tpl/whut/login.html` remains the canonical page.

The field config contained a commented test URL followed by the active `var host_url = '/api'`. Only the active declaration establishes the API base.

## Failures found

1. A single NeverSSL probe timed out, preventing discovery.
2. The actual `/api/r/<nasId>` redirect was initially rejected as an unknown login path.
3. Route-only fingerprinting selected Meta/TUN rather than physical WLAN.
4. A commented config.js `host_url` looked like an ambiguous second assignment.
5. Store PowerShell enumeration returned multiple executable paths (`String[]`), which could not be assigned to a scheduled-task Action path.

## Fixes

1. Independent NCSI/NeverSSL/direct-WHUT probes with a bounded shared discovery budget.
2. Strict HTTP bootstrap allowlist, dynamic metadata extraction, bootstrap replay in a cookie jar, then the canonical login page.
3. Physical adapter enumeration with APIPA/benchmark-range exclusion and exact bootstrap `userip` matching. No SSID scan or VPN management.
4. Parse active `var|let|const host_url` declarations, ignore comments and deduplicate identical values; retain safe-path and CSRF checks.
5. Prefer the stable Store App Execution Alias, then the running PowerShell directory, then a unique safe application candidate. Construct a scalar Action executable and quoted script arguments.

## Successful chain

```text
NCSI → bootstrap → canonical portal → config.js → CSRF/cookies
→ status (offline) → real login → status (online) → Internet verification
```

Diagnostics successfully recognized bootstrap, selected physical WLAN, reported its subnet rather than a complete user IP, resolved `/api`, obtained CSRF and reported account code 1 before login. Real login then succeeded, account/status was rechecked, and Internet access recovered. Subsequent `status` reported online; `auto` returned immediately without another login.

## Scheduled login validation

`install` produced a Ready task named **WHUT-Net AutoLogin**, with logon and NetworkProfile EventID 10000 triggers. Its Action used the current user's `Microsoft\WindowsApps\pwsh.exe` alias, `-NoLogo -NoProfile -NonInteractive -File "...\whut-net.ps1" auto`, and the script's directory.

```text
Disconnect/reconnect WHUT → NetworkProfile event → Task Scheduler
→ pwsh alias → auto → authenticated → Internet restored
```

This reconnect test succeeded without opening a browser. It validates the event-driven path, not an always-running service.

## Security observations

WHUT still uses HTTP; DPAPI protects storage only. Bootstrap/login host and path allowlists, protocol shapes and physical fingerprints restrict credential use but do not cryptographically authenticate the server. Password decryption is late and owned buffers are cleared; runtime/HTTP-stack copies cannot be guaranteed erased. No account ID, credential, cookie, CSRF value, full user IP or raw authentication body is included in this record.

## Release regression coverage

Offline tests cover the supplied campus forms plus a synthetic third session, invalid bootstrap URLs, ignored foreign redirects, TUN exclusion, config comments/deduplication, password encoding/cleanup and scalar Task Scheduler actions.

The additional `trustedNetworks[]` registration and automatic v2→v3 migration requested during release preparation are offline-tested for matching either registration, deduplication, retained account/credential and refusal to enroll by profile name. These new multi-registration operations have not been represented as a fresh physical campus-switch test. Existing authentication and scheduler behavior remain grounded in the field evidence above.

## Result

**Windows v1.3.2 field-verified.** The release consolidates the verified Windows authentication and reconnect-automation fixes. Future portal or deployment changes may require updates.
