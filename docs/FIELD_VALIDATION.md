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

## v1.4.0 fixed — additional supplied field evidence (2026-10-11)

The maintainer supplied private `devlog` captures. They are excluded from Git because they contain local account and session data. The following is a sanitized engineering summary, not a fresh test performed during publication:

- PowerShell 7.6.6 parsed the v1.4 script. `diagnose` recognized `/api/r/59`, replayed bootstrap, selected physical WLAN with TUN present, obtained `/api` and CSRF, and reported account code 1.
- A new physical environment did not match the old v2 fingerprint; diagnostics required explicit trust.
- The initial v1.4 `networks` output disappeared because the dispatcher captured the table stream with the exit code. The supplied fixed script routes tables through `Out-Host` and JSON through stdout separately.
- The fixed script displayed the retained WHUT-WLAN registration. Explicit `trust-current -Label "WHUT-DORM"` verified the WHUT protocol, migrated to v3, and added the second fingerprint.
- `networks` then displayed both WHUT-WLAN and WHUT-DORM. Default invocation authenticated successfully and verified Internet recovery.

The log does not show a later return to WHUT-WLAN or a new scheduler test on the final release file. The earlier v1.3.2 scheduler observation remains historical evidence. Android has no new device-side WHUT evidence.

Publication retains the v1.4 behavior while restoring v1.3.2 regression protections: atomic config writes, automatic v2 migration on read, exact physical bootstrap-IP matching, raw redirect checks, malformed-bootstrap rejection and block-comment/case-sensitive config parsing. It also keeps `setup -AddNetwork` and adds IDs to existing v1.3.2 v3 registrations. These release-preparation edits are covered by offline tests; they are not claimed to have been re-run against the campus portal.

## Supplemental historical hidden-launcher evidence (recorded 2026-10-23)

The Phase 1–2 task supplied additional prior conversation evidence concerning the fixed v1.4.0 script. This supplements, rather than rewrites, the dated records above. The precise observation date was not supplied:

- The fixed script was run in `auto` mode through a manually configured `wutnet-hidden.vbs`.
- Task Scheduler used `wscript.exe` and that VBS rather than directly starting the visible PowerShell console.
- Manual task invocation and lock/unlock each returned `LastTaskResult = 0`.
- The black PowerShell console no longer appeared in the tested scenario.

These are maintainer-supplied historical observations, not new Codex field tests, and not proof that the historical launcher propagated every failure exit code. The manual machine-specific location is not an installer prerequisite. The managed v1.5.0 launcher is generated from the actual installation path. The supplied evidence contains no additional sleep-resume or periodic-retry acceptance.

## v1.5.0 automated and safe local integration boundary (2026-10-23)

The dependency-free suite checks generated quoting/UTF-16, synchronous hidden launch/exit structure, missing dependencies, launcher/write/probe failures, five-trigger definitions, repeat installation and upgrade, least privilege, command contracts and recoverable uninstall. All data, network transport and task registration are synthetic.

Separate safe local integration started a generated launcher against a temporary script returning 37; WSH returned 37. Actual Windows Scheduler COM accepted the five-trigger definition using `TASK_VALIDATE_ONLY`, without registering a task. Local provider metadata confirmed Power-Troubleshooter EventID 1 describes resume from a low-power state. These checks do not perform authentication, physically unlock/sleep the device, observe a new task firing, or establish universal standby/periodic-retry acceptance. Existing field evidence does not need to be repeated to preserve it.
