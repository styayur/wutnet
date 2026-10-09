# WHUT Portal protocol — Windows v1.3.2

This records the current field-verified Windows flow, not an official WHUT specification. The [field record](FIELD_VALIDATION.md) identifies the observed environments and separates them from offline regression coverage. Android implementation is unchanged; see the platform notes below.

## Discovery and bootstrap

1. Send a public HTTP probe without proxies or automatic redirects.
2. Observe a 302 to `http://172.30.21.100/api/r/<nasId>?...`.
3. Validate HTTP, exact host, default port, no userinfo/fragment, and raw path `^/api/r/[0-9]{1,10}$`.
4. Parse dynamic `nasId`, `userip`, `acip`, `acname`, and `wlanacname`.
5. Replay the bootstrap using the operation's cookie jar. Validate any response redirect; do not follow arbitrary destinations.
6. Open `http://172.30.21.100/tpl/whut/login.html` with the derived session query in that same jar.
7. GET `/tpl/whut/static/js/config.js`.
8. Parse the active safe relative API base.
9. GET `<base>/csrf-token`.
10. GET `<base>/account/status?token=null`.
11. If offline and login is requested, match a registered physical fingerprint, then POST `<base>/account/login` using the late-decrypted credential.
12. Verify account/status again.
13. Verify Internet recovery.

`/api/r/<nasId>` is a **bootstrap redirector**. `/api/account/login` is an **authentication endpoint**. They are not interchangeable.

Historical private DHCP examples are anonymized: one observed environment used `/api/r/59` with `10.91.x.x`, another `/api/r/52` with `10.82.x.x`. No NAS, user address or BRAS value is hard-coded into discovery.

Internet preflight uses NCSI content and NeverSSL identity. Discovery priority is NCSI redirect → NCSI content → NeverSSL → direct WHUT. Each request has a 4-second timeout; discovery has a 16-second shared request budget, separate from up to 8 seconds of preflight. A public foreign redirect is ignored, never followed or trusted. An unrecognized destination on the WHUT host returns exit 13.

Bootstrap forbids HTTPS, suffix hostnames, nondefault ports, path normalization (`..`), encoded lookalikes, userinfo and fragments. The canonical login allowlist retains HTTP/HTTPS default-port compatibility, exact host and exact raw page path. Relative handshake redirects must already have a known raw path before URI resolution.

Direct page reachability without `nasId` permits diagnostics/status but cannot authorize a credential POST. Discovery reports `InternetOnline`, `PortalRedirectFound`, `WhutBootstrapFound`, `WhutPortalReachable`, `ProtocolChanged`, `ProbeTimeout`, `PortalUnreachable` or `PortalNotFound`. Exhausted discovery prioritizes timeout (31), then direct unavailability (30), then not-found (11).

## Physical trust and configuration

The bootstrap `userip` is a credential-free hint, not authentication. Select only active `Get-NetAdapter -Physical` candidates with usable IPv4/gateway data. Reject APIPA and `198.18.0.0/15`; virtual route ownership does not determine the fingerprint. A supplied hint must match one physical address exactly. Without a hint, select an unambiguous physical candidate using the existing private-address/route-metric preference.

Config v3 stores `trustedNetworks[]`; each entry contains profile name (auxiliary), interface alias/type, recorded IPv4 address, actual CIDR prefix, default gateway and portal host. `setup -AddNetwork` is the explicit enrollment operation and preserves the existing account/password. Same-fingerprint registrations are deduplicated. Ordinary setup replaces the registrations with the current network.

Reading v2 wraps its existing single fingerprint in the v3 list and atomically replaces only the config file. It does not decrypt or rewrite `credential.dat`. Version 1 remains readable; its profile names cannot authorize auto-login.

Immediately before decryption, auto must match **one complete entry** by prefix, gateway, host and interface alias/type. Fields from different entries are never combined. Manual login may tolerate an alias/type change, but v3/v2 still require prefix/gateway/host consistency. Profile/SSID names never enroll networks or suffice for trust. DHCP host addresses may change within the registered prefix.

## API base and protocol fingerprint

After removing block comments, parse active declarations with:

```regex
(?m)^\s*(?:var|let|const)\s+host_url\s*=\s*['"]([^'"]+)['"]\s*;?
```

Line-commented declarations do not match. Deduplicate identical values with case-sensitive `Sort-Object -Unique`; multiple distinct paths mean `ProtocolChanged` (13). API paths are case-sensitive.

Only nonempty ASCII relative path segments such as `/api` and `/eportal/api` are accepted. Reject absolute URLs, schemes, authorities, `//`, `..`, backslashes, percent escapes, query/fragment suffixes and root-only paths. Unsafe explicit config fails closed. If config is unavailable/unparseable, `/api` fallback requires an active matching CSRF response; status is then validated before credential release.

| Endpoint | Required HTTP/JSON fingerprint |
| --- | --- |
| `<base>/csrf-token` | HTTP 200; object with a nonblank string `csrf_token`, no control characters |
| `<base>/account/status?token=null` | HTTP 200; object with integer `code` |
| `<base>/account/login` | HTTP 200; object with integer `code` and string `msg` |

Duplicate top-level JSON keys and missing, malformed or wrongly typed fields return exit 13. Raw `msg` is never UI/log content. CSRF request failure uses 22; other unavailable APIs use 30. Authentication rejection is 20 only after a valid login response; code 2 requires additional verification (21).

## Authentication request and verification

Status/login use the validated portal Referer, JSON Accept header, `X-Requested-With: XMLHttpRequest`, `X-Csrf-Token`, and operation cookies. Login additionally supplies Origin and UTF-8 form content:

| Field | Value |
| --- | --- |
| `username` | Saved account |
| `password` | Late-decrypted credential, never logged |
| `nasId` | Current discovered session value |
| `swtichip` | Empty; spelling matches the observed API |
| `userIpv4`, `userMac`, `captcha`, `captchaId` | Empty |

DPAPI `CurrentUser` remains the storage mechanism. The credential-specific POST converts SecureString through BSTR and mutable character/UTF-8 buffers, then clears owned buffers on success/failure. No generic logging or form helper receives a plaintext password string. No complete request body is attached to application exceptions.

After login code 0, wait once for 750 ms, require status code 0 and require an Internet identity probe to succeed. A POST alone never means authentication success. Already-online `auto` returns without decrypting credentials. There is no retry daemon.

## Android platform notes

The existing Android source and CI are unchanged by Windows v1.3.2. Android uses a selected Wi-Fi Network, network-bound requests, Keystore-backed storage and its existing strict portal/config validation. Its system sign-in entry is permission-protected; installing the app does not force OEMs to select it. Windows bootstrap and multi-network changes are not implicitly ported to Android. See [Android usage](ANDROID.md) and [device testing](android-testing.md).

## Security limits

WHUT currently uses HTTP. DPAPI and Keystore protect storage only. IP/path/protocol/network fingerprints are defence-in-depth, not cryptographic server identity. Internet HTTP content checks can also be spoofed. Runtime and HTTP-stack memory copies cannot be guaranteed erased, and Windows routing may change after the physical trust check. No account, password, Cookie, CSRF value, complete user IP or raw authentication body is logged.
