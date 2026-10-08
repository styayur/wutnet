# WHUT Portal protocol

This document records the observed protocol implemented by the existing root
[`whut-net.ps1`](../whut-net.ps1) and the Android client. It is not an official WHUT
specification. Full captive-session field validation remains pending on both platforms.

## Discovery and trust

Windows uses a direct Internet identity probe (`Microsoft Connect Test`, with a
NeverSSL page-identity fallback), then discovers an HTTP redirect from
`http://neverssl.com/`. Android first inspects the **selected Wi-Fi Network's**
`VALIDATED` / `CAPTIVE_PORTAL` capabilities; neither the cellular default route nor
HTTP 200 alone establishes Internet connectivity. Without a captive flag or validated
capability, a network-bound HTTPS 204 probe is a fallback.

Android accepts a system portal URL only as an untrusted hint, or reads one redirect
from the NeverSSL probe. It never follows an arbitrary external redirect. Android
rejects probe-relative redirects that do not immediately resolve to the exact WHUT
portal. Windows additionally permits bounded same-host discovery redirects.

The observed WHUT portal is:

```text
http://172.30.21.100/tpl/whut/login.html?nasId=<session-specific-value>
```

Android requires HTTP, host exactly `172.30.21.100`, default port or 80, no userinfo,
no fragment, and raw path exactly `/tpl/whut/login.html`. It rejects suffix hostnames,
other private IPs, encoded/normalised lookalike paths, HTTPS hints, and alternate ports.
Windows retains its existing allowlist (HTTP/HTTPS default ports and its existing
path comparison). No Windows code was changed for the Android MVP.

`nasId` is discovered anew for each operation, URL-decoded, and submitted as a login
field. Android requires exactly one nonblank value, limits its length, and rejects
control characters. It is not an account identifier, password, Cookie or CSRF token;
diagnostics may show it locally. Do not upload diagnostic dumps containing local state.

## Session and API discovery

1. GET the validated portal page to establish cookies.
2. GET `/tpl/whut/static/js/config.js` on that same origin.
3. Extract `host_url = '/api'` (single/double quotes), which supplies the API base path.
4. GET `<base>/csrf-token`, with the portal Referer.
5. Parse the JSON `csrf_token` string and retain it only within this operation.

Android requires an unambiguous `host_url` assignment. A base is an ASCII absolute
path containing segment characters `[A-Za-z0-9._~-]`; `..`, `//`, percent escapes,
backslashes, queries, fragments, scheme/host and root-only paths are rejected.
Missing config structure fails closed. Windows preserves its existing `/api` fallback
when config discovery fails. This deliberate Android tightening affects discovery,
not the meaning of any authentication field.

Android maintains a per-operation Java `CookieManager` accepting only original-server
cookies. There is no global CookieHandler. Each portal request sends appropriate
cookies; probes receive no portal Cookie or CSRF header. All endpoint redirects are
rejected, and the cookie jar is discarded after the finite operation.

## Account status and login

GET `<base>/account/status?token=null`, with:

```text
Accept: application/json, */*
Referer: <validated portal URL>
X-Requested-With: XMLHttpRequest
X-Csrf-Token: <operation token>
Cookie: <session cookies, if any>
```

Require HTTP 200 plus a well-formed JSON object with a numeric integer `code`.
`code == 0` means the WHUT account reports online; other codes mean not online.
Server `msg` strings are not trusted UI/log content. Additional fields are ignored.
Android rejects missing, duplicate, nested-only, string, boolean and noninteger codes.

After portal, config, CSRF and status fingerprints pass, and only if offline and login
is requested, decrypt the saved password. POST `<base>/account/login` on the validated
origin, with the preceding headers plus `Origin: http://172.30.21.100` and
`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`.

| Form field | Value |
| --- | --- |
| `username` | User-entered campus account |
| `password` | Decrypted password; never persist plaintext |
| `swtichip` | Empty string; spelling intentionally matches the observed API |
| `nasId` | Newly discovered session value |
| `userIpv4` | Empty string |
| `userMac` | Empty string |
| `captcha` | Empty string |
| `captchaId` | Empty string |

HTTP 200 is insufficient. The login JSON must contain numeric `code == 0`; nonzero
codes fail, including code 2 (additional verification may be required). Android v0.1
does not solve CAPTCHAs or bypass verification.

## Success and Internet verification

After successful POST, GET account status again and require `code == 0`. Android
then checks the **same Wi-Fi** VALIDATED capability or GETs `https://connectivitycheck.gstatic.com/generate_204` over that Wi-Fi,
with redirects disabled and platform TLS validation; require HTTP 204. If filtered, a single credential-free HTTP NCSI probe at `http://www.msftconnecttest.com/connecttest.txt` requires status 200 **and the exact body** `Microsoft Connect Test` (the Windows identity check). This HTTP fingerprint can be spoofed by a hostile network and is not cryptographic verification. If all capability/probe checks fail,
the operation reports verification failure even if the account is online. Windows
uses its existing direct Internet identity probes. Neither client reports full login
success based on a POST response alone.

For an already online account, Android still verifies Wi-Fi Internet before reporting
authenticated. An already `VALIDATED` non-captive Wi-Fi can exit as `Online` without
contacting WHUT. Android calls `reportCaptivePortalDismissed()` only after verified
account/Internet success, and only when the system supplied a CaptivePortal handle.
The system then performs its own revalidation; the app cannot force a default route.

## Android network and system integration

`ConnectivityManager` selects an existing Wi-Fi, preferring a unique captive network;
a system-supplied `EXTRA_NETWORK` must itself be a usable Wi-Fi. No SSID/location
permission is needed. Android 17+ (target 37) additionally requires the explicit `ACCESS_LOCAL_NETWORK` runtime grant to reach the private-IP portal; denial stops local requests. This does not enable SSID access or Wi-Fi scanning. An ambiguous or unavailable selection safely fails. Every
request uses `Network.openConnection(url, Proxy.NO_PROXY)`. No global process binding,
cellular fallback, Wi-Fi scanning, persistent service or periodic worker exists.
Foreground callbacks are unregistered and operations cancelled when the Activity stops.

The exported compatibility Activity handles `ACTION_CAPTIVE_PORTAL_SIGN_IN` with
`EXTRA_NETWORK`, `EXTRA_CAPTIVE_PORTAL` and an optional URL hint. It requires the
signature system permission `CONNECTIVITY_INTERNAL` **on callers**, not as an app
permission request. This prevents ordinary apps triggering saved-password login.
Many Android/OEM builds explicitly launch their own captive portal component and
will never route this action to WUTNet. The manifest filter does not make WUTNet a
default handler. Manual launch/login is the reliable MVP entry point; no privileged
workaround is attempted.

## Security limits

WHUT's current portal uses **HTTP**. Credentials and session material travel without
transport encryption. DPAPI/Keystore protect storage only; IP/path/config/API fingerprints
are defence in depth, not cryptographic proof of server identity. A hostile access point
can impersonate these fingerprints. Only use an authorised account on trusted WHUT Wi-Fi.

Android's Network Security Config disables cleartext by default and explicitly lists
the portal IP and two credential-free discovery probe hosts. A domain-config entry for
a numeric IP is not a network firewall and may vary by OEM; the application validates
every destination as well. No global cleartext opt-in is used.

No passwords, Cookie values, CSRF values, POST bodies or raw portal messages are logged.
Android has no persistent diagnostic log and no release verbose logging. Mutable
password/POST buffers are wiped, but JVM/ART immutable encoding Strings cannot be
reliably zeroed. Keystore decryption failure requires re-entry, never a plaintext fallback.

References: [ConnectivityManager](https://developer.android.com/reference/android/net/ConnectivityManager#ACTION_CAPTIVE_PORTAL_SIGN_IN),
[Network.openConnection](https://developer.android.com/reference/android/net/Network#openConnection(java.net.URL,%20java.net.Proxy)),
[CaptivePortal](https://developer.android.com/reference/android/net/CaptivePortal),
[Network Security Config](https://developer.android.com/privacy-and-security/security-config),
[Android Keystore](https://developer.android.com/privacy-and-security/keystore).
