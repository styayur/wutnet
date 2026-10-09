# Android client — existing experimental implementation

Historical Android v0.1 notes. The Windows v1.3.2 release does not change Android behavior.

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

See the [device/manual testing checklist](android-testing.md) for cellular coexistence, network loss, credential storage and real system-entry verification. The most valuable next step is real WHUT field validation followed by device-side regression tests; a Quick Settings Tile remains a possible v0.2 addition.
