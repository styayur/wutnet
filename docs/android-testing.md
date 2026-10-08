# Android v0.1 manual test checklist

The APK is experimental. JVM tests and lint cannot validate WHUT's current deployment,
Android Keystore on every device, or OEM captive-sign-in routing.

## Build and install

Use JDK 21 (17+ supported by AGP), Android SDK platform 37.0 and build tools 36.0.0.
Point Android Studio, `ANDROID_HOME`, or ignored `android/local.properties` at the SDK.

```sh
cd android
./gradlew test
./gradlew lint
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

On Windows use `gradlew.bat`. Debug is signed by the local Android debug key and is
installable. A different machine's debug signature cannot update an existing install
without uninstalling it (which clears credentials). `assembleRelease` produces an
unsigned, shrunk APK for inspection; it is not installable until signed. No private
signing key is requested or committed.

## Device scenarios

0. On Android 17+, use **Allow local portal access**. Test grant, denial and later revocation: denied access must stop portal requests, without a repeated permission prompt. No location/Wi-Fi-scan permission is requested.
1. Launch with no Wi-Fi or cellular only: show no usable Wi-Fi; no portal login request.
2. Open Settings. Enter a test account/password, acknowledge the HTTP disclosure, Save.
   Reopen the app: account is configured, password field empty. Do not use real secrets
   in screenshots, fixtures, adb commands or bug reports.
3. Inspect private storage in a **debug-only test installation** via `run-as`: a versioned
   binary record is in `no_backup/credential.bin` with username, 12-byte IV and GCM
   ciphertext. Password must not appear in preferences, logs, bundle state or backups.
   Clear deletes the record and Keystore alias; re-entry creates a new key/IV.
4. On unauthenticated WHUT Wi-Fi **with cellular enabled**, use Diagnostics. Check Wi-Fi
   transport/capabilities, exact portal, nasId, config API base, CSRF OK and account code.
   Diagnostics must not POST login or display Cookie/token/password values.
5. Tap Login. Require accepted POST, account status online, then same-Wi-Fi VALIDATED / HTTPS 204 / exact NCSI identity verification.
   Confirm real Internet access. Repeated Login when validated should exit without POST.
6. Invalid account/verification challenge: safe failure, no raw response or secret in UI/logcat.
7. Unknown captive portal / hostile hostname / alternate IP: refuse without decrypting.
8. Disconnect Wi-Fi during login: fail/cancel, never retry on cellular. Background the app:
   callbacks stop; no service, polling or deferred login. Return: one status operation.
9. Rotate/background while entering password: password not restored; account remains
   encrypted. Try inaccessible/corrupt ciphertext or invalidated key on a test device:
   request fresh credentials without transmitting anything.
10. Test Android 8 and a current Android device: keyboard/system-bar insets, large fonts,
    save/update/clear, exact-IP cleartext allowance, proxy bypass and network changes.

## System sign-in

Observe whether the real system sign-in notification actually launches WUTNet. Many
builds always launch their explicit system portal Activity; that is an expected limitation.
If the OEM/system routes the protected action here, verify exact `EXTRA_NETWORK` binding,
one automatic attempt using the previously acknowledged credential, account + Internet
verification, and `reportCaptivePortalDismissed()` followed by system revalidation.
Missing extras fail closed. Ordinary apps cannot invoke the protected Activity; the
launcher Activity ignores sign-in extras. Do not simulate a real system integration
success with an unprivileged `adb am start` or claim it has been proven by JVM tests.

## Most valuable v0.2 work

Run this checklist on real WHUT Wi-Fi (including cellular coexistence), record only
redacted protocol differences, and add regression fixtures. Then add device-side Keystore,
network-loss and UI lifecycle tests. Consider a user-invoked Quick Settings Tile only
after the authentication chain and OEM limitations are understood.
