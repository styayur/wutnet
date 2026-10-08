#!/usr/bin/env bash
set -euo pipefail

# GitHub runners no longer consistently include sdkmanager in PATH.
# Pin the last standalone SDK-manager toolchain rather than an interactive CLI shim.
sdk_root="${RUNNER_TEMP:?}/wutnet-android-sdk"
tools_zip="${RUNNER_TEMP}/wutnet-commandline-tools.zip"
curl --fail --location --retry 3 \
  https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip \
  --output "$tools_zip"
# SHA-1 as published in Google's official repository2-3.xml package manifest.
printf '%s  %s\n' '5fdcc763663eefb86a5b8879697aa6088b041e70' "$tools_zip" | sha1sum --check
mkdir -p "$sdk_root/cmdline-tools"
unzip -q "$tools_zip" -d "$sdk_root/cmdline-tools"
mv "$sdk_root/cmdline-tools/cmdline-tools" "$sdk_root/cmdline-tools/19.0"
mkdir -p "$sdk_root/licenses"
# Standard Android SDK licence acceptance for this build-only CI environment.
printf '%s\n' '24333f8a63b6825ea9c5514f83c2829b004d1fee' > "$sdk_root/licenses/android-sdk-license"
"$sdk_root/cmdline-tools/19.0/bin/sdkmanager" --sdk_root="$sdk_root" \
  'platforms;android-37.0' 'build-tools;36.0.0'
printf 'ANDROID_HOME=%s\nANDROID_SDK_ROOT=%s\n' "$sdk_root" "$sdk_root" >> "${GITHUB_ENV:?}"
