# Contributing

Keep Windows PowerShell-native, CLI-first, read-only-first and minimal in runtime dependencies. Make every mutation and recovery limit explicit. Windows remains a single-file client; Android remains a separate experimental implementation. Do not weaken portal/network checks or add automatic enrollment to `auto`.


Run from PowerShell 7 on Windows; tests use synthetic credentials and mocked transport:

```powershell
pwsh -NoLogo -NoProfile -File .\tests\windows.tests.ps1
pwsh -NoLogo -NoProfile -File .\tests\check-secrets.ps1 -History
pwsh -NoLogo -NoProfile -File .\tests\check-architecture.ps1
Install-Module PSScriptAnalyzer -RequiredVersion 1.23.0 -Scope CurrentUser -Repository PSGallery
pwsh -NoLogo -NoProfile -File .\tests\check-powershell.ps1
pwsh -NoLogo -NoProfile -File .\tests\analyzer.tests.ps1
```

Windows CI runs `Parser::ParseFile`, offline regression, secret/local-state guard and PSScriptAnalyzer **1.23.0** on PowerShell 7.2.24 and the Windows runner version. This published analyzer version is pinned in both installation and `Import-Module -RequiredVersion`; import, invocation and Error/Warning findings fail CI. The settings are repository-owned in `PSScriptAnalyzerSettings.psd1`; production copies and all test/validation scripts are analyzed. The analyzer is a development dependency only. `tests/analyzer.tests.ps1` proves the same gate exits nonzero for an intentionally invalid verb in an isolated temporary fixture.

The rule set covers approved verbs, reserved/unsafe parameter declarations, aliases, Invoke-Expression, credential conversions, WMI, empty catches, automatic-variable assignments, unused variables/parameters and accidental built-in shadowing. Intentional interactive `Write-Host` remains allowed; `PSUseShouldProcessForStateChangingFunctions`/ShouldProcess are deferred with Phase 3, so no WhatIf/Confirm behavior is introduced. Noun pluralization/formatting rules are not part of this behavior-focused gate. Narrow suppressions explain the compatibility-only `Automatic` fingerprint argument and the private logger's compatibility-catalog false positive. Offline test files suppress only deliberate scoped command doubles/unused mock parameters and synthetic SecureString fixture conversion. Other rules remain active.

The analyzer pin is deliberate: 1.23.0 loads on the tested PowerShell 7.2.24/.NET 6 toolchain; 1.24.0's published Core assembly depends on .NET 8 despite its loader's older minimum, and 1.25.0 explicitly requires Core 7.4.6. Verify a replacement on both matrix engines before upgrading. WUTNet itself retains PowerShell 7.2+ compatibility and does not import this module.

Safe local Windows integration is separate from the mock-only suite:

```powershell
pwsh -NoLogo -NoProfile -File .\tests\windows.integration.tests.ps1
```

It starts a generated VBS against a temporary synthetic script (exit 37), and uses actual Task Scheduler COM with `TASK_VALIDATE_ONLY` to check XML. It never registers a task, decrypts a real credential or makes a campus request. WSH/VBScript or Scheduler policy restrictions cause a real failure; report the reason rather than calling it field acceptance. CI runs this separate integration step. Historical field observations stay in `docs/FIELD_VALIDATION.md`.

Documentation checks are lightweight; optional Mermaid rendering remains a manual development check. Android CI runs JVM tests, Lint and a debug APK build when Android inputs change; this Windows-only release does not rebuild/relabel an Android artifact. The secret guard is intentionally small, not an exhaustive secret scanner.



Run tests from the repository root. Do not use real credentials, authenticate the maintainer's network or install a task during automated checks. Preserve existing synthetic tests and the byte-identical versioned release script: the architecture gate intentionally checks both public Windows filenames. A source-only documentation change does not require an Android rebuild when Android inputs are unchanged.

Separate maintainer-supplied field evidence, this checkout's offline tests and future real-device acceptance. Record new observations in [field validation](docs/FIELD_VALIDATION.md), not as universal compatibility claims. Use [issues](https://github.com/styayur/wutnet/issues) for reproducible bugs and [private reporting](SECURITY.md) for vulnerabilities. Contributions retain the [MIT license](LICENSE) and [third-party attribution](THIRD_PARTY.md).
