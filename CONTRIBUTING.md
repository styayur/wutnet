# Contributing

Keep Windows PowerShell-native, CLI-first, read-only-first and minimal in runtime dependencies. Make every mutation and recovery limit explicit. Windows remains a single-file client; Android remains a separate experimental implementation. Do not weaken portal/network checks or add automatic enrollment to `auto`.


Run from PowerShell 7 on Windows; tests use synthetic credentials and mocked transport:

```powershell
pwsh -NoLogo -NoProfile -File .\tests\windows.tests.ps1
pwsh -NoLogo -NoProfile -File .\tests\check-secrets.ps1 -History
pwsh -NoLogo -NoProfile -File .\tests\check-architecture.ps1
```

Windows CI runs `Parser::ParseFile`, offline regression and the secret/local-state guard. Documentation checks are lightweight; optional Mermaid rendering remains a manual development check. Android CI runs JVM tests, Lint and a debug APK build. The secret guard is intentionally small, not an exhaustive secret scanner.



Run tests from the repository root. Do not use real credentials, authenticate the maintainer's network or install a task during automated checks. Preserve existing synthetic tests and the byte-identical versioned release script: the architecture gate intentionally checks both public Windows filenames. A source-only documentation change does not require an Android rebuild when Android inputs are unchanged.

Separate maintainer-supplied field evidence, this checkout's offline tests and future real-device acceptance. Record new observations in [field validation](docs/FIELD_VALIDATION.md), not as universal compatibility claims. Use [issues](https://github.com/styayur/wutnet/issues) for reproducible bugs and [private reporting](SECURITY.md) for vulnerabilities. Contributions retain the [MIT license](LICENSE) and [third-party attribution](THIRD_PARTY.md).
