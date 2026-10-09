#requires -Version 7.2
# Lightweight repository guard, deliberately not an exhaustive secret scanner.
param([switch]$History)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $tracked = @(git ls-files)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate tracked files.' }
    $badNames = @($tracked | Where-Object { $_ -match '(^|/)(credential\.dat|config\.json)$|\.log($|\.)' })
    if ($badNames.Count) { throw 'Local credentials/configuration/logs must not be tracked.' }
    foreach ($path in @('credential.dat','config.json','whut-net.log','nested/credential.dat','nested/config.json','nested/test.log')) {
        git check-ignore --no-index --quiet -- $path
        if ($LASTEXITCODE -ne 0) { throw "Missing ignore rule: $path" }
    }
    $patterns = @(
        '01000000d08c9[d]df0115d1118c7a00c04fc297eb',
        'gh[pousr]_[A-Za-z0-9]{36,}',
        'github_pat_[A-Za-z0-9_]{60,}',
        '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
    )
    foreach ($pattern in $patterns) {
        # Print no matching content: it could be a credential. git grep inspects tracked text only.
        $null = git grep -I -l -E -e $pattern -- .
        if ($LASTEXITCODE -eq 0) { throw 'Potential secret detected in tracked content; values suppressed.' }
        if ($LASTEXITCODE -ne 1) { throw 'Secret scan failed to run.' }
    }
    if ($History) {
        # Capture output in memory only. Never print possible account/secret matches.
        $historyText = (git log --all --format=fuller --patch --diff-merges=first-parent --no-ext-diff --no-color) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect repository history.' }
        foreach ($pattern in $patterns) {
            if ([regex]::IsMatch($historyText, $pattern)) { throw 'Potential secret in history; values suppressed.' }
        }
        # Student identifiers are not needed in source or fixtures. Long standalone
        # decimal identifiers require review rather than silently entering a release.
        if ($historyText -match '(?<![A-Za-z0-9])[0-9]{12,18}(?![A-Za-z0-9])') {
            throw 'Potential account identifier in history; values suppressed.'
        }
        $localConfig = Join-Path $env:LOCALAPPDATA 'WHUT-Net/config.json'
        if (Test-Path -LiteralPath $localConfig) {
            $localAccount = [string]((Get-Content -LiteralPath $localConfig -Raw | ConvertFrom-Json).username)
            if (-not [string]::IsNullOrWhiteSpace($localAccount)) {
                if ($historyText.Contains($localAccount)) { throw 'Local account identifier found in history; value suppressed.' }
                Write-Host 'PASS exact local account identifier absent from history'
            }
            $localAccount = $null
        }
        else { Write-Host 'INFO local account config unavailable; historical identifier-pattern scan applied' }
        $historyText = $null
        Write-Host 'PASS reachable Git history secret/account guard'
    }
    Write-Host 'PASS tracked secret/config/log guard and ignore rules'
}
finally { Pop-Location }
# GitHub's pwsh wrapper propagates LASTEXITCODE; git grep uses 1 for a clean scan.
exit 0
