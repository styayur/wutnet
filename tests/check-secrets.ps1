#requires -Version 7.2
# Lightweight repository guard, deliberately not an exhaustive secret scanner.
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
    Write-Host 'PASS tracked secret/config/log guard and ignore rules'
}
finally { Pop-Location }
# GitHub's pwsh wrapper propagates LASTEXITCODE; git grep uses 1 for a clean scan.
exit 0
