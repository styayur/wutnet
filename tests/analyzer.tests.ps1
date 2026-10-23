#requires -Version 7.2
#requires -PSEdition Core
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('whut-analyzer-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
try {
    [void][IO.Directory]::CreateDirectory((Join-Path $fixture 'tests'))
    Copy-Item -LiteralPath (Join-Path $root 'PSScriptAnalyzerSettings.psd1') -Destination $fixture
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'check-powershell.ps1') -Destination (Join-Path $fixture 'tests/check-powershell.ps1')
    [IO.File]::WriteAllText((Join-Path $fixture 'whut-net.ps1'), 'function Frobnicate-Synthetic { param() }')
    $output = & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File (Join-Path $fixture 'tests/check-powershell.ps1') 2>&1
    if ($LASTEXITCODE -eq 0 -or ($output -join "`n") -notmatch 'PSUseApprovedVerbs') {
        throw 'Analyzer gate did not reject the deliberately unapproved synthetic verb'
    }
    Write-Host 'PASS analyzer gate returns nonzero for synthetic rule violation'
}
finally {
    # Remove only the explicit fixture files and now-empty directories.
    Remove-Item -LiteralPath (Join-Path $fixture 'whut-net.ps1'),(Join-Path $fixture 'PSScriptAnalyzerSettings.psd1'),(Join-Path $fixture 'tests/check-powershell.ps1') -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $fixture 'tests'),$fixture
}
exit 0
