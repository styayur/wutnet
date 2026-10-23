#requires -Version 7.2
#requires -PSEdition Core
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module PSScriptAnalyzer -RequiredVersion 1.24.0 -ErrorAction Stop
$paths = @(Get-ChildItem $root -Filter 'whut-net*.ps1') + @(Get-ChildItem $PSScriptRoot -Filter '*.ps1')
$findings = @(foreach ($path in $paths) {
    Invoke-ScriptAnalyzer -Path $path.FullName -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1') -Severity Error,Warning -ErrorAction Stop
})
if ($findings.Count) {
    $findings | Format-Table ScriptName, Line, RuleName, Message -Wrap | Out-Host
    throw "PSScriptAnalyzer 1.24.0: $($findings.Count) Error/Warning findings."
}
Write-Host "PASS PSScriptAnalyzer 1.24.0: $($paths.Count) scripts; zero Error/Warning findings"
exit 0
