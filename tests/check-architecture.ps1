#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$evidence = Get-Content (Join-Path $root 'docs/architecture/evidence.json') -Raw | ConvertFrom-Json
$readme = Get-Content (Join-Path $root $evidence.diagram_source) -Raw
$blocks = [regex]::Matches($readme, '(?s)<!-- architecture:overview:start -->\s*```mermaid\s*\n(.*?)\n```\s*<!-- architecture:overview:end -->')
if ($blocks.Count -ne 1) { throw 'Expected one authoritative architecture diagram.' }
foreach ($source in $evidence.sources) {
    $text = Get-Content (Join-Path $root $source.path) -Raw
    foreach ($anchor in $source.anchors) {
        if (-not $text.Contains($anchor)) { throw "Missing architecture source anchor: $anchor" }
    }
}
$markdowns = @((Join-Path $root 'README.md')) + @(Get-ChildItem (Join-Path $root 'docs') -Recurse -Filter *.md | ForEach-Object FullName)
$linkCount = 0
foreach ($markdown in $markdowns) {
    $text = [regex]::Replace((Get-Content -LiteralPath $markdown -Raw), '(?s)```.*?```', '')
    foreach ($match in [regex]::Matches($text, '!?\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)')) {
        $target = $match.Groups[1].Value
        if ($target -match '^[A-Za-z][A-Za-z0-9+.-]*:|^//|^#') { continue }
        $path = [Uri]::UnescapeDataString(($target -split '[?#]',2)[0])
        $resolved = Join-Path (Split-Path -Parent $markdown) $path
        if (-not (Test-Path -LiteralPath $resolved)) { throw "Missing documentation link: $target" }
        $linkCount++
    }
}
$scripts = @((Join-Path $root 'whut-net.ps1')) + @(Get-ChildItem $PSScriptRoot -Filter *.ps1 | ForEach-Object FullName)
foreach ($file in $scripts) {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "PowerShell syntax errors in $file" }
}
$scriptText = Get-Content (Join-Path $root 'whut-net.ps1') -Raw
$version = [regex]::Match($scriptText, '\$Script:Version = ''([^'']+)''').Groups[1].Value
if ($version -ne '1.3.2' -or -not $readme.Contains("v$version") -or $evidence.source_version -ne "v$version") {
    throw 'Release version/documentation mismatch.'
}
$helpText = & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File (Join-Path $root 'whut-net.ps1') help
if ($LASTEXITCODE -ne 0 -or ($helpText -join "`n") -notmatch [regex]::Escape("WHUT-Net v$version")) {
    throw 'Versioned help failed.'
}
Write-Host "PASS architecture anchors, $linkCount local links, syntax and v$version help"
exit 0
