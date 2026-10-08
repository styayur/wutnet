#requires -Version 7.2
#requires -PSEdition Core
<#
.SYNOPSIS
    WHUT-Net v0.1 - Lightweight Wuhan University of Technology campus network authenticator.

.DESCRIPTION
    Windows-only, zero third-party dependency PowerShell client for the WHUT captive portal.
    Features:
      - Direct HTTP with proxy bypass (UseProxy = false)
      - Strict WHUT portal allowlist before credentials are sent
      - Dynamic nasId discovery
      - Dynamic API base path discovery from config.js
      - CSRF + cookie session handling
      - DPAPI-protected password storage (CurrentUser)
      - Login / status / auto / diagnose
      - Optional Task Scheduler integration (logon + network-connect event)

    The current WHUT portal uses HTTP. DPAPI protects the password at rest, but cannot
    add transport encryption to a server that only exposes HTTP.

.NOTES
    Version: 0.1.0-alpha.1
    Target: PowerShell 7.2+ on Windows 10/11
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'setup', 'status', 'login', 'auto', 'diagnose', 'install', 'uninstall')]
    [string]$Command = 'help',

    [string]$Username
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:Version = '0.1.0-alpha.1'
$Script:AllowedPortalHosts = @('172.30.21.100')
$Script:ExpectedPortalPath = '/tpl/whut/login.html'
$Script:PortalConfigPath = '/tpl/whut/static/js/config.js'
$Script:DefaultApiBasePath = '/api'
$Script:InternetProbeUri = [Uri]'http://www.msftconnecttest.com/connecttest.txt'
$Script:InternetProbeExpected = 'Microsoft Connect Test'
$Script:PortalProbeUri = [Uri]'http://neverssl.com/'
$Script:RequestTimeoutSeconds = 5
$Script:TaskName = 'WHUT-Net AutoLogin'

if (-not $IsWindows) {
    Write-Error 'WHUT-Net v0.1 is Windows-only because credential protection uses Windows DPAPI.'
    exit 50
}

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    Write-Error 'LOCALAPPDATA is unavailable.'
    exit 50
}

$Script:DataDir = Join-Path $env:LOCALAPPDATA 'WHUT-Net'
$Script:ConfigPath = Join-Path $Script:DataDir 'config.json'
$Script:CredentialPath = Join-Path $Script:DataDir 'credential.dat'
$Script:LogPath = Join-Path $Script:DataDir 'whut-net.log'

function New-WhutException {
    param(
        [Parameter(Mandatory)]
        [int]$ExitCode,
        [Parameter(Mandatory)]
        [string]$Message
    )
    $exception = [System.Exception]::new($Message)
    $exception.Data['ExitCode'] = $ExitCode
    return $exception
}

function Throw-Whut {
    param(
        [Parameter(Mandatory)]
        [int]$ExitCode,
        [Parameter(Mandatory)]
        [string]$Message
    )
    throw (New-WhutException -ExitCode $ExitCode -Message $Message)
}

function Ensure-DataDirectory {
    if (-not (Test-Path -LiteralPath $Script:DataDir)) {
        New-Item -ItemType Directory -Path $Script:DataDir -Force | Out-Null
    }
}

function Get-ObjectProperty {
    param(
        [Parameter(Mandatory)]
        $Object,
        [Parameter(Mandatory)]
        [string]$Name,
        $Default = $null
    )

    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Get-ActivePhysicalNetworkProfiles {
    try {
        $physicalIndexes = @(
            Get-NetAdapter -Physical -ErrorAction Stop |
                Where-Object { $_.Status -eq 'Up' } |
                ForEach-Object { [int]$_.ifIndex }
        )

        if ($physicalIndexes.Count -eq 0) { return @() }

        return @(
            Get-NetConnectionProfile -ErrorAction Stop |
                Where-Object { $physicalIndexes -contains [int]$_.InterfaceIndex } |
                ForEach-Object { [string]$_.Name } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object -Unique
        )
    }
    catch {
        return @()
    }
}

function Test-TrustedLocalNetwork {
    param(
        [Parameter(Mandatory)]
        $Config
    )

    $trusted = @(Get-ObjectProperty -Object $Config -Name 'trustedProfiles' -Default @())
    if ($trusted.Count -eq 0) { return $null }

    $active = @(Get-ActivePhysicalNetworkProfiles)
    foreach ($profile in $active) {
        if ($trusted -contains $profile) {
            return $true
        }
    }

    return $false
}

function Write-Log {
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory)]
        [string]$Message,
        [switch]$Quiet
    )

    Ensure-DataDirectory

    $safeMessage = ($Message -replace '[\r\n]+', ' ').Trim()
    $line = '{0} {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $safeMessage

    try {
        if (Test-Path -LiteralPath $Script:LogPath) {
            $length = (Get-Item -LiteralPath $Script:LogPath).Length
            if ($length -ge 1MB) {
                $old = "$($Script:LogPath).1"
                Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $Script:LogPath -Destination $old -Force
            }
        }
        Add-Content -LiteralPath $Script:LogPath -Value $line -Encoding utf8
    }
    catch {
        # Logging must never break authentication.
    }

    if (-not $Quiet) {
        switch ($Level) {
            'ERROR' { Write-Host "[ERROR] $safeMessage" -ForegroundColor Red }
            'WARN'  { Write-Host "[WARN]  $safeMessage" -ForegroundColor Yellow }
            default { Write-Host "[INFO]  $safeMessage" }
        }
    }
}

function Read-Config {
    if (-not (Test-Path -LiteralPath $Script:ConfigPath)) {
        Throw-Whut 50 "Configuration not found. Run: .\whut-net.ps1 setup"
    }

    try {
        $config = Get-Content -LiteralPath $Script:ConfigPath -Raw -Encoding utf8 | ConvertFrom-Json
    }
    catch {
        Throw-Whut 50 'Configuration file is invalid.'
    }

    $storedUsername = Get-ObjectProperty -Object $config -Name 'username'
    if ($null -eq $storedUsername -or [string]::IsNullOrWhiteSpace([string]$storedUsername)) {
        Throw-Whut 50 'Configuration is missing username.'
    }

    return $config
}

function Read-ProtectedPassword {
    if (-not (Test-Path -LiteralPath $Script:CredentialPath)) {
        Throw-Whut 50 "Credential not found. Run: .\whut-net.ps1 setup"
    }

    try {
        $encrypted = (Get-Content -LiteralPath $Script:CredentialPath -Raw -Encoding utf8).Trim()
        if ([string]::IsNullOrWhiteSpace($encrypted)) {
            throw 'empty credential'
        }
        return ($encrypted | ConvertTo-SecureString)
    }
    catch {
        Throw-Whut 50 'Credential cannot be decrypted for the current Windows user. Run setup again.'
    }
}

function ConvertTo-PlainText {
    param(
        [Parameter(Mandatory)]
        [Security.SecureString]$SecureString
    )

    $bstr = [IntPtr]::Zero
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function New-HttpContext {
    param(
        [switch]$AllowAutoRedirect
    )

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = [bool]$AllowAutoRedirect
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $handler.AutomaticDecompression = (
        [System.Net.DecompressionMethods]::GZip -bor
        [System.Net.DecompressionMethods]::Deflate
    )

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($Script:RequestTimeoutSeconds)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/140.0 Safari/537.36'
    )

    return [pscustomobject]@{
        Handler = $handler
        Client  = $client
        Cookies = $handler.CookieContainer
    }
}

function Close-HttpContext {
    param($Context)
    if ($null -ne $Context -and $null -ne $Context.Client) {
        $Context.Client.Dispose()
    }
}

function New-FormContent {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Form
    )

    $pairs = [System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]]::new()
    foreach ($key in $Form.Keys) {
        $value = if ($null -eq $Form[$key]) { '' } else { [string]$Form[$key] }
        $pairs.Add(
            [System.Collections.Generic.KeyValuePair[string,string]]::new([string]$key, $value)
        )
    }

    return [System.Net.Http.FormUrlEncodedContent]::new($pairs)
}

function Invoke-HttpText {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory)]
        [Uri]$Uri,
        [hashtable]$Headers = @{},
        [hashtable]$Form
    )

    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method),
        $Uri
    )

    try {
        foreach ($entry in $Headers.GetEnumerator()) {
            [void]$request.Headers.TryAddWithoutValidation([string]$entry.Key, [string]$entry.Value)
        }

        if ($PSBoundParameters.ContainsKey('Form')) {
            $request.Content = New-FormContent -Form $Form
        }

        $response = $Context.Client.SendAsync(
            $request,
            [System.Net.Http.HttpCompletionOption]::ResponseContentRead
        ).GetAwaiter().GetResult()

        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $location = $null
            if ($null -ne $response.Headers.Location) {
                $location = $response.Headers.Location
            }

            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Body       = [string]$body
                Location   = $location
            }
        }
        finally {
            $response.Dispose()
        }
    }
    finally {
        $request.Dispose()
    }
}

function Test-TrustedPortalUri {
    param(
        [Parameter(Mandatory)]
        [Uri]$Uri
    )

    if ($Uri.Scheme -notin @('http', 'https')) { return $false }
    if (-not [string]::IsNullOrEmpty($Uri.UserInfo)) { return $false }
    if ($Script:AllowedPortalHosts -notcontains $Uri.Host) { return $false }

    if (-not $Uri.IsDefaultPort) {
        if (($Uri.Scheme -eq 'http' -and $Uri.Port -ne 80) -or
            ($Uri.Scheme -eq 'https' -and $Uri.Port -ne 443)) {
            return $false
        }
    }

    return ($Uri.AbsolutePath.TrimEnd('/') -eq $Script:ExpectedPortalPath.TrimEnd('/'))
}

function Test-SafeApiBasePath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not $Path.StartsWith('/')) { return $false }
    if ($Path.Contains('..') -or $Path.Contains('\') -or $Path.Contains('?') -or
        $Path.Contains('#') -or $Path.Contains(':')) {
        return $false
    }

    return ($Path -match '^/[A-Za-z0-9._~/-]*$')
}

function Get-QueryValue {
    param(
        [Parameter(Mandatory)]
        [Uri]$Uri,
        [Parameter(Mandatory)]
        [string]$Name
    )

    $query = $Uri.Query.TrimStart('?')
    if ([string]::IsNullOrWhiteSpace($query)) { return $null }

    foreach ($part in $query -split '&') {
        if ([string]::IsNullOrEmpty($part)) { continue }

        $kv = $part -split '=', 2
        $key = [Uri]::UnescapeDataString(($kv[0] -replace '\+', ' '))
        if ($key -eq $Name) {
            if ($kv.Count -eq 1) { return '' }
            return [Uri]::UnescapeDataString(($kv[1] -replace '\+', ' '))
        }
    }

    return $null
}

function Get-Origin {
    param(
        [Parameter(Mandatory)]
        [Uri]$Uri
    )
    return '{0}://{1}' -f $Uri.Scheme, $Uri.Authority
}

function Test-Internet {
    $context = $null
    try {
        $context = New-HttpContext

        $result = Invoke-HttpText -Context $context -Method GET -Uri $Script:InternetProbeUri
        if ($result.StatusCode -eq 200 -and
            $result.Body.Trim() -eq $Script:InternetProbeExpected) {
            return $true
        }

        # Fallback: useful when Windows NCSI itself is filtered. A captive portal may
        # return HTTP 200 too, so require NeverSSL's page identity, not status alone.
        $fallback = Invoke-HttpText -Context $context -Method GET -Uri $Script:PortalProbeUri
        return (
            $fallback.StatusCode -eq 200 -and
            $fallback.Body -match '(?i)<title>\s*NeverSSL'
        )
    }
    catch {
        return $false
    }
    finally {
        Close-HttpContext $context
    }
}

function Find-WhutPortal {
    $context = $null
    try {
        $context = New-HttpContext
        $current = $Script:PortalProbeUri

        for ($i = 0; $i -lt 5; $i++) {
            $result = Invoke-HttpText -Context $context -Method GET -Uri $current

            if ($result.StatusCode -ge 300 -and $result.StatusCode -lt 400) {
                if ($null -eq $result.Location) {
                    Throw-Whut 11 'Redirect received without a Location header.'
                }

                $candidate = if ($result.Location.IsAbsoluteUri) {
                    [Uri]$result.Location
                }
                else {
                    [Uri]::new($current, $result.Location)
                }

                if (Test-TrustedPortalUri -Uri $candidate) {
                    return $candidate
                }

                # Only follow a benign relative/same-host redirect from the probe itself.
                if ($candidate.Scheme -eq 'http' -and $candidate.Host -eq $current.Host) {
                    $current = $candidate
                    continue
                }

                Throw-Whut 12 "Captive portal redirect is not trusted: $($candidate.Host)"
            }

            if ($result.StatusCode -eq 200) {
                return $null
            }

            if ($result.StatusCode -ge 400) {
                Throw-Whut 30 "Portal discovery probe returned HTTP $($result.StatusCode)."
            }

            return $null
        }

        Throw-Whut 11 'Portal discovery exceeded redirect limit.'
    }
    catch [System.Net.Http.HttpRequestException] {
        Throw-Whut 40 'Portal discovery network error.'
    }
    catch [System.Threading.Tasks.TaskCanceledException] {
        Throw-Whut 40 'Portal discovery timed out.'
    }
    finally {
        Close-HttpContext $context
    }
}

function Start-WhutSession {
    param(
        [Parameter(Mandatory)]
        [Uri]$PortalUri
    )

    if (-not (Test-TrustedPortalUri -Uri $PortalUri)) {
        Throw-Whut 12 'Refusing to start a session with an untrusted portal.'
    }

    $context = New-HttpContext

    try {
        $headers = @{
            'Accept'     = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            'Referer'    = (Get-Origin -Uri $PortalUri) + '/'
        }

        $result = Invoke-HttpText -Context $context -Method GET -Uri $PortalUri -Headers $headers
        if ($result.StatusCode -ne 200) {
            Close-HttpContext $context
            Throw-Whut 30 "WHUT portal handshake failed with HTTP $($result.StatusCode)."
        }

        return $context
    }
    catch {
        Close-HttpContext $context
        throw
    }
}

function Get-ApiBasePath {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        [Uri]$PortalUri
    )

    $origin = Get-Origin -Uri $PortalUri
    $configUri = [Uri]::new($origin + $Script:PortalConfigPath)

    $result = Invoke-HttpText -Context $Context -Method GET -Uri $configUri -Headers @{
        'Accept'  = '*/*'
        'Referer' = $PortalUri.AbsoluteUri
    }

    if ($result.StatusCode -eq 200) {
        $match = [regex]::Match(
            $result.Body,
            'host_url\s*=\s*[''"]([^''"]+)[''"]',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )

        if ($match.Success) {
            $path = $match.Groups[1].Value.Trim()
            if (Test-SafeApiBasePath -Path $path) {
                return $path.TrimEnd('/')
            }

            Throw-Whut 12 'config.js returned an unsafe API base path.'
        }
    }

    Write-Log WARN "Could not dynamically read API base path; falling back to $Script:DefaultApiBasePath."
    return $Script:DefaultApiBasePath
}

function Get-CsrfToken {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        [Uri]$PortalUri,
        [Parameter(Mandatory)]
        [string]$ApiBasePath
    )

    if (-not (Test-SafeApiBasePath -Path $ApiBasePath)) {
        Throw-Whut 12 'Unsafe API base path.'
    }

    $origin = Get-Origin -Uri $PortalUri
    $uri = [Uri]::new($origin + $ApiBasePath + '/csrf-token')

    try {
        $result = Invoke-HttpText -Context $Context -Method GET -Uri $uri -Headers @{
            'Accept'  = 'application/json, */*'
            'Referer' = $PortalUri.AbsoluteUri
        }

        if ($result.StatusCode -ne 200) {
            Throw-Whut 22 "CSRF endpoint returned HTTP $($result.StatusCode)."
        }

        $data = $result.Body | ConvertFrom-Json
        $token = [string](Get-ObjectProperty -Object $data -Name 'csrf_token' -Default '')
        if ([string]::IsNullOrWhiteSpace($token)) {
            Throw-Whut 22 'CSRF endpoint did not return csrf_token.'
        }

        return $token
    }
    catch [System.Management.Automation.RuntimeException] {
        Throw-Whut 22 'CSRF response is not valid JSON.'
    }
}

function Get-WhutAccountStatus {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        [Uri]$PortalUri,
        [Parameter(Mandatory)]
        [string]$ApiBasePath,
        [Parameter(Mandatory)]
        [string]$CsrfToken
    )

    $origin = Get-Origin -Uri $PortalUri
    $uri = [Uri]::new($origin + $ApiBasePath + '/account/status?token=null')

    $result = Invoke-HttpText -Context $Context -Method GET -Uri $uri -Headers @{
        'Accept'           = 'application/json, */*'
        'Referer'          = $PortalUri.AbsoluteUri
        'X-Requested-With' = 'XMLHttpRequest'
        'X-Csrf-Token'     = $CsrfToken
    }

    if ($result.StatusCode -ne 200) {
        Throw-Whut 30 "Account status endpoint returned HTTP $($result.StatusCode)."
    }

    try {
        $data = $result.Body | ConvertFrom-Json
        $code = Get-ObjectProperty -Object $data -Name 'code'
        if ($null -eq $code) {
            Throw-Whut 30 'Account status response is missing code.'
        }
        return $data
    }
    catch {
        if ($null -ne $_.Exception.Data['ExitCode']) { throw }
        Throw-Whut 30 'Account status response is not valid JSON.'
    }
}

function Invoke-WhutLogin {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        [Uri]$PortalUri,
        [Parameter(Mandatory)]
        [string]$ApiBasePath,
        [Parameter(Mandatory)]
        [string]$CsrfToken,
        [Parameter(Mandatory)]
        [string]$NasId,
        [Parameter(Mandatory)]
        [string]$User,
        [Parameter(Mandatory)]
        [Security.SecureString]$Password
    )

    if (-not (Test-TrustedPortalUri -Uri $PortalUri)) {
        Throw-Whut 12 'Refusing to send credentials to an untrusted portal.'
    }

    $origin = Get-Origin -Uri $PortalUri
    $uri = [Uri]::new($origin + $ApiBasePath + '/account/login')
    $plainPassword = $null

    try {
        $plainPassword = ConvertTo-PlainText -SecureString $Password

        $result = Invoke-HttpText -Context $Context -Method POST -Uri $uri -Headers @{
            'Accept'           = 'application/json, */*'
            'Referer'          = $PortalUri.AbsoluteUri
            'Origin'           = $origin
            'X-Requested-With' = 'XMLHttpRequest'
            'X-Csrf-Token'     = $CsrfToken
        } -Form @{
            'username'  = $User
            'password'  = $plainPassword
            'swtichip'  = ''
            'nasId'     = $NasId
            'userIpv4'  = ''
            'userMac'   = ''
            'captcha'   = ''
            'captchaId' = ''
        }

        if ($result.StatusCode -ne 200) {
            Throw-Whut 20 "Login endpoint returned HTTP $($result.StatusCode)."
        }

        try {
            $data = $result.Body | ConvertFrom-Json
        }
        catch {
            Throw-Whut 20 'Login response is not valid JSON.'
        }

        $rawCode = Get-ObjectProperty -Object $data -Name 'code'
        if ($null -eq $rawCode) {
            Throw-Whut 20 'Login response is missing code.'
        }

        $code = [int]$rawCode
        if ($code -ne 0) {
            # Existing WHUT implementations document code 2 as a verification/code failure.
            if ($code -eq 2) {
                Throw-Whut 21 'Login requires additional verification or code check.'
            }

            Throw-Whut 20 "Authentication rejected (code $code)."
        }

        return $data
    }
    finally {
        # Managed strings cannot be reliably zeroed, so keep plaintext lifetime minimal.
        $plainPassword = $null
    }
}

function Resolve-PortalSession {
    $portal = Find-WhutPortal
    if ($null -eq $portal) {
        Throw-Whut 11 'WHUT captive portal was not discovered.'
    }

    if (-not (Test-TrustedPortalUri -Uri $portal)) {
        Throw-Whut 12 'Discovered captive portal is not trusted.'
    }

    $nasId = Get-QueryValue -Uri $portal -Name 'nasId'
    if ([string]::IsNullOrWhiteSpace($nasId)) {
        Throw-Whut 11 'WHUT portal URL did not contain nasId.'
    }

    $session = Start-WhutSession -PortalUri $portal

    try {
        $apiBase = Get-ApiBasePath -Context $session -PortalUri $portal
        $csrf = Get-CsrfToken -Context $session -PortalUri $portal -ApiBasePath $apiBase

        return [pscustomobject]@{
            Portal      = $portal
            NasId       = $nasId
            ApiBasePath = $apiBase
            CsrfToken   = $csrf
            Session     = $session
        }
    }
    catch {
        Close-HttpContext $session
        throw
    }
}

function Invoke-StatusCommand {
    if (Test-Internet) {
        Write-Log INFO 'ONLINE: direct Internet probe succeeded.'
        return 0
    }

    $resolved = $null
    try {
        $resolved = Resolve-PortalSession
        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        if ([int](Get-ObjectProperty -Object $status -Name 'code') -eq 0) {
            Write-Log WARN 'WHUT account reports ONLINE, but the direct Internet probe failed.'
            return 40
        }

        Write-Log INFO 'PORTAL: account is not online.'
        return 10
    }
    finally {
        if ($null -ne $resolved) {
            Close-HttpContext $resolved.Session
        }
    }
}

function Invoke-LoginCommand {
    param(
        [switch]$Automatic
    )

    if (Test-Internet) {
        Write-Log INFO 'ONLINE: no authentication needed.'
        return 0
    }

    $resolved = $null
    try {
        $resolved = Resolve-PortalSession
        Write-Log INFO 'Trusted WHUT portal discovered.'

        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        if ([int](Get-ObjectProperty -Object $status -Name 'code') -eq 0) {
            if (Test-Internet) {
                Write-Log INFO 'ONLINE: account and Internet probes both succeeded.'
                return 0
            }

            Write-Log WARN 'Account is authenticated, but Internet connectivity is unavailable.'
            return 40
        }

        $config = Read-Config
        $trustedNetwork = Test-TrustedLocalNetwork -Config $config
        if ($trustedNetwork -eq $false) {
            Throw-Whut 12 'Current physical Windows network profile is not trusted. Run setup again while connected to WHUT.'
        }
        if ($Automatic -and $null -eq $trustedNetwork) {
            Throw-Whut 12 'Automatic login requires a captured trusted physical network profile. Run setup again while connected to WHUT.'
        }

        $password = Read-ProtectedPassword

        [void](Invoke-WhutLogin `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken `
            -NasId $resolved.NasId `
            -User ([string](Get-ObjectProperty -Object $config -Name 'username')) `
            -Password $password)

        Start-Sleep -Milliseconds 750

        $verified = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        if ([int](Get-ObjectProperty -Object $verified -Name 'code') -ne 0) {
            Throw-Whut 20 'Login endpoint accepted the request, but account status verification failed.'
        }

        if (-not (Test-Internet)) {
            Throw-Whut 40 'WHUT authentication succeeded, but the Internet probe still fails.'
        }

        Write-Log INFO 'Authentication successful; Internet connectivity verified.'
        return 0
    }
    finally {
        if ($null -ne $resolved) {
            Close-HttpContext $resolved.Session
        }
    }
}

function Invoke-DiagnoseCommand {
    Write-Host "WHUT-Net v$Script:Version diagnostics"
    Write-Host ('-' * 52)
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
    Write-Host "Config:     $(if (Test-Path -LiteralPath $Script:ConfigPath) { 'present' } else { 'missing' })"
    Write-Host "Credential: $(if (Test-Path -LiteralPath $Script:CredentialPath) { 'present (DPAPI)' } else { 'missing' })"
    Write-Host "HTTP_PROXY: $(if ([string]::IsNullOrWhiteSpace($env:HTTP_PROXY)) { 'not set' } else { 'set (ignored by WHUT-Net)' })"
    Write-Host "HTTPS_PROXY:$(if ([string]::IsNullOrWhiteSpace($env:HTTPS_PROXY)) { ' not set' } else { ' set (ignored by WHUT-Net)' })"

    $internet = Test-Internet
    Write-Host "Internet:   $(if ($internet) { 'OK' } else { 'failed / captive' })"

    if ($internet) {
        Write-Host 'Portal:     not required while Internet is reachable'
        return 0
    }

    $resolved = $null
    try {
        $resolved = Resolve-PortalSession
        Write-Host "Portal:     trusted ($($resolved.Portal.Host))"
        Write-Host "nasId:      $($resolved.NasId)"
        Write-Host "API base:   $($resolved.ApiBasePath)"
        Write-Host 'CSRF:       OK (value intentionally hidden)'

        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        $message = [string](Get-ObjectProperty -Object $status -Name 'msg' -Default '')
        $statusCode = Get-ObjectProperty -Object $status -Name 'code'
        Write-Host "Account:    code=$statusCode $message"
        return 0
    }
    finally {
        if ($null -ne $resolved) {
            Close-HttpContext $resolved.Session
        }
    }
}

function Invoke-SetupCommand {
    param(
        [string]$RequestedUsername
    )

    Ensure-DataDirectory

    $user = $RequestedUsername
    if ([string]::IsNullOrWhiteSpace($user)) {
        $user = Read-Host 'WHUT campus network username'
    }
    $user = $user.Trim()

    if ([string]::IsNullOrWhiteSpace($user)) {
        Throw-Whut 50 'Username cannot be empty.'
    }

    $password = Read-Host 'WHUT campus network password' -AsSecureString
    if ($password.Length -eq 0) {
        Throw-Whut 50 'Password cannot be empty.'
    }

    $trustedProfiles = @(Get-ActivePhysicalNetworkProfiles)

    $config = [ordered]@{
        version         = 1
        username        = $user
        trustedProfiles = $trustedProfiles
    }

    $config | ConvertTo-Json | Set-Content -LiteralPath $Script:ConfigPath -Encoding utf8

    # On Windows, ConvertFrom-SecureString without -Key uses DPAPI scoped to CurrentUser.
    $encrypted = $password | ConvertFrom-SecureString
    Set-Content -LiteralPath $Script:CredentialPath -Value $encrypted -Encoding utf8

    Write-Log INFO 'Configuration saved. Password is protected with Windows DPAPI CurrentUser.'
    if ($trustedProfiles.Count -gt 0) {
        Write-Log INFO 'Trusted physical network profile(s) saved.'
    }
    else {
        Write-Log WARN 'No active physical Windows network profile was captured. Manual login can still work, but auto/install will refuse until setup is rerun on WHUT.'
    }
    Write-Log WARN 'The WHUT portal currently uses HTTP; the network transport itself is not end-to-end encrypted.'
    return 0
}

function Install-WhutScheduledTask {
    if (-not (Test-Path -LiteralPath $Script:ConfigPath) -or
        -not (Test-Path -LiteralPath $Script:CredentialPath)) {
        Throw-Whut 50 'Run setup before installing the scheduled task.'
    }

    $config = Read-Config
    $trustedProfiles = @(Get-ObjectProperty -Object $config -Name 'trustedProfiles' -Default @())
    if ($trustedProfiles.Count -eq 0) {
        Throw-Whut 50 'No trusted physical network profile is stored. Run setup again while connected to WHUT before enabling automatic login.'
    }

    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path -LiteralPath $PSCommandPath)) {
        Throw-Whut 50 'The script must be saved as a .ps1 file before installing the scheduled task.'
    }

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $root = $service.GetFolder('\')
    $task = $service.NewTask(0)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    $task.RegistrationInfo.Description = 'WHUT-Net v0.1 auto-login on user logon and network connection.'
    $task.Settings.Enabled = $true
    $task.Settings.Hidden = $true
    $task.Settings.StartWhenAvailable = $true
    $task.Settings.MultipleInstances = 2  # IgnoreNew
    $task.Settings.ExecutionTimeLimit = 'PT2M'
    $task.Settings.DisallowStartIfOnBatteries = $false
    $task.Settings.StopIfGoingOnBatteries = $false

    $task.Principal.UserId = $identity
    $task.Principal.LogonType = 3  # TASK_LOGON_INTERACTIVE_TOKEN
    $task.Principal.RunLevel = 0   # least privilege

    $logonTrigger = $task.Triggers.Create(9) # TASK_TRIGGER_LOGON
    $logonTrigger.Enabled = $true
    $logonTrigger.UserId = $identity
    $logonTrigger.Delay = 'PT5S'

    $eventTrigger = $task.Triggers.Create(0) # TASK_TRIGGER_EVENT
    $eventTrigger.Enabled = $true
    $eventTrigger.Delay = 'PT3S'
    $eventTrigger.Subscription = @'
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">
    <Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000)]]</Select>
  </Query>
</QueryList>
'@

    $action = $task.Actions.Create(0) # TASK_ACTION_EXEC
    $action.Path = (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop).Source
    $action.Arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}" auto' -f $PSCommandPath
    $action.WorkingDirectory = Split-Path -Parent $PSCommandPath

    # TASK_CREATE_OR_UPDATE = 6; no password is stored because this uses the current
    # interactive user's token.
    [void]$root.RegisterTaskDefinition(
        $Script:TaskName,
        $task,
        6,
        $identity,
        $null,
        3,
        $null
    )

    Write-Log INFO "Scheduled task '$Script:TaskName' installed (logon + NetworkProfile EventID 10000)."
    return 0
}

function Uninstall-Whut {
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $root = $service.GetFolder('\')
        $root.DeleteTask($Script:TaskName, 0)
        Write-Host "[INFO]  Scheduled task removed."
    }
    catch {
        Write-Host "[INFO]  Scheduled task was not present or could not be removed."
    }

    if (Test-Path -LiteralPath $Script:DataDir) {
        Remove-Item -LiteralPath $Script:DataDir -Recurse -Force
        Write-Host '[INFO]  Local configuration, DPAPI credential, and log removed.'
    }

    return 0
}

function Show-Help {
    @"
WHUT-Net v$Script:Version

Usage:
  .\whut-net.ps1 setup [-Username <student-id>]
  .\whut-net.ps1 status
  .\whut-net.ps1 login
  .\whut-net.ps1 auto
  .\whut-net.ps1 diagnose
  .\whut-net.ps1 install
  .\whut-net.ps1 uninstall
  .\whut-net.ps1 help

Commands:
  setup       Save username and a DPAPI-protected password.
  status      Check Internet / WHUT authentication state. Never logs in.
  login       Authenticate once if needed.
  auto        Idempotent mode for Task Scheduler: exit immediately when online.
  diagnose    Inspect portal discovery, nasId, API base, CSRF and account status.
  install     Register one per-user scheduled task for logon + network-connect.
  uninstall   Remove the task and all WHUT-Net local data.
  help        Show this usage information.

Exit codes:
   0  online / login successful
  10  WHUT portal reached, account offline
  11  WHUT portal not discovered / nasId missing
  12  untrusted portal, network profile or unsafe API path
  20  authentication failed
  21  additional verification / code check required
  22  CSRF acquisition failed
  30  WHUT portal/API unavailable
  40  network or post-auth Internet failure
  50  local configuration / credential error

Security:
  - Password at rest: Windows DPAPI CurrentUser.
  - Proxy variables are ignored for authentication traffic.
  - Credentials are sent only to the hard-coded allowlisted WHUT portal host.
  - Automatic mode additionally requires a physical Windows network profile captured during setup.
  - CSRF token, cookies and password are never written to the log.
  - The current WHUT portal is HTTP, so transport confidentiality depends on WHUT.
"@ | Write-Host
    return 0
}

$exitCode = 0

try {
    switch ($Command) {
        'help'     { $exitCode = Show-Help }
        'setup'    { $exitCode = Invoke-SetupCommand -RequestedUsername $Username }
        'status'   { $exitCode = Invoke-StatusCommand }
        'login'    { $exitCode = Invoke-LoginCommand }
        'auto'     { $exitCode = Invoke-LoginCommand -Automatic }
        'diagnose' { $exitCode = Invoke-DiagnoseCommand }
        'install'  { $exitCode = Install-WhutScheduledTask }
        'uninstall'{ $exitCode = Uninstall-Whut }
        default    { $exitCode = Show-Help }
    }
}
catch {
    $exitCode = 40

    try {
        $storedCode = $_.Exception.Data['ExitCode']
        if ($null -ne $storedCode) {
            $exitCode = [int]$storedCode
        }
    }
    catch {
        $exitCode = 40
    }

    # Only deliberate WHUT errors contain messages safe for persistent logging.
    # Unexpected exceptions may include request URLs or other session details.
    if ($null -ne $_.Exception.Data['ExitCode']) {
        Write-Log ERROR $_.Exception.Message
    }
    else {
        Write-Log ERROR 'Unexpected operation failure; no request or credential details were logged.'
    }
}

exit $exitCode
