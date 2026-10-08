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
    Version: 0.1.1
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

$Script:Version = '0.1.1'
$Script:AllowedPortalHosts = @('172.30.21.100')
$Script:ExpectedPortalPath = '/tpl/whut/login.html'
# Known WHUT wire protocol. All response shapes are checked before using their values.
$Script:WhutProtocol = @{
    ConfigPath = '/tpl/whut/static/js/config.js'
    FallbackBase = '/api'
    CsrfPath = '/csrf-token'
    StatusPath = '/account/status?token=null'
    LoginPath = '/account/login'
    OnlineCode = 0
    VerificationCode = 2
}
$Script:DiscoveryProbeSeconds = 4
$Script:DiscoveryBudgetSeconds = 16
$Script:PortalProbes = @(
    @{ Name = 'msft-redirect'; Uri = [Uri]'http://www.msftconnecttest.com/redirect' }
    @{ Name = 'msft-connecttest'; Uri = [Uri]'http://www.msftconnecttest.com/connecttest.txt' }
    @{ Name = 'neverssl'; Uri = [Uri]'http://neverssl.com/' }
    @{ Name = 'whut-direct'; Uri = [Uri]'http://172.30.21.100/tpl/whut/login.html' }
)
$Script:InternetProbeExpected = 'Microsoft Connect Test'
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
        [AllowNull()]
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

function Get-IPv4Prefix {
    param([string]$Address, [ValidateRange(0,32)][int]$PrefixLength)
    $ip = [System.Net.IPAddress]::Parse($Address)
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        Throw-Whut 50 'Invalid IPv4 network fingerprint.'
    }
    $bytes = $ip.GetAddressBytes()
    for ($i = 0; $i -lt 4; $i++) {
        $bits = [Math]::Min(8, [Math]::Max(0, $PrefixLength - 8 * $i))
        $bytes[$i] = $bytes[$i] -band (256 - [Math]::Pow(2, 8 - $bits))
    }
    return '{0}/{1}' -f ([System.Net.IPAddress]::new($bytes)), $PrefixLength
}

function Get-CurrentNetworkFingerprint {
    # Select the route to WHUT, rather than any other simultaneously active adapter.
    # No SSID scanning, elevation, or persistent network changes are needed.
    try {
        $route = @(Find-NetRoute -RemoteIPAddress $Script:AllowedPortalHosts[0] -ErrorAction Stop)
        $address = @($route | Where-Object { $null -ne $_.PSObject.Properties['IPAddress'] })
        if ($address.Count -ne 1) { return $null }
        $address = $address[0]
        $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {
            $_.Status -eq 'Up' -and $_.ifIndex -eq $address.InterfaceIndex
        })
        if ($adapters.Count -ne 1) { return $null }
        $adapter = $adapters[0]
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $address.InterfaceIndex -ErrorAction Stop
        $gateways = @($ipConfig.IPv4DefaultGateway | ForEach-Object { $_.NextHop } | Sort-Object -Unique)
        if ($gateways.Count -ne 1) { return $null }
        $profiles = @(Get-NetConnectionProfile -InterfaceIndex $address.InterfaceIndex -ErrorAction SilentlyContinue)
        return [pscustomobject]@{
            profileName = if ($profiles.Count -eq 1) { [string]$profiles[0].Name } else { '' }
            interfaceAlias = [string]$adapter.Name
            interfaceType = [string]$adapter.InterfaceType
            ipv4Address = [string]$address.IPAddress
            ipv4Prefix = Get-IPv4Prefix $address.IPAddress $address.PrefixLength
            defaultGateway = [string]$gateways[0]
            portalHost = $Script:AllowedPortalHosts[0]
        }
    }
    catch { return $null }
}

function Test-TrustedLocalNetwork {
    param($Config, [switch]$Automatic)
    $current = Get-CurrentNetworkFingerprint
    if ($null -eq $current) { return $false }
    if ((Get-ObjectProperty $Config 'version' 1) -eq 1) {
        # Profile-only configurations remain readable, but cannot authorize automation.
        return (-not $Automatic)
    }
    $trusted = Get-ObjectProperty $Config 'trustedNetwork'
    if ($null -eq $trusted) { return $false }
    # A DHCP address may change within its real prefix. A renamed profile is harmless.
    $fields = @('ipv4Prefix', 'defaultGateway', 'portalHost')
    if ($Automatic) { $fields += @('interfaceAlias', 'interfaceType') }
    foreach ($field in $fields) {
        $expected = [string](Get-ObjectProperty $trusted $field '')
        if ([string]::IsNullOrWhiteSpace($expected) -or
            $expected -cne [string](Get-ObjectProperty $current $field '')) { return $false }
    }
    return $true
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

    $version = Get-ObjectProperty $config 'version' 1
    if ($version -notin @(1, 2)) { Throw-Whut 50 'Unsupported configuration version.' }
    if ($version -eq 1) {
        Write-Log WARN 'Version 1 configuration: run setup on WHUT to capture a network fingerprint before auto/install.'
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

function New-HttpContext {
    param([double]$TimeoutSeconds = $Script:RequestTimeoutSeconds)

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = $false
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $handler.AutomaticDecompression = (
        [System.Net.DecompressionMethods]::GZip -bor
        [System.Net.DecompressionMethods]::Deflate
    )

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $client.MaxResponseContentBufferSize = 1MB
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

function Invoke-HttpText {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        [ValidateSet('GET')]
        [string]$Method,
        [Parameter(Mandatory)]
        [Uri]$Uri,
        [hashtable]$Headers = @{},
        [int]$TimeoutMilliseconds = 5000
    )

    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method),
        $Uri
    )

    $cancel = $null
    try {
        foreach ($entry in $Headers.GetEnumerator()) {
            [void]$request.Headers.TryAddWithoutValidation([string]$entry.Key, [string]$entry.Value)
        }

        $cancel = [System.Threading.CancellationTokenSource]::new($TimeoutMilliseconds)

        $response = $Context.Client.SendAsync(
            $request,
            [System.Net.Http.HttpCompletionOption]::ResponseContentRead,
            $cancel.Token
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
        if ($null -ne $cancel) { $cancel.Dispose() }
    }
}

function Test-TrustedPortalUri {
    param([Parameter(Mandatory)][Uri]$Uri)
    if (-not $Uri.IsAbsoluteUri) { return $false }
    if ($Uri.Scheme -notin @('http', 'https')) { return $false }
    if ($Uri.UserInfo -or $Uri.Fragment -or -not $Uri.IsDefaultPort) { return $false }
    if ($Script:AllowedPortalHosts -cnotcontains $Uri.Host) { return $false }
    # Check the original representation too: System.Uri normalizes ../ and escapes.
    $raw = $Uri.OriginalString
    if ($raw -match '[\x00-\x20\x7f]' -or
        $raw -cnotmatch '^https?://172\.30\.21\.100(?::(?:80|443))?/tpl/whut/login\.html(?:\?[^#\\]*)?\z') { return $false }
    return ($Uri.AbsolutePath -ceq $Script:ExpectedPortalPath)
}

function Test-SafeApiBasePath {
    param([AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('..')) { return $false }
    # Only nonempty ASCII path segments; no //, escaping, authority, scheme, or suffix.
    return ($Path -cmatch '^/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*\z')
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
    # Independent, credential-free preflight: a failed NCSI must not suppress NeverSSL.
    foreach ($probe in @($Script:PortalProbes[1], $Script:PortalProbes[2])) {
        $context = $null
        try {
            $context = New-HttpContext -TimeoutSeconds $Script:DiscoveryProbeSeconds
            $result = Invoke-HttpText $context GET $probe.Uri -TimeoutMilliseconds ($Script:DiscoveryProbeSeconds * 1000)
            if (Test-InternetResponse $probe.Name $result) { return $true }
            if ($result.StatusCode -ge 300 -and $result.StatusCode -lt 400) {
                $candidate = $null
                if ($null -eq $result.Location -or
                    -not [Uri]::TryCreate([string]$result.Location, [UriKind]::Absolute, [ref]$candidate) -or
                    -not (Test-TrustedPortalUri $candidate)) {
                    Throw-Whut 12 'UntrustedRedirect during Internet preflight.'
                }
                return $false
            }
        }
        catch {
            if ($_.Exception.Data['ExitCode'] -eq 12) { throw }
        }
        finally { Close-HttpContext $context }
    }
    return $false
}

function Test-InternetResponse {
    param([string]$Probe, $Result)
    if ($Result.StatusCode -ne 200) { return $false }
    if ($Probe -eq 'msft-connecttest') { return ($Result.Body.Trim() -ceq $Script:InternetProbeExpected) }
    if ($Probe -eq 'neverssl') { return ($Result.Body -match '(?i)<title>\s*NeverSSL\s*</title>') }
    return $false
}

function Find-WhutPortal {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $directUnavailable = $false
    foreach ($probe in $Script:PortalProbes) {
        $remaining = [int]($Script:DiscoveryBudgetSeconds * 1000 - $timer.ElapsedMilliseconds)
        if ($remaining -le 0) { $timedOut = $true; break }
        $context = $null
        try {
            $context = New-HttpContext -TimeoutSeconds $Script:DiscoveryProbeSeconds
            $timeout = [Math]::Min($remaining, $Script:DiscoveryProbeSeconds * 1000)
            $result = Invoke-HttpText $context GET $probe.Uri -TimeoutMilliseconds $timeout
            if ($result.StatusCode -ge 300 -and $result.StatusCode -lt 400) {
                Write-Log INFO "probe=$($probe.Name) result=redirect"
                $candidate = $null
                if ($null -ne $result.Location) {
                    $location = [string]$result.Location
                    # Do not let URI resolution normalize a relative lookalike into the allowlist.
                    if ($location -cmatch '^/tpl/whut/login\.html(?:\?[^#\\]*)?\z' -or
                        $location -cmatch '^https?://') {
                        [void][Uri]::TryCreate($probe.Uri, $location, [ref]$candidate)
                    }
                }
                if ($null -eq $candidate -or -not (Test-TrustedPortalUri $candidate)) {
                    Write-Log WARN 'portal=untrusted result=UntrustedRedirect'
                    return [pscustomobject]@{ State = 'UntrustedRedirect'; Portal = $null; ExitCode = 12 }
                }
                Write-Log INFO 'portal=trusted result=PortalRedirectFound'
                return [pscustomobject]@{ State = 'PortalRedirectFound'; Portal = $candidate; ExitCode = 0 }
            }
            if (Test-InternetResponse $probe.Name $result) {
                Write-Log INFO "probe=$($probe.Name) result=InternetOnline"
                return [pscustomobject]@{ State = 'InternetOnline'; Portal = $null; ExitCode = 0 }
            }
            if ($probe.Name -eq 'whut-direct' -and $result.StatusCode -eq 200) {
                Write-Log INFO 'probe=whut-direct result=WhutPortalReachable portal=trusted'
                return [pscustomobject]@{ State = 'WhutPortalReachable'; Portal = $probe.Uri; ExitCode = 0 }
            }
            Write-Log INFO "probe=$($probe.Name) result=http-$($result.StatusCode)"
            if ($probe.Name -eq 'whut-direct' -and $result.StatusCode -ge 500) { $directUnavailable = $true }
        }
        catch [System.OperationCanceledException] {
            $timedOut = $true
            Write-Log WARN "probe=$($probe.Name) result=timeout state=ProbeTimeout"
        }
        catch {
            Write-Log WARN "probe=$($probe.Name) result=unreachable"
            if ($probe.Name -eq 'whut-direct') { $directUnavailable = $true }
        }
        finally { Close-HttpContext $context }
    }
    # Preserve timeouts in the final result instead of collapsing them into not-found.
    $state = if ($timedOut) { 'ProbeTimeout' } elseif ($directUnavailable) { 'PortalUnreachable' } else { 'PortalNotFound' }
    $code = if ($timedOut) { 31 } elseif ($directUnavailable) { 30 } else { 11 }
    Write-Log WARN "discovery=$state"
    return [pscustomobject]@{ State = $state; Portal = $null; ExitCode = $code }
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
            Throw-Whut 30 "WHUT portal handshake failed with HTTP $($result.StatusCode)."
        }

        return $context
    }
    catch {
        Close-HttpContext $context
        if ($_.Exception.Data['ExitCode'] -eq 30) { throw }
        Throw-Whut 30 'WHUT portal handshake unavailable.'
    }
}

function Get-ApiBasePath {
    param($Context, [Uri]$PortalUri)
    if (-not (Test-TrustedPortalUri $PortalUri)) { Throw-Whut 12 'Untrusted bootstrap portal.' }
    $configUri = [Uri]::new((Get-Origin $PortalUri) + $Script:WhutProtocol.ConfigPath)
    $result = $null
    try { $result = Invoke-HttpText $Context GET $configUri }
    catch { Write-Log WARN 'protocol=config-unavailable' }
    if ($null -ne $result -and $result.StatusCode -eq 200) {
        $matches = [regex]::Matches($result.Body, '(?<![A-Za-z0-9_$])host_url\s*=\s*[''"]([^''"]*)[''"]')
        if ($matches.Count -gt 1) { Throw-Whut 13 'ProtocolChanged: ambiguous API base.' }
        if ($matches.Count -eq 1) {
            $path = $matches[0].Groups[1].Value
            if (-not (Test-SafeApiBasePath $path)) { Throw-Whut 12 'config.js returned an unsafe API base path.' }
            return $path
        }
    }
    # A missing config is tolerated only after active fingerprint validation.
    try {
        [void](Get-CsrfToken $Context $PortalUri $Script:WhutProtocol.FallbackBase)
    }
    catch { Throw-Whut 13 'UnsupportedProtocol: /api fallback fingerprint did not match.' }
    Write-Log WARN 'protocol=fallback-csrf-validated; status fingerprint still required'
    return $Script:WhutProtocol.FallbackBase
}

function Get-WhutApiUri {
    param([Uri]$PortalUri, [string]$ApiBasePath, [string]$Endpoint)
    if (-not (Test-TrustedPortalUri $PortalUri) -or -not (Test-SafeApiBasePath $ApiBasePath)) {
        Throw-Whut 12 'Untrusted portal or unsafe API base path.'
    }
    return [Uri]::new((Get-Origin $PortalUri) + $ApiBasePath + $Endpoint)
}

function Read-WhutProtocolResponse {
    param($Result, [ValidateSet('Csrf','Status','Login')][string]$Kind)
    if ($Result.StatusCode -ne 200) {
        if ($Kind -eq 'Csrf') { Throw-Whut 22 'CSRF/bootstrap endpoint unavailable.' }
        Throw-Whut 30 'WHUT API endpoint unavailable.'
    }
    $document = $null
    try {
        $document = [System.Text.Json.JsonDocument]::Parse([string]$Result.Body)
        $root = $document.RootElement
        if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'shape' }
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $root.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw 'duplicate' }
        }
        if ($Kind -eq 'Csrf') {
            $token = $root.GetProperty('csrf_token').GetString()
            if ([string]::IsNullOrWhiteSpace($token) -or $token.Length -gt 4096 -or $token -match '[\x00-\x1f\x7f]') { throw 'token shape' }
            return $token
        }
        $code = $root.GetProperty('code').GetInt32()
        if ($Kind -eq 'Login') {
            $msg = $root.GetProperty('msg')
            if ($msg.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { throw 'message shape' }
        }
        # Do not return raw messages, unexpected fields, or reflected credentials.
        return [pscustomobject]@{ code = $code }
    }
    catch { Throw-Whut 13 "ProtocolChanged: $Kind response fingerprint did not match." }
    finally { if ($null -ne $document) { $document.Dispose() } }
}

function Get-CsrfToken {
    param($Context, [Uri]$PortalUri, [string]$ApiBasePath)
    $uri = Get-WhutApiUri $PortalUri $ApiBasePath $Script:WhutProtocol.CsrfPath
    try {
        $result = Invoke-HttpText $Context GET $uri -Headers @{
            Accept = 'application/json, */*'; Referer = $PortalUri.AbsoluteUri
        }
    }
    catch { Throw-Whut 22 'CSRF/bootstrap request failed.' }
    return Read-WhutProtocolResponse $result Csrf
}

function Get-WhutAccountStatus {
    param($Context, [Uri]$PortalUri, [string]$ApiBasePath, [string]$CsrfToken)
    $uri = Get-WhutApiUri $PortalUri $ApiBasePath $Script:WhutProtocol.StatusPath
    try {
        $result = Invoke-HttpText $Context GET $uri -Headers @{
            Accept = 'application/json, */*'; Referer = $PortalUri.AbsoluteUri
            'X-Requested-With' = 'XMLHttpRequest'; 'X-Csrf-Token' = $CsrfToken
        }
    }
    catch { Throw-Whut 30 'WHUT status request failed.' }
    return Read-WhutProtocolResponse $result Status
}

function Add-WhutFormBytes {
    param([IO.MemoryStream]$Stream, [string]$Name, [byte[]]$Bytes)
    if ($Stream.Length -gt 0) { $Stream.WriteByte(38) }
    foreach ($b in [Text.Encoding]::ASCII.GetBytes($Name + '=')) { $Stream.WriteByte($b) }
    foreach ($b in $Bytes) {
        if (($b -ge 65 -and $b -le 90) -or ($b -ge 97 -and $b -le 122) -or
            ($b -ge 48 -and $b -le 57) -or $b -in @(45,46,95,126)) {
            $Stream.WriteByte($b)
        }
        elseif ($b -eq 32) { $Stream.WriteByte(43) }
        else {
            $Stream.WriteByte(37)
            $Stream.WriteByte([byte][char]'0123456789ABCDEF'[[int]($b -shr 4)])
            $Stream.WriteByte([byte][char]'0123456789ABCDEF'[[int]($b -band 15)])
        }
    }
}

function Invoke-WhutLogin {
    param($Context, [Uri]$PortalUri, [string]$ApiBasePath, [string]$CsrfToken,
          [string]$NasId, [string]$User, $Config, [switch]$Automatic)
    $uri = Get-WhutApiUri $PortalUri $ApiBasePath $Script:WhutProtocol.LoginPath
    if ([string]::IsNullOrWhiteSpace($NasId) -or $NasId.Length -gt 1024 -or $NasId -match '[\x00-\x1f\x7f]') {
        Throw-Whut 11 'Trusted portal is reachable, but a valid session nasId was not discovered.'
    }
    # Re-read the actual route immediately before releasing the credential.
    if (-not (Test-TrustedLocalNetwork $Config -Automatic:$Automatic)) {
        Throw-Whut 12 'Current physical network fingerprint is not trusted. Run setup on WHUT.'
    }
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $uri)
    $response = $null
    $password = $null
    $bstr = [IntPtr]::Zero
    $chars = $null
    $bytes = $null
    $body = $null
    $stream = [IO.MemoryStream]::new()
    try {
        [void]$request.Headers.TryAddWithoutValidation('Accept', 'application/json, */*')
        [void]$request.Headers.TryAddWithoutValidation('Referer', $PortalUri.AbsoluteUri)
        [void]$request.Headers.TryAddWithoutValidation('Origin', (Get-Origin $PortalUri))
        [void]$request.Headers.TryAddWithoutValidation('X-Requested-With', 'XMLHttpRequest')
        [void]$request.Headers.TryAddWithoutValidation('X-Csrf-Token', $CsrfToken)
        foreach ($field in ([ordered]@{ username = $User; swtichip = ''; nasId = $NasId;
            userIpv4 = ''; userMac = ''; captcha = ''; captchaId = '' }).GetEnumerator()) {
            Add-WhutFormBytes $stream $field.Key ([Text.Encoding]::UTF8.GetBytes([string]$field.Value))
        }
        # Credential-specific path: no plaintext .NET String, form hashtable, or generic POST helper.
        $password = Read-ProtectedPassword
        try {
            # Reserve before copying plaintext so MemoryStream growth cannot abandon a password buffer.
            $stream.Capacity = [int]($stream.Length + 10 + 12 * $password.Length)
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
            $chars = [char[]]::new($password.Length)
            [Runtime.InteropServices.Marshal]::Copy($bstr, $chars, 0, $chars.Length)
            $bytes = [Text.Encoding]::UTF8.GetBytes($chars)
            Add-WhutFormBytes $stream 'password' $bytes
            $body = $stream.ToArray()
        }
        finally {
            if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $bstr = [IntPtr]::Zero }
            if ($null -ne $chars) { [Array]::Clear($chars, 0, $chars.Length); $chars = $null }
            if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length); $bytes = $null }
            if ($null -ne $password) { $password.Dispose(); $password = $null }
            [Array]::Clear($stream.GetBuffer(), 0, $stream.Capacity)
        }
        $request.Content = [Net.Http.ByteArrayContent]::new($body)
        $request.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/x-www-form-urlencoded; charset=UTF-8')
        $response = $Context.Client.SendAsync($request).GetAwaiter().GetResult()
    }
    catch {
        $localCredentialError = $_.Exception.Data['ExitCode'] -eq 50
        # Do not retain the original transport ErrorRecord in PowerShell's error history.
        [void]$Error.Remove($_)
        if ($localCredentialError) { Throw-Whut 50 'Stored credential could not be read for the current Windows user.' }
        Throw-Whut 30 'WHUT credential POST failed; request details suppressed.'
    }
    finally {
        $request.Dispose()
        if ($null -ne $body) { [Array]::Clear($body, 0, $body.Length); $body = $null }
        [Array]::Clear($stream.GetBuffer(), 0, $stream.Capacity)
        $stream.Dispose()
        $request = $null
    }
    try {
        $result = [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
        $data = Read-WhutProtocolResponse $result Login
    }
    catch {
        $code = $_.Exception.Data['ExitCode']
        [void]$Error.Remove($_)
        if ($code -eq 13) { Throw-Whut 13 'ProtocolChanged: Login response fingerprint did not match.' }
        Throw-Whut 30 'WHUT login response unavailable.'
    }
    finally { $result = $null; $response.Dispose(); $response = $null }
    if ($data.code -eq $Script:WhutProtocol.VerificationCode) { Throw-Whut 21 'Login requires additional verification or code check.' }
    if ($data.code -ne $Script:WhutProtocol.OnlineCode) { Throw-Whut 20 'Authentication rejected by WHUT.' }
    return $data
}

function Resolve-PortalSession {
    $discovery = Find-WhutPortal
    if ($discovery.State -eq 'InternetOnline') { return $null }
    if ($discovery.ExitCode -ne 0) { Throw-Whut $discovery.ExitCode $discovery.State }
    $portal = $discovery.Portal

    if (-not (Test-TrustedPortalUri -Uri $portal)) {
        Throw-Whut 12 'Discovered captive portal is not trusted.'
    }

    $nasId = Get-QueryValue -Uri $portal -Name 'nasId'
    # Direct reachability permits diagnostics; login still requires a discovered nasId.

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
        if ($null -eq $resolved) { Write-Log INFO 'InternetOnline'; return 0 }
        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        if ([int](Get-ObjectProperty -Object $status -Name 'code') -eq $Script:WhutProtocol.OnlineCode) {
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
        if ($null -eq $resolved) { Write-Log INFO 'InternetOnline'; return 0 }
        Write-Log INFO 'Trusted WHUT portal discovered.'

        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        if ([int](Get-ObjectProperty -Object $status -Name 'code') -eq $Script:WhutProtocol.OnlineCode) {
            if (Test-Internet) {
                Write-Log INFO 'ONLINE: account and Internet probes both succeeded.'
                return 0
            }

            Write-Log WARN 'Account is authenticated, but Internet connectivity is unavailable.'
            return 40
        }

        $config = Read-Config
        [void](Invoke-WhutLogin `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken `
            -NasId $resolved.NasId `
            -User ([string](Get-ObjectProperty -Object $config -Name 'username')) `
            -Config $config -Automatic:$Automatic)

        Start-Sleep -Milliseconds 750

        $verified = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        if ([int](Get-ObjectProperty -Object $verified -Name 'code') -ne $Script:WhutProtocol.OnlineCode) {
            Throw-Whut 40 'Login endpoint accepted the request, but account status verification failed.'
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
        if ($null -eq $resolved) { Write-Log INFO 'InternetOnline'; return 0 }
        Write-Host "Portal:     trusted ($($resolved.Portal.Host))"
        Write-Host "nasId:      $(if ($resolved.NasId) { 'present' } else { 'missing; login unavailable' })"
        Write-Host "API base:   $($resolved.ApiBasePath)"
        Write-Host 'CSRF:       OK (value intentionally hidden)'

        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        $statusCode = Get-ObjectProperty -Object $status -Name 'code'
        Write-Host "Account:    code=$statusCode"
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
        $password.Dispose()
        Throw-Whut 50 'Password cannot be empty.'
    }

    try {
        $trustedNetwork = Get-CurrentNetworkFingerprint
        $config = [ordered]@{
            version = 2
            username = $user
            trustedNetwork = $trustedNetwork
        }
        # ConvertFrom-SecureString without -Key uses DPAPI CurrentUser on Windows.
        $encrypted = $password | ConvertFrom-SecureString
        Set-Content -LiteralPath $Script:CredentialPath -Value $encrypted -Encoding utf8
        $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Script:ConfigPath -Encoding utf8
    }
    finally { $password.Dispose(); $password = $null; $encrypted = $null }
    Write-Log INFO 'Configuration v2 saved. Password is protected with Windows DPAPI CurrentUser.'
    if ($null -ne $trustedNetwork) {
        Write-Log INFO 'Trusted physical route/network fingerprint saved.'
    }
    else {
        Write-Log WARN 'No complete physical route fingerprint captured. Run setup again on WHUT before login/auto/install.'
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
    if (-not (Test-TrustedLocalNetwork $config -Automatic)) {
        Throw-Whut 50 'Install requires a matching version 2 physical network fingerprint. Run setup on WHUT.'
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
  11  PortalNotFound / session nasId missing
  12  untrusted portal, network fingerprint or unsafe API path
  13  UnsupportedProtocol / ProtocolChanged
  20  authentication rejected
  21  additional verification / code check required
  22  CSRF acquisition failed
  30  PortalUnreachable / WHUT API unavailable
  31  ProbeTimeout (discovery exhausted after one or more timeouts)
  40  network or post-auth Internet failure
  50  local configuration / credential error

Security:
  - Password at rest: Windows DPAPI CurrentUser.
  - Proxy variables are ignored for authentication traffic.
  - Credentials are sent only to the hard-coded allowlisted WHUT portal host.
  - Auto requires a v2 physical route, IPv4 prefix, gateway and interface fingerprint.
  - Profile names are auxiliary; rerun setup to upgrade v1 without automatic migration.
  - Discovery: NCSI redirect, NCSI content, NeverSSL, direct WHUT (4s each, 16s budget).
  - Internet preflight has an additional 8s maximum; any untrusted discovery redirect stops.
  - Protocol shapes are checked; /api fallback requires an active CSRF fingerprint.
  - Fingerprints are defence-in-depth, not cryptographic server authentication.
  - DPAPI protects storage only; managed strings cannot be guaranteed immediately erased.
  - CSRF token, cookies and password are never written to the log.
  - The current WHUT portal is HTTP, so transport confidentiality depends on WHUT.
"@ | Write-Host
    return 0
}

# Dot-sourcing loads functions for repeatable offline tests; direct invocation remains the CLI.
if ($MyInvocation.InvocationName -eq '.') { return }

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
