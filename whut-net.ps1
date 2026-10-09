#requires -Version 7.2
#requires -PSEdition Core
<#
.SYNOPSIS
    WHUT-Net v1.3.2 - Lightweight Wuhan University of Technology campus network authenticator.

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
    Version: 1.3.2
    Target: PowerShell 7.2+ on Windows 10/11
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'setup', 'status', 'login', 'auto', 'diagnose', 'install', 'uninstall')]
    [string]$Command = 'help',

    [string]$Username,

    [switch]$AddNetwork
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:Version = '1.3.2'
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
    Write-Error 'WHUT-Net v1.3.2 is Windows-only because credential protection uses Windows DPAPI.'
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

function Test-UsablePhysicalIPv4 {
    param([Parameter(Mandatory)][string]$Address)
    try {
        $ip = [System.Net.IPAddress]::Parse($Address)
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
        $b = $ip.GetAddressBytes()
        if ($b[0] -eq 0 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false } # APIPA
        if ($b[0] -eq 198 -and $b[1] -in 18,19) { return $false } # RFC 2544 / common TUN range
        return $true
    }
    catch { return $false }
}

function Test-PrivateIPv4 {
    param([Parameter(Mandatory)][string]$Address)
    try {
        $b = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
        return (
            $b[0] -eq 10 -or
            ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
            ($b[0] -eq 192 -and $b[1] -eq 168)
        )
    }
    catch { return $false }
}

function Get-PhysicalNetworkCandidates {
    $items = [Collections.Generic.List[object]]::new()
    try {
        $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
        foreach ($adapter in $adapters) {
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
            if ($null -eq $ipConfig) { continue }

            $gateways = @(
                $ipConfig.IPv4DefaultGateway |
                    ForEach-Object { [string]$_.NextHop } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Sort-Object -Unique
            )
            if ($gateways.Count -ne 1) { continue }

            $addresses = @(
                $ipConfig.IPv4Address |
                    Where-Object {
                        $null -ne $_ -and
                        (Test-UsablePhysicalIPv4 -Address ([string]$_.IPAddress))
                    }
            )
            if ($addresses.Count -eq 0) { continue }

            $profile = @(Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue)
            $profileName = if ($profile.Count -eq 1) { [string]$profile[0].Name } else { '' }

            $routeMetric = [int]::MaxValue
            try {
                $routes = @(
                    Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop |
                        Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }
                )
                if ($routes.Count -gt 0) {
                    $routeMetric = [int](($routes | Measure-Object -Property RouteMetric -Minimum).Minimum)
                }
            }
            catch {}

            $interfaceMetric = 0
            try {
                $ipInterface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
                $interfaceMetric = [int]$ipInterface.InterfaceMetric
            }
            catch {}

            foreach ($address in $addresses) {
                $addr = [string]$address.IPAddress
                $items.Add([pscustomobject]@{
                    profileName    = $profileName
                    interfaceAlias = [string]$adapter.Name
                    interfaceType  = [string]$adapter.InterfaceType
                    interfaceIndex = [int]$adapter.ifIndex
                    ipv4Address    = $addr
                    prefixLength   = [int]$address.PrefixLength
                    ipv4Prefix     = Get-IPv4Prefix $addr ([int]$address.PrefixLength)
                    defaultGateway = [string]$gateways[0]
                    portalHost     = $Script:AllowedPortalHosts[0]
                    privateIPv4    = Test-PrivateIPv4 -Address $addr
                    metric         = [long]$routeMetric + [long]$interfaceMetric
                })
            }
        }
    }
    catch {}
    return @($items)
}

function Get-CurrentNetworkFingerprint {
    param([string]$UserIpHint)

    # Do not trust Find-NetRoute alone: Clash/Mihomo/WireGuard/TUN adapters can own
    # the best route to the portal. Select from physical adapters first.
    $candidates = @(Get-PhysicalNetworkCandidates)
    if ($candidates.Count -eq 0) { return $null }

    $selected = $null

    # WHUT's credential-free bootstrap exposes the campus-side userip. Prefer the
    # physical adapter that owns that exact address.
    if (-not [string]::IsNullOrWhiteSpace($UserIpHint)) {
        $matched = @($candidates | Where-Object { $_.ipv4Address -ceq $UserIpHint })
        if ($matched.Count -eq 1) { $selected = $matched[0] }
        else { return $null } # A supplied campus hint must match exactly; never substitute another uplink.
    }

    if ($null -eq $selected) {
        if ($candidates.Count -eq 1) {
            $selected = $candidates[0]
        }
        else {
            $private = @($candidates | Where-Object { $_.privateIPv4 })
            $pool = if ($private.Count -gt 0) { $private } else { $candidates }
            $sorted = @($pool | Sort-Object metric, interfaceIndex)
            if ($sorted.Count -eq 0) { return $null }
            if ($sorted.Count -gt 1 -and $sorted[0].metric -eq $sorted[1].metric) {
                return $null
            }
            $selected = $sorted[0]
        }
    }

    return [pscustomobject]@{
        profileName    = $selected.profileName
        interfaceAlias = $selected.interfaceAlias
        interfaceType  = $selected.interfaceType
        ipv4Address    = $selected.ipv4Address
        ipv4Prefix     = $selected.ipv4Prefix
        defaultGateway = $selected.defaultGateway
        portalHost     = $selected.portalHost
    }
}

function Test-TrustedLocalNetwork {
    param($Config, [switch]$Automatic, [string]$UserIpHint)

    $current = Get-CurrentNetworkFingerprint -UserIpHint $UserIpHint
    if ($null -eq $current) { return $false }

    if ((Get-ObjectProperty $Config 'version' 1) -eq 1) {
        # Profile-only configurations remain readable, but cannot authorize automation.
        return (-not $Automatic)
    }

    foreach ($trusted in @(Get-RegisteredNetworks $Config)) {
        if (Test-NetworkFingerprintMatch $current $trusted -Automatic:$Automatic) { return $true }
    }
    return $false
}

function Get-RegisteredNetworks {
    param($Config)
    if ((Get-ObjectProperty $Config 'version' 1) -eq 2) {
        $single = Get-ObjectProperty $Config 'trustedNetwork'
        if ($null -ne $single) { return $single }
        return
    }
    return @(Get-ObjectProperty $Config 'trustedNetworks' @()) | Where-Object { $null -ne $_ }
}

function Test-NetworkFingerprintMatch {
    param($Current, $Trusted, [switch]$Automatic)
    if ($null -eq $Current -or $null -eq $Trusted) { return $false }
    # Profile names and DHCP host addresses never grant trust or add registrations.
    $fields = @('ipv4Prefix', 'defaultGateway', 'portalHost')
    if ($Automatic) { $fields += @('interfaceAlias', 'interfaceType') }

    foreach ($field in $fields) {
        $expected = [string](Get-ObjectProperty $Trusted $field '')
        if ([string]::IsNullOrWhiteSpace($expected) -or
            $expected -cne [string](Get-ObjectProperty $Current $field '')) {
            return $false
        }
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
    if ($version -notin @(1, 2, 3)) { Throw-Whut 50 'Unsupported configuration version.' }
    if ($version -eq 1) {
        Write-Log WARN 'Version 1 configuration: run setup on WHUT to capture a network fingerprint before auto/install.'
    }
    if ($version -eq 2) {
        $config = [pscustomobject]@{
            version = 3
            username = [string]$storedUsername
            trustedNetworks = @(Get-RegisteredNetworks $config)
        }
        Write-Config $config
        Write-Log INFO 'Configuration migrated from v2 to v3; existing network and credential retained.'
    }
    return $config
}

function Write-Config {
    param($Config)
    # Replace in the same directory; never leave a partially written trust list.
    $temporary = $Script:ConfigPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding utf8
        if (Test-Path -LiteralPath $Script:ConfigPath) {
            [IO.File]::Replace($temporary, $Script:ConfigPath, [NullString]::Value)
        }
        else { [IO.File]::Move($temporary, $Script:ConfigPath) }
    }
    catch { Throw-Whut 50 'Could not save network configuration; existing configuration retained.' }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
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

function Test-TrustedBootstrapUri {
    param([Parameter(Mandatory)][Uri]$Uri)

    if (-not $Uri.IsAbsoluteUri) { return $false }
    if ($Uri.Scheme -cne 'http') { return $false }
    if ($Uri.UserInfo -or $Uri.Fragment -or -not $Uri.IsDefaultPort) { return $false }
    if ($Script:AllowedPortalHosts -cnotcontains $Uri.Host) { return $false }

    $raw = $Uri.OriginalString
    if ($raw -match '[\x00-\x20\x7f]' -or
        $raw -cnotmatch '^http://172\.30\.21\.100(?::80)?/api/r/[0-9]{1,10}(?:\?[^#\\]*)?\z') {
        return $false
    }

    return ($Uri.AbsolutePath -cmatch '^/api/r/[0-9]{1,10}\z')
}

function Test-SafeWhutRedirectLocation {
    param([string]$Location)
    # Absolute destinations still pass the full URI allowlist below. For relative
    # redirects, prevent System.Uri from normalizing a lookalike into an allowed path.
    if ($Location -cmatch '^https?://') { return $true }
    return ($Location -cmatch '^/(?:api/r/[0-9]{1,10}|tpl/whut/login\.html)(?:\?[^#\\\x00-\x20\x7f]*)?\z')
}

function Get-WhutBootstrapMetadata {
    param([Parameter(Mandatory)][Uri]$Uri)

    if (-not (Test-TrustedBootstrapUri -Uri $Uri)) {
        Throw-Whut 12 'Untrusted WHUT bootstrap URI.'
    }

    $nasId = $Uri.AbsolutePath.Substring('/api/r/'.Length)
    $userIp = Get-QueryValue -Uri $Uri -Name 'userip'

    if (-not [string]::IsNullOrWhiteSpace($userIp)) {
        try {
            $parsed = [System.Net.IPAddress]::Parse($userIp)
            if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                throw 'not IPv4'
            }
        }
        catch {
            Throw-Whut 13 'ProtocolChanged: bootstrap userip is invalid.'
        }
    }

    return [pscustomobject]@{
        NasId      = $nasId
        UserIp     = $userIp
        AcIp       = Get-QueryValue -Uri $Uri -Name 'acip'
        AcName     = Get-QueryValue -Uri $Uri -Name 'acname'
        WlanAcName = Get-QueryValue -Uri $Uri -Name 'wlanacname'
    }
}

function Convert-BootstrapToPortalUri {
    param([Parameter(Mandatory)][Uri]$BootstrapUri)

    $meta = Get-WhutBootstrapMetadata -Uri $BootstrapUri
    $pairs = [Collections.Generic.List[string]]::new()

    function Add-QueryPair([string]$Name, [AllowNull()][string]$Value, [switch]$IncludeEmpty) {
        if ($null -eq $Value) { return }
        if (-not $IncludeEmpty -and [string]::IsNullOrWhiteSpace($Value)) { return }
        $pairs.Add(
            ([Uri]::EscapeDataString($Name)) + '=' +
            ([Uri]::EscapeDataString([string]$Value))
        )
    }

    Add-QueryPair 'acip' $meta.AcIp
    Add-QueryPair 'acname' $meta.AcName
    if (-not [string]::IsNullOrWhiteSpace($meta.UserIp)) {
        Add-QueryPair 'ip' $meta.UserIp
    }
    Add-QueryPair 'nasId' $meta.NasId
    Add-QueryPair 'userip' $meta.UserIp
    Add-QueryPair 'wlanacname' $meta.WlanAcName -IncludeEmpty

    $query = $pairs -join '&'
    $portal = [Uri](
        "http://{0}{1}{2}" -f
        $Script:AllowedPortalHosts[0],
        $Script:ExpectedPortalPath,
        $(if ($query) { "?$query" } else { '' })
    )

    if (-not (Test-TrustedPortalUri -Uri $portal)) {
        Throw-Whut 13 'ProtocolChanged: derived WHUT portal URI did not pass validation.'
    }

    return $portal
}

function Get-WhutNetworkHint {
    # Credential-free helper for setup. It lets WHUT's bootstrap identify the actual
    # campus-side physical IPv4 even when a TUN adapter owns the route table.
    $context = $null
    try {
        $context = New-HttpContext -TimeoutSeconds $Script:DiscoveryProbeSeconds
        $probe = $Script:PortalProbes[1] # NCSI content probe
        $result = Invoke-HttpText $context GET $probe.Uri `
            -TimeoutMilliseconds ($Script:DiscoveryProbeSeconds * 1000)

        if ($result.StatusCode -ge 300 -and $result.StatusCode -lt 400 -and
            $null -ne $result.Location) {

            $candidate = $null
            if ([Uri]::TryCreate([string]$result.Location, [UriKind]::Absolute, [ref]$candidate)) {
                if (Test-TrustedBootstrapUri -Uri $candidate) {
                    return (Get-WhutBootstrapMetadata -Uri $candidate).UserIp
                }

                if (Test-TrustedPortalUri -Uri $candidate) {
                    $hint = Get-QueryValue -Uri $candidate -Name 'userip'
                    if ([string]::IsNullOrWhiteSpace($hint)) {
                        $hint = Get-QueryValue -Uri $candidate -Name 'ip'
                    }
                    return $hint
                }
            }
        }
    }
    catch {}
    finally {
        Close-HttpContext $context
    }

    return $null
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
    # Credential-free preflight answers only whether Internet access is proven.
    # Redirects are not followed and never authorize a credential destination.
    foreach ($probe in @($Script:PortalProbes[1], $Script:PortalProbes[2])) {
        $context = $null
        try {
            $context = New-HttpContext -TimeoutSeconds $Script:DiscoveryProbeSeconds
            $result = Invoke-HttpText $context GET $probe.Uri `
                -TimeoutMilliseconds ($Script:DiscoveryProbeSeconds * 1000)

            if (Test-InternetResponse $probe.Name $result) {
                return $true
            }

            if ($result.StatusCode -ge 300 -and $result.StatusCode -lt 400) {
                if ($null -ne $result.Location) {
                    $candidate = $null
                    if ([Uri]::TryCreate([string]$result.Location, [UriKind]::Absolute, [ref]$candidate)) {
                        if (Test-TrustedPortalUri -Uri $candidate) {
                            Write-Log INFO "preflight=$($probe.Name) result=whut-portal-redirect"
                            return $false
                        }
                        if (Test-TrustedBootstrapUri -Uri $candidate) {
                            Write-Log INFO "preflight=$($probe.Name) result=whut-bootstrap-redirect"
                            return $false
                        }
                        if ($Script:AllowedPortalHosts -ccontains $candidate.Host) {
                            Throw-Whut 13 'ProtocolChanged: preflight returned an unknown WHUT destination.'
                        }
                    }
                }

                # A foreign/unknown redirect only means the expected Internet identity
                # was not obtained. Do not trust/follow it, but continue discovery.
                Write-Log WARN "preflight=$($probe.Name) result=redirect-ignored"
            }
        }
        catch [System.OperationCanceledException] {
            Write-Log WARN "preflight=$($probe.Name) result=timeout"
        }
        catch {
            if ($_.Exception.Data['ExitCode'] -eq 13) { throw }
            Write-Log WARN "preflight=$($probe.Name) result=unreachable"
        }
        finally {
            Close-HttpContext $context
        }
    }

    return $false
}

function Test-InternetResponse {
    param([string]$Probe, $Result)

    if ($Result.StatusCode -ne 200) { return $false }
    if ($Probe -eq 'msft-connecttest') {
        return ($Result.Body.Trim() -ceq $Script:InternetProbeExpected)
    }
    if ($Probe -eq 'neverssl') {
        return ($Result.Body -match '(?i)<title>\s*NeverSSL\s*</title>')
    }
    return $false
}

function Find-WhutPortal {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $directUnavailable = $false

    foreach ($probe in $Script:PortalProbes) {
        $remaining = [int]($Script:DiscoveryBudgetSeconds * 1000 - $timer.ElapsedMilliseconds)
        if ($remaining -le 0) {
            $timedOut = $true
            break
        }

        $context = $null
        try {
            $context = New-HttpContext -TimeoutSeconds $Script:DiscoveryProbeSeconds
            $timeout = [Math]::Min($remaining, $Script:DiscoveryProbeSeconds * 1000)
            $result = Invoke-HttpText $context GET $probe.Uri -TimeoutMilliseconds $timeout

            if ($result.StatusCode -ge 300 -and $result.StatusCode -lt 400) {
                Write-Log INFO "probe=$($probe.Name) result=redirect"

                if ($null -eq $result.Location) {
                    Write-Log WARN "probe=$($probe.Name) result=redirect-without-location"
                    continue
                }

                $candidate = $null
                $location = [string]$result.Location
                if (-not [Uri]::TryCreate($probe.Uri, $location, [ref]$candidate)) {
                    Write-Log WARN "probe=$($probe.Name) result=invalid-redirect-ignored"
                    continue
                }

                $safeLocation = Test-SafeWhutRedirectLocation $location
                if ($safeLocation -and (Test-TrustedPortalUri -Uri $candidate)) {
                    Write-Log INFO 'portal=trusted result=PortalRedirectFound'

                    $userIpHint = Get-QueryValue -Uri $candidate -Name 'userip'
                    if ([string]::IsNullOrWhiteSpace($userIpHint)) {
                        $userIpHint = Get-QueryValue -Uri $candidate -Name 'ip'
                    }

                    return [pscustomobject]@{
                        State      = 'PortalRedirectFound'
                        Portal     = $candidate
                        NasId      = Get-QueryValue -Uri $candidate -Name 'nasId'
                        UserIpHint = $userIpHint
                        Bootstrap  = $null
                        ExitCode   = 0
                    }
                }

                if ($safeLocation -and (Test-TrustedBootstrapUri -Uri $candidate)) {
                    $meta = Get-WhutBootstrapMetadata -Uri $candidate
                    $portal = Convert-BootstrapToPortalUri -BootstrapUri $candidate
                    Write-Log INFO "portal=trusted result=WhutBootstrapFound nasId=$($meta.NasId)"

                    return [pscustomobject]@{
                        State      = 'WhutBootstrapFound'
                        Portal     = $portal
                        NasId      = $meta.NasId
                        UserIpHint = $meta.UserIp
                        Bootstrap  = $candidate
                        ExitCode   = 0
                    }
                }

                # A redirect to the allowlisted WHUT host on an unknown path is
                # evidence of protocol drift and should fail closed.
                if ($Script:AllowedPortalHosts -ccontains $candidate.Host) {
                    Write-Log WARN "probe=$($probe.Name) result=unknown-whut-path"
                    return [pscustomobject]@{
                        State      = 'ProtocolChanged'
                        Portal     = $null
                        NasId      = $null
                        UserIpHint = $null
                        Bootstrap  = $null
                        ExitCode   = 13
                    }
                }

                Write-Log WARN "probe=$($probe.Name) result=foreign-redirect-ignored"
                continue
            }

            if (Test-InternetResponse $probe.Name $result) {
                Write-Log INFO "probe=$($probe.Name) result=InternetOnline"
                return [pscustomobject]@{
                    State = 'InternetOnline'; Portal = $null; NasId = $null
                    UserIpHint = $null; Bootstrap = $null; ExitCode = 0
                }
            }

            if ($probe.Name -eq 'whut-direct' -and $result.StatusCode -eq 200) {
                Write-Log INFO 'probe=whut-direct result=WhutPortalReachable portal=trusted'
                return [pscustomobject]@{
                    State      = 'WhutPortalReachable'
                    Portal     = $probe.Uri
                    NasId      = $null
                    UserIpHint = $null
                    Bootstrap  = $null
                    ExitCode   = 0
                }
            }

            Write-Log INFO "probe=$($probe.Name) result=http-$($result.StatusCode)"
            if ($probe.Name -eq 'whut-direct' -and $result.StatusCode -ge 500) {
                $directUnavailable = $true
            }
        }
        catch [System.OperationCanceledException] {
            $timedOut = $true
            Write-Log WARN "probe=$($probe.Name) result=timeout state=ProbeTimeout"
        }
        catch {
            if ($_.Exception.Data['ExitCode'] -eq 13) { throw }
            Write-Log WARN "probe=$($probe.Name) result=unreachable"
            if ($probe.Name -eq 'whut-direct') {
                $directUnavailable = $true
            }
        }
        finally {
            Close-HttpContext $context
        }
    }

    $state = if ($timedOut) {
        'ProbeTimeout'
    }
    elseif ($directUnavailable) {
        'PortalUnreachable'
    }
    else {
        'PortalNotFound'
    }

    $code = if ($timedOut) { 31 } elseif ($directUnavailable) { 30 } else { 11 }
    Write-Log WARN "discovery=$state"

    return [pscustomobject]@{
        State = $state; Portal = $null; NasId = $null
        UserIpHint = $null; Bootstrap = $null; ExitCode = $code
    }
}

function Start-WhutSession {
    param(
        [Parameter(Mandatory)]
        [Uri]$PortalUri,
        [Uri]$BootstrapUri
    )

    if (-not (Test-TrustedPortalUri -Uri $PortalUri)) {
        Throw-Whut 12 'Refusing to start a session with an untrusted portal.'
    }

    if ($null -ne $BootstrapUri -and -not (Test-TrustedBootstrapUri -Uri $BootstrapUri)) {
        Throw-Whut 12 'Refusing to start a session with an untrusted bootstrap URI.'
    }

    $context = New-HttpContext

    try {
        # Replay /api/r/<nasId> in the same cookie jar. No credential exists yet.
        if ($null -ne $BootstrapUri) {
            $bootstrapResult = Invoke-HttpText -Context $context -Method GET -Uri $BootstrapUri -Headers @{
                'Accept' = 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'
            }

            if ($bootstrapResult.StatusCode -ge 300 -and $bootstrapResult.StatusCode -lt 400) {
                if ($null -eq $bootstrapResult.Location) {
                    Throw-Whut 13 'ProtocolChanged: WHUT bootstrap redirect has no Location.'
                }

                $next = $null
                if (-not [Uri]::TryCreate(
                    $BootstrapUri,
                    [string]$bootstrapResult.Location,
                    [ref]$next
                )) {
                    Throw-Whut 13 'ProtocolChanged: WHUT bootstrap redirect is invalid.'
                }

                if (-not (Test-SafeWhutRedirectLocation ([string]$bootstrapResult.Location)) -or
                    (-not (Test-TrustedPortalUri -Uri $next) -and
                     -not (Test-TrustedBootstrapUri -Uri $next))) {
                    Throw-Whut 13 'ProtocolChanged: WHUT bootstrap redirected outside the known protocol.'
                }

                Write-Log INFO 'protocol=bootstrap-handshake redirect=validated'
            }
            elseif ($bootstrapResult.StatusCode -lt 200 -or $bootstrapResult.StatusCode -ge 400) {
                Throw-Whut 30 "WHUT bootstrap handshake failed with HTTP $($bootstrapResult.StatusCode)."
            }
        }

        $headers = @{
            'Accept'  = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            'Referer' = (Get-Origin -Uri $PortalUri) + '/'
        }

        $result = Invoke-HttpText -Context $context -Method GET -Uri $PortalUri -Headers $headers
        if ($result.StatusCode -ne 200) {
            Throw-Whut 30 "WHUT portal handshake failed with HTTP $($result.StatusCode)."
        }

        return $context
    }
    catch {
        Close-HttpContext $context
        if ($null -ne $_.Exception.Data['ExitCode']) { throw }
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
        # Only accept executable top-level var/let/const assignments. A commented-out
        # WHUT test URL such as //var host_url = 'http://192.168.x.x/api' must not
        # create a false ambiguity. Deduplicate identical active values.
        $matches = [regex]::Matches(
            ([regex]::Replace($result.Body, '(?s)/\*.*?\*/', '')),
            '(?m)^\s*(?:var|let|const)\s+host_url\s*=\s*[''"]([^''"]+)[''"]\s*;?'
        )
        $paths = @(
            $matches |
                ForEach-Object { $_.Groups[1].Value } |
                Sort-Object -Unique -CaseSensitive
        )

        if ($paths.Count -gt 1) {
            Throw-Whut 13 'ProtocolChanged: multiple distinct API base paths.'
        }

        if ($paths.Count -eq 1) {
            $path = $paths[0]
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
          [string]$NasId, [string]$User, $Config, [switch]$Automatic, [string]$UserIpHint)
    $uri = Get-WhutApiUri $PortalUri $ApiBasePath $Script:WhutProtocol.LoginPath
    if ([string]::IsNullOrWhiteSpace($NasId) -or $NasId.Length -gt 1024 -or $NasId -match '[\x00-\x1f\x7f]') {
        Throw-Whut 11 'Trusted portal is reachable, but a valid session nasId was not discovered.'
    }
    # Re-read the actual route immediately before releasing the credential.
    if (-not (Test-TrustedLocalNetwork $Config -Automatic:$Automatic -UserIpHint $UserIpHint)) {
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

    $nasId = $discovery.NasId
    if ([string]::IsNullOrWhiteSpace([string]$nasId)) {
        $nasId = Get-QueryValue -Uri $portal -Name 'nasId'
    }

    $userIpHint = $discovery.UserIpHint
    if ([string]::IsNullOrWhiteSpace([string]$userIpHint)) {
        $userIpHint = Get-QueryValue -Uri $portal -Name 'userip'
        if ([string]::IsNullOrWhiteSpace([string]$userIpHint)) {
            $userIpHint = Get-QueryValue -Uri $portal -Name 'ip'
        }
    }

    # Direct reachability permits diagnostics; login still requires a discovered nasId.
    $session = Start-WhutSession -PortalUri $portal -BootstrapUri $discovery.Bootstrap

    try {
        $apiBase = Get-ApiBasePath -Context $session -PortalUri $portal
        $csrf = Get-CsrfToken -Context $session -PortalUri $portal -ApiBasePath $apiBase

        return [pscustomobject]@{
            Portal      = $portal
            NasId       = $nasId
            ApiBasePath = $apiBase
            CsrfToken   = $csrf
            UserIpHint  = $userIpHint
            Bootstrap   = $discovery.Bootstrap
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
            -Config $config -Automatic:$Automatic `
            -UserIpHint $resolved.UserIpHint)

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
        Write-Host "Bootstrap:  $(if ($resolved.Bootstrap) { 'recognized /api/r/<nasId>' } else { 'not required / not observed' })"
        Write-Host "nasId:      $(if ($resolved.NasId) { 'present' } else { 'missing; login unavailable' })"
        $fingerprint = Get-CurrentNetworkFingerprint -UserIpHint $resolved.UserIpHint
        Write-Host "Physical:   $(if ($fingerprint) { 'OK (' + $fingerprint.interfaceAlias + ', ' + $fingerprint.ipv4Prefix + ')' } else { 'unresolved' })"
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
        [string]$RequestedUsername,
        [switch]$AddNetwork
    )

    Ensure-DataDirectory

    if ($AddNetwork) {
        $config = Read-Config
        if (-not (Test-Path -LiteralPath $Script:CredentialPath)) {
            Throw-Whut 50 'Run setup with a password before adding a network.'
        }
        if ($RequestedUsername -and $RequestedUsername -cne [string]$config.username) {
            Throw-Whut 50 'AddNetwork retains the existing account; do not specify a different username.'
        }
        $hint = Get-WhutNetworkHint
        $current = Get-CurrentNetworkFingerprint -UserIpHint $hint
        if ($null -eq $current) { Throw-Whut 12 'No unambiguous physical network to register. Connect to WHUT and retry.' }
        $registered = @(Get-RegisteredNetworks $config)
        foreach ($trusted in $registered) {
            if (Test-NetworkFingerprintMatch $current $trusted -Automatic) {
                Write-Log INFO 'This physical network fingerprint is already registered.'
                return 0
            }
        }
        Write-Config ([pscustomobject]@{
            version = 3; username = [string]$config.username
            trustedNetworks = @($registered) + @($current)
        })
        Write-Log INFO 'Additional physical network explicitly registered; existing account and credential retained.'
        return 0
    }

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
        $networkHint = Get-WhutNetworkHint
        $trustedNetwork = Get-CurrentNetworkFingerprint -UserIpHint $networkHint
        $config = [ordered]@{
            version = 3
            username = $user
            trustedNetworks = @($trustedNetwork | Where-Object { $null -ne $_ })
        }
        # ConvertFrom-SecureString without -Key uses DPAPI CurrentUser on Windows.
        $encrypted = $password | ConvertFrom-SecureString
        Set-Content -LiteralPath $Script:CredentialPath -Value $encrypted -Encoding utf8
        Write-Config $config
    }
    finally { $password.Dispose(); $password = $null; $encrypted = $null }
    Write-Log INFO 'Configuration v3 saved. Password is protected with Windows DPAPI CurrentUser.'
    if ($null -ne $trustedNetwork) {
        Write-Log INFO 'Trusted physical network fingerprint saved (TUN/VPN routes ignored).'
    }
    else {
        Write-Log WARN 'No unambiguous physical network fingerprint captured. Disconnect extra physical uplinks or run setup again on WHUT.'
    }
    Write-Log WARN 'The WHUT portal currently uses HTTP; the network transport itself is not end-to-end encrypted.'
    return 0
}

function Resolve-PwshExecutable {
    # App Execution Alias survives Store package upgrades and always returns a scalar.
    $preferred = @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pwsh.exe'),
        (Join-Path $PSHOME 'pwsh.exe')
    )
    foreach ($path in $preferred) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { return [string]$path }
    }

    $candidates = @(
        Get-Command pwsh.exe -All -CommandType Application -ErrorAction SilentlyContinue |
            ForEach-Object { [string]$_.Source } |
            Where-Object {
                $_ -match '^[A-Za-z]:\\' -and $_ -notmatch '["\x00-\x1f\x7f]' -and
                [IO.Path]::GetFileName($_) -ieq 'pwsh.exe' -and
                (Test-Path -LiteralPath $_ -PathType Leaf)
            } | Sort-Object -Unique
    )
    if ($candidates.Count -ne 1) {
        Throw-Whut 50 'No unique PowerShell executable found. Enable the Store pwsh alias or install PowerShell 7.'
    }
    return [string]$candidates[0]
}

function New-WhutTaskActionSpec {
    param([string]$ScriptPath = $PSCommandPath)
    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or
        -not [IO.Path]::IsPathFullyQualified($ScriptPath) -or
        $ScriptPath -match '["\x00-\x1f\x7f]' -or
        -not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        Throw-Whut 50 'The script must be saved at a valid absolute path before installing the task.'
    }
    return [pscustomobject]@{
        Execute = [string](Resolve-PwshExecutable)
        Arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}" auto' -f $ScriptPath
        WorkingDirectory = [string](Split-Path -Parent $ScriptPath)
    }
}

function Install-WhutScheduledTask {
    if (-not (Test-Path -LiteralPath $Script:ConfigPath) -or
        -not (Test-Path -LiteralPath $Script:CredentialPath)) {
        Throw-Whut 50 'Run setup before installing the scheduled task.'
    }

    $config = Read-Config
    if (-not (Test-TrustedLocalNetwork $config -Automatic)) {
        Throw-Whut 50 'Install requires a registered physical network fingerprint. Run setup on WHUT.'
    }

    $actionSpec = New-WhutTaskActionSpec -ScriptPath $PSCommandPath

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $root = $service.GetFolder('\')
    $task = $service.NewTask(0)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    $task.RegistrationInfo.Description = "WHUT-Net v$Script:Version auto-login on user logon and network connection."
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
    $action.Path = $actionSpec.Execute
    $action.Arguments = $actionSpec.Arguments
    $action.WorkingDirectory = $actionSpec.WorkingDirectory

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
  .\whut-net.ps1 setup -AddNetwork
  .\whut-net.ps1 status
  .\whut-net.ps1 login
  .\whut-net.ps1 auto
  .\whut-net.ps1 diagnose
  .\whut-net.ps1 install
  .\whut-net.ps1 uninstall
  .\whut-net.ps1 help

Commands:
  setup       Save account/password and current network; -AddNetwork appends without changing the account.
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
  - Auto requires a matching registered physical IPv4 prefix, gateway and interface fingerprint.
  - Config v3 stores trustedNetworks[]; v2 single fingerprints migrate automatically.
  - setup -AddNetwork explicitly registers another WHUT network; profile names never add trust.
  - Profile names are auxiliary; rerun setup to upgrade v1 without automatic migration.
  - Discovery: NCSI redirect/content, NeverSSL, direct WHUT; /api/r/<nasId> bootstrap is recognized.
  - Internet preflight never follows foreign redirects; unknown redirects are ignored and discovery continues.
  - Protocol shapes are checked; commented-out config.js host_url test values are ignored.
  - /api fallback requires an active CSRF fingerprint.
  - Physical fingerprint selection ignores virtual/TUN routes; WHUT userip is used as a credential-free hint.
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
    if ($AddNetwork -and $Command -ne 'setup') { Throw-Whut 50 'AddNetwork is only valid with setup.' }
    switch ($Command) {
        'help'     { $exitCode = Show-Help }
        'setup'    { $exitCode = Invoke-SetupCommand -RequestedUsername $Username -AddNetwork:$AddNetwork }
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
