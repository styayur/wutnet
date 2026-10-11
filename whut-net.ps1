#requires -Version 7.2
#requires -PSEdition Core
<#
.SYNOPSIS
    WHUT-Net v1.4.0 - Lightweight Wuhan University of Technology campus network authenticator.

.DESCRIPTION
    Windows-only, zero third-party dependency PowerShell client for the WHUT captive portal.
    Features:
      - Direct HTTP with proxy bypass (UseProxy = false)
      - Strict WHUT portal allowlist before credentials are sent
      - Dynamic nasId discovery
      - Dynamic API base path discovery from config.js
      - CSRF + cookie session handling
      - DPAPI-protected password storage (CurrentUser)
      - Multi-network trustedNetworks[] store for cross-campus roaming
      - Smart Trust & Connect flow for newly verified WHUT networks
      - Login / status / auto / diagnose + JSON machine output
      - Task Scheduler auto-login with single-instance cooldown/backoff

    The current WHUT portal uses HTTP. DPAPI protects the password at rest, but cannot
    add transport encryption to a server that only exposes HTTP.

.NOTES
    Version: 1.4.0
    Target: PowerShell 7.2+ on Windows 10/11
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        'run', 'help', 'setup', 'status', 'login', 'auto', 'diagnose',
        'trust-current', 'networks', 'remove-network', 'install', 'uninstall'
    )]
    [string]$Command = 'run',

    [string]$Username,
    [string]$NetworkId,
    [string]$Label,
    [switch]$AddNetwork,
    [switch]$Json,
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:Version = '1.4.0'
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
$Script:ConfigVersion = 3
$Script:AutoCooldownSeconds = 30
$Script:AutoBackoffSeconds = @(30, 120, 300)

if (-not $IsWindows) {
    Write-Error 'WHUT-Net v1.4.0 is Windows-only because credential protection uses Windows DPAPI.'
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
$Script:AutoStatePath = Join-Path $Script:DataDir 'auto-state.json'
$Script:JsonMode = [bool]$Json

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

function Get-NetworkFingerprintId {
    param([Parameter(Mandatory)]$Fingerprint)

    $material = @(
        [string](Get-ObjectProperty $Fingerprint 'ipv4Prefix' '')
        [string](Get-ObjectProperty $Fingerprint 'defaultGateway' '')
        [string](Get-ObjectProperty $Fingerprint 'portalHost' '')
        [string](Get-ObjectProperty $Fingerprint 'interfaceType' '')
    ) -join '|'

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($material)
        $hash = $sha.ComputeHash($bytes)
        return ([Convert]::ToHexString($hash).Substring(0, 12)).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function New-TrustedNetworkEntry {
    param(
        [Parameter(Mandatory)]$Fingerprint,
        [string]$RequestedLabel
    )

    $labelValue = $RequestedLabel
    if ([string]::IsNullOrWhiteSpace($labelValue)) {
        $labelValue = [string](Get-ObjectProperty $Fingerprint 'profileName' '')
    }
    if ([string]::IsNullOrWhiteSpace($labelValue)) {
        $labelValue = '{0} {1}' -f `
            [string](Get-ObjectProperty $Fingerprint 'interfaceAlias' 'Network'),
            [string](Get-ObjectProperty $Fingerprint 'ipv4Prefix' '')
    }

    return [pscustomobject][ordered]@{
        id              = Get-NetworkFingerprintId -Fingerprint $Fingerprint
        label           = $labelValue.Trim()
        profileName     = [string](Get-ObjectProperty $Fingerprint 'profileName' '')
        interfaceAlias  = [string](Get-ObjectProperty $Fingerprint 'interfaceAlias' '')
        interfaceType   = [string](Get-ObjectProperty $Fingerprint 'interfaceType' '')
        ipv4Prefix      = [string](Get-ObjectProperty $Fingerprint 'ipv4Prefix' '')
        defaultGateway  = [string](Get-ObjectProperty $Fingerprint 'defaultGateway' '')
        portalHost      = [string](Get-ObjectProperty $Fingerprint 'portalHost' '')
        lastSeen        = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function Get-TrustedNetworks {
    param([AllowNull()]$Config)

    if ($null -eq $Config) { return @() }
    $version = [int](Get-ObjectProperty $Config 'version' 1)

    if ($version -ge 3) {
        return @(
            Get-ObjectProperty $Config 'trustedNetworks' @() |
                Where-Object { $null -ne $_ } |
                ForEach-Object {
                    if ([string]::IsNullOrWhiteSpace([string](Get-ObjectProperty $_ 'id' ''))) {
                        New-TrustedNetworkEntry -Fingerprint $_
                    } else { $_ }
                }
        )
    }

    if ($version -eq 2) {
        $single = Get-ObjectProperty $Config 'trustedNetwork'
        if ($null -ne $single) {
            $legacyLabel = [string](Get-ObjectProperty $single 'profileName' '')
            return @(New-TrustedNetworkEntry -Fingerprint $single -RequestedLabel $legacyLabel)
        }
    }

    return @()
}

function Test-NetworkFingerprintMatch {
    param(
        [Parameter(Mandatory)]$Trusted,
        [Parameter(Mandatory)]$Current,
        [switch]$Automatic
    )

    # Profile/SSID names are presentation only. A trusted network is identified by
    # physical network characteristics plus the independently verified WHUT portal.
    $fields = @('ipv4Prefix', 'defaultGateway', 'portalHost', 'interfaceType')
    foreach ($field in $fields) {
        $expected = [string](Get-ObjectProperty $Trusted $field '')
        $actual = [string](Get-ObjectProperty $Current $field '')
        if ([string]::IsNullOrWhiteSpace($expected) -or $expected -cne $actual) {
            return $false
        }
    }

    return $true
}

function Find-TrustedNetworkMatch {
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Current,
        [switch]$Automatic
    )

    foreach ($trusted in @(Get-TrustedNetworks -Config $Config)) {
        if (Test-NetworkFingerprintMatch -Trusted $trusted -Current $Current -Automatic:$Automatic) {
            return $trusted
        }
    }
    return $null
}

function Test-TrustedLocalNetwork {
    param($Config, [switch]$Automatic, [string]$UserIpHint)

    $current = Get-CurrentNetworkFingerprint -UserIpHint $UserIpHint
    if ($null -eq $current) { return $false }

    $version = [int](Get-ObjectProperty $Config 'version' 1)
    if ($version -eq 1) {
        # Legacy profile-only config remains readable for diagnostics but cannot
        # authorize credential release.
        return $false
    }

    return $null -ne (Find-TrustedNetworkMatch -Config $Config -Current $current -Automatic:$Automatic)
}

function Convert-ConfigToV3 {
    param(
        [Parameter(Mandatory)]$Config,
        [AllowNull()][object[]]$TrustedNetworks
    )

    if ($null -eq $TrustedNetworks) {
        $TrustedNetworks = @(Get-TrustedNetworks -Config $Config)
    }

    return [pscustomobject][ordered]@{
        version         = 3
        username        = [string](Get-ObjectProperty $Config 'username' '')
        trustedNetworks = @($TrustedNetworks)
    }
}

function Save-Config {
    param($Config)
    Ensure-DataDirectory
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

function Add-TrustedNetworkToConfig {
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Fingerprint,
        [string]$RequestedLabel
    )

    $networks = [Collections.Generic.List[object]]::new()
    foreach ($item in @(Get-TrustedNetworks -Config $Config)) {
        $networks.Add($item)
    }

    $newEntry = New-TrustedNetworkEntry -Fingerprint $Fingerprint -RequestedLabel $RequestedLabel
    $existingIndex = -1

    for ($i = 0; $i -lt $networks.Count; $i++) {
        if (Test-NetworkFingerprintMatch -Trusted $networks[$i] -Current $Fingerprint) {
            $existingIndex = $i
            break
        }
    }

    if ($existingIndex -ge 0) {
        $existing = $networks[$existingIndex]
        if ([string]::IsNullOrWhiteSpace($RequestedLabel)) {
            $newEntry.label = [string](Get-ObjectProperty $existing 'label' $newEntry.label)
        }
        $newEntry.id = [string](Get-ObjectProperty $existing 'id' $newEntry.id)
        $networks[$existingIndex] = $newEntry
    }
    else {
        $networks.Add($newEntry)
    }

    $v3 = Convert-ConfigToV3 -Config $Config -TrustedNetworks @($networks.ToArray())
    Save-Config -Config $v3
    return $newEntry
}

function Remove-TrustedNetworkFromConfig {
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$Id
    )

    $remaining = @(
        Get-TrustedNetworks -Config $Config |
            Where-Object { [string](Get-ObjectProperty $_ 'id' '') -cne $Id }
    )
    $before = @(Get-TrustedNetworks -Config $Config).Count
    if ($remaining.Count -eq $before) {
        Throw-Whut 50 "Trusted network '$Id' was not found."
    }

    $v3 = Convert-ConfigToV3 -Config $Config -TrustedNetworks $remaining
    Save-Config -Config $v3
    return $remaining.Count
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

    if ($Script:JsonMode) { $Quiet = $true }

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

    $version = [int](Get-ObjectProperty $config 'version' 1)
    if ($version -notin @(1, 2, 3)) {
        Throw-Whut 50 'Unsupported configuration version.'
    }

    if ($version -eq 1) {
        Write-Log WARN 'Legacy v1 configuration cannot authorize auto-login. Run setup or trust-current on WHUT.'
    }
    elseif ($version -eq 2) {
        $config = Convert-ConfigToV3 -Config $config
        Save-Config -Config $config
        Write-Log INFO 'Configuration migrated from v2 to v3; existing network and credential retained.'
    }
    elseif ($version -eq 3) {
        $missingMetadata = @(Get-ObjectProperty $config 'trustedNetworks' @() | Where-Object {
            [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty $_ 'id' ''))
        })
        if ($missingMetadata.Count -gt 0) {
            $config = Convert-ConfigToV3 -Config $config
            Save-Config -Config $config
        }
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

function Write-ResultJson {
    param([Parameter(Mandatory)]$Object)

    # Dispatch stores a command's integer return value in $exitCode. Writing JSON
    # through the success pipeline would therefore be captured together with that
    # integer. Write directly to stdout so -Json remains machine-readable.
    $json = $Object | ConvertTo-Json -Depth 8 -Compress
    [Console]::Out.WriteLine($json)
}

function Test-TunLikeAdapterPresent {
    try {
        foreach ($cfg in @(Get-NetIPConfiguration -ErrorAction Stop)) {
            foreach ($addr in @($cfg.IPv4Address)) {
                if ($null -eq $addr) { continue }
                $ip = [string]$addr.IPAddress
                try {
                    $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
                    if ($b[0] -eq 198 -and $b[1] -in 18,19) { return $true }
                }
                catch {}
            }
        }
    }
    catch {}
    return $false
}

function Resolve-PwshExecutable {
    $alias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pwsh.exe'
    if (Test-Path -LiteralPath $alias) {
        return [string]$alias
    }

    $homePwsh = Join-Path $PSHOME 'pwsh.exe'
    if (Test-Path -LiteralPath $homePwsh) {
        return [string]$homePwsh
    }

    $candidates = @(
        Get-Command pwsh.exe -CommandType Application -All -ErrorAction SilentlyContinue |
            ForEach-Object { [string]$_.Source } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) } |
            Sort-Object -Unique
    )

    if ($candidates.Count -eq 1) {
        return [string]$candidates[0]
    }

    Throw-Whut 50 'Could not resolve a stable single pwsh.exe executable for Task Scheduler.'
}

function Get-AutoState {
    if (-not (Test-Path -LiteralPath $Script:AutoStatePath)) {
        return [pscustomobject]@{ failureCount = 0; nextAllowedUtc = $null }
    }
    try {
        return Get-Content -LiteralPath $Script:AutoStatePath -Raw -Encoding utf8 | ConvertFrom-Json
    }
    catch {
        return [pscustomobject]@{ failureCount = 0; nextAllowedUtc = $null }
    }
}

function Save-AutoState {
    param([int]$FailureCount, [AllowNull()][DateTimeOffset]$NextAllowedUtc)
    Ensure-DataDirectory
    [pscustomobject]@{
        failureCount  = $FailureCount
        nextAllowedUtc = if ($null -eq $NextAllowedUtc) { $null } else { $NextAllowedUtc.ToString('o') }
    } | ConvertTo-Json | Set-Content -LiteralPath $Script:AutoStatePath -Encoding utf8
}

function Get-AutoCooldownRemaining {
    $state = Get-AutoState
    $raw = Get-ObjectProperty $state 'nextAllowedUtc'
    if ([string]::IsNullOrWhiteSpace([string]$raw)) { return 0 }

    try {
        $next = [DateTimeOffset]::Parse([string]$raw)
        $seconds = [int][Math]::Ceiling(($next - [DateTimeOffset]::UtcNow).TotalSeconds)
        return [Math]::Max(0, $seconds)
    }
    catch { return 0 }
}

function Register-AutoSuccess {
    Save-AutoState -FailureCount 0 -NextAllowedUtc ([DateTimeOffset]::UtcNow.AddSeconds($Script:AutoCooldownSeconds))
}

function Register-AutoFailure {
    $state = Get-AutoState
    $count = [int](Get-ObjectProperty $state 'failureCount' 0) + 1
    $index = [Math]::Min($count - 1, $Script:AutoBackoffSeconds.Count - 1)
    $delay = [int]$Script:AutoBackoffSeconds[$index]
    Save-AutoState -FailureCount $count -NextAllowedUtc ([DateTimeOffset]::UtcNow.AddSeconds($delay))
}

function Enter-AutoMutex {
    $created = $false
    $mutex = [Threading.Mutex]::new($true, 'Local\WUTNet-Auto-v1', [ref]$created)
    if (-not $created) {
        $mutex.Dispose()
        return $null
    }
    return $mutex
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

function Test-SafeWhutRedirectLocation {
    param([string]$Location)
    # Absolute destinations still pass the full URI allowlist below. For relative
    # redirects, prevent System.Uri from normalizing a lookalike into an allowed path.
    if ($Location -cmatch '^https?://') { return $true }
    return ($Location -cmatch '^/(?:api/r/[0-9]{1,10}|tpl/whut/login\.html)(?:\?[^#\\\x00-\x20\x7f]*)?\z')
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
    # Re-read the physical network immediately before releasing the credential.
    if (-not (Test-TrustedLocalNetwork $Config -Automatic:$Automatic -UserIpHint $UserIpHint)) {
        Throw-Whut 12 'Current physical network changed or is no longer trusted; credentials were not sent.'
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

function Invoke-NetworksCommand {
    $config = Read-Config
    $networks = @(Get-TrustedNetworks -Config $config)

    if ($Script:JsonMode) {
        Write-ResultJson ([pscustomobject]@{
            state = 'TrustedNetworks'
            version = [int](Get-ObjectProperty $config 'version' 1)
            count = $networks.Count
            networks = $networks
        })
        return 0
    }

    if ($networks.Count -eq 0) {
        Write-Host 'No trusted physical WHUT networks are registered.'
        return 0
    }

    $networks |
        Select-Object id, label, ipv4Prefix, defaultGateway, interfaceType, lastSeen |
        Format-Table -AutoSize |
        Out-Host
    return 0
}

function Invoke-RemoveNetworkCommand {
    param([string]$Id)

    if ([string]::IsNullOrWhiteSpace($Id)) {
        Throw-Whut 50 'remove-network requires -NetworkId <id>.'
    }

    $config = Read-Config
    $remaining = Remove-TrustedNetworkFromConfig -Config $config -Id $Id

    if ($Script:JsonMode) {
        Write-ResultJson ([pscustomobject]@{
            state = 'TrustedNetworkRemoved'
            id = $Id
            remaining = $remaining
        })
    }
    else {
        Write-Host "[INFO]  Trusted network '$Id' removed. Remaining: $remaining"
    }
    return 0
}

function Invoke-TrustCurrentCommand {
    param([string]$RequestedLabel)

    $config = Read-Config

    if (Test-Internet) {
        Throw-Whut 50 'Current Internet is already validated. Reconnect while captive so WHUT can be verified before trusting this network.'
    }

    $resolved = $null
    try {
        $resolved = Resolve-PortalSession
        if ($null -eq $resolved) {
            Throw-Whut 50 'No captive WHUT session is available to verify the current network.'
        }

        if ([string]::IsNullOrWhiteSpace([string]$resolved.NasId)) {
            Throw-Whut 11 'A current WHUT session nasId is required before registering this network.'
        }

        # Require a valid status response before persisting the new network.
        [void](Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken)

        $fingerprint = Get-CurrentNetworkFingerprint -UserIpHint $resolved.UserIpHint
        if ($null -eq $fingerprint) {
            Throw-Whut 50 'Could not identify one unambiguous physical network.'
        }

        $entry = Add-TrustedNetworkToConfig `
            -Config $config `
            -Fingerprint $fingerprint `
            -RequestedLabel $RequestedLabel

        if ($Script:JsonMode) {
            Write-ResultJson ([pscustomobject]@{
                state = 'TrustedNetworkAdded'
                network = $entry
            })
        }
        else {
            Write-Host "[INFO]  Trusted current WHUT network: $($entry.label) [$($entry.id)]"
        }
        return 0
    }
    finally {
        if ($null -ne $resolved) {
            Close-HttpContext $resolved.Session
        }
    }
}

function Invoke-StatusCommand {
    if (Test-Internet) {
        Write-Log INFO 'ONLINE: direct Internet probe succeeded.'
        if ($Script:JsonMode) {
            Write-ResultJson ([pscustomobject]@{
                state = 'Online'
                exitCode = 0
            })
        }
        return 0
    }

    $resolved = $null
    try {
        $resolved = Resolve-PortalSession
        if ($null -eq $resolved) {
            if ($Script:JsonMode) {
                Write-ResultJson ([pscustomobject]@{ state = 'Online'; exitCode = 0 })
            }
            return 0
        }

        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        $code = [int](Get-ObjectProperty -Object $status -Name 'code')
        $config = $null
        $trusted = $false
        if (Test-Path -LiteralPath $Script:ConfigPath) {
            $config = Read-Config
            $trusted = Test-TrustedLocalNetwork -Config $config -UserIpHint $resolved.UserIpHint
        }

        if ($Script:JsonMode) {
            Write-ResultJson ([pscustomobject]@{
                state = if ($code -eq $Script:WhutProtocol.OnlineCode) {
                    'WhutAccountOnlineButInternetUnavailable'
                } else {
                    'AuthenticationRequired'
                }
                exitCode = if ($code -eq $Script:WhutProtocol.OnlineCode) { 40 } else { 10 }
                portalVerified = $true
                networkTrusted = [bool]$trusted
                nasIdPresent = -not [string]::IsNullOrWhiteSpace([string]$resolved.NasId)
                apiBase = $resolved.ApiBasePath
            })
        }

        if ($code -eq $Script:WhutProtocol.OnlineCode) {
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
        [switch]$Automatic,
        [switch]$PromptForTrust
    )

    if (Test-Internet) {
        Write-Log INFO 'ONLINE: no authentication needed.'
        if ($Script:JsonMode) {
            Write-ResultJson ([pscustomobject]@{ state = 'Online'; exitCode = 0 })
        }
        return 0
    }

    $resolved = $null
    try {
        $resolved = Resolve-PortalSession
        if ($null -eq $resolved) {
            if ($Script:JsonMode) {
                Write-ResultJson ([pscustomobject]@{ state = 'Online'; exitCode = 0 })
            }
            return 0
        }

        Write-Log INFO 'Trusted WHUT portal discovered.'

        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        if ([int](Get-ObjectProperty -Object $status -Name 'code') -eq $Script:WhutProtocol.OnlineCode) {
            if (Test-Internet) {
                Write-Log INFO 'ONLINE: account and Internet probes both succeeded.'
                if ($Script:JsonMode) {
                    Write-ResultJson ([pscustomobject]@{ state = 'Online'; exitCode = 0 })
                }
                return 0
            }

            Write-Log WARN 'Account is authenticated, but Internet connectivity is unavailable.'
            if ($Script:JsonMode) {
                Write-ResultJson ([pscustomobject]@{
                    state = 'WhutAccountOnlineButInternetUnavailable'
                    exitCode = 40
                })
            }
            return 40
        }

        if ([string]::IsNullOrWhiteSpace([string]$resolved.NasId)) {
            Throw-Whut 11 'A current WHUT session nasId is required before authentication or registration.'
        }
        $config = Read-Config
        $current = Get-CurrentNetworkFingerprint -UserIpHint $resolved.UserIpHint
        if ($null -eq $current) {
            Throw-Whut 12 'Current physical network could not be identified safely.'
        }

        $match = Find-TrustedNetworkMatch -Config $config -Current $current -Automatic:$Automatic

        if ($null -eq $match) {
            if ($Script:JsonMode) {
                Write-ResultJson ([pscustomobject]@{
                    state = 'NewWhutNetwork'
                    exitCode = 14
                    portalVerified = $true
                    networkTrusted = $false
                    interface = $current.interfaceAlias
                    ipv4Prefix = $current.ipv4Prefix
                })
                return 14
            }

            if ($Automatic -or -not $PromptForTrust) {
                Throw-Whut 14 'New WHUT physical network detected; explicit trust is required before credentials can be sent.'
            }

            Write-Host ''
            Write-Host 'New WHUT network detected.' -ForegroundColor Yellow
            Write-Host "  Interface: $($current.interfaceAlias)"
            Write-Host "  Prefix:    $($current.ipv4Prefix)"
            Write-Host '  Portal:    verified'
            Write-Host ''

            $approved = $Yes
            if (-not $approved) {
                $answer = Read-Host 'Trust this network and connect? [y/N]'
                $approved = $answer -match '^(?i:y|yes)$'
            }

            if (-not $approved) {
                Throw-Whut 14 'Current WHUT network was not trusted; credentials were not sent.'
            }

            $entry = Add-TrustedNetworkToConfig `
                -Config $config `
                -Fingerprint $current `
                -RequestedLabel $Label
            Write-Log INFO "Trusted new WHUT network '$($entry.label)' [$($entry.id)]."
            $config = Read-Config
        }

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
        if ($Script:JsonMode) {
            Write-ResultJson ([pscustomobject]@{
                state = 'Online'
                exitCode = 0
                authenticated = $true
            })
        }
        return 0
    }
    finally {
        if ($null -ne $resolved) {
            Close-HttpContext $resolved.Session
        }
    }
}

function Invoke-RunCommand {
    # Smart default: online -> exit; known WHUT -> connect; new verified WHUT ->
    # one explicit Trust & Connect prompt.
    return Invoke-LoginCommand -PromptForTrust
}

function Invoke-AutoCommand {
    $mutex = Enter-AutoMutex
    if ($null -eq $mutex) {
        Write-Log INFO 'auto=skipped reason=already-running'
        if ($Script:JsonMode) { Write-ResultJson ([pscustomobject]@{state='Skipped';reason='already-running';exitCode=0}) }
        return 0
    }

    try {
        $remaining = Get-AutoCooldownRemaining
        if ($remaining -gt 0) {
            Write-Log INFO "auto=skipped reason=cooldown remaining=${remaining}s"
            if ($Script:JsonMode) { Write-ResultJson ([pscustomobject]@{state='Skipped';reason='cooldown';exitCode=0}) }
            return 0
        }

        try {
            $code = Invoke-LoginCommand -Automatic
            if ($code -eq 0) {
                Register-AutoSuccess
            }
            else {
                Register-AutoFailure
            }
            return $code
        }
        catch {
            Register-AutoFailure
            throw
        }
    }
    finally {
        try { $mutex.ReleaseMutex() } catch {}
        $mutex.Dispose()
    }
}

function Invoke-DiagnoseCommand {
    if (-not $Script:JsonMode) {
        Write-Host "WHUT-Net v$Script:Version diagnostics"
        Write-Host ('-' * 52)
        Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
        Write-Host "Config:     $(if (Test-Path -LiteralPath $Script:ConfigPath) { 'present' } else { 'missing' })"
        Write-Host "Credential: $(if (Test-Path -LiteralPath $Script:CredentialPath) { 'present (DPAPI)' } else { 'missing' })"
        Write-Host "HTTP_PROXY: $(if ([string]::IsNullOrWhiteSpace($env:HTTP_PROXY)) { 'not set' } else { 'set (ignored by WHUT-Net)' })"
        Write-Host "HTTPS_PROXY:$(if ([string]::IsNullOrWhiteSpace($env:HTTPS_PROXY)) { ' not set' } else { ' set (ignored by WHUT-Net)' })"
        Write-Host "VPN/TUN:    $(if (Test-TunLikeAdapterPresent) { 'detected' } else { 'not detected' })"
    }

    $internet = Test-Internet
    if (-not $Script:JsonMode) {
        Write-Host "Internet:   $(if ($internet) { 'OK' } else { 'failed / captive' })"
    }

    if ($internet) {
        if ($Script:JsonMode) {
            Write-ResultJson ([pscustomobject]@{
                state = 'Online'
                powershell = [string]$PSVersionTable.PSVersion
                configPresent = Test-Path -LiteralPath $Script:ConfigPath
                credentialPresent = Test-Path -LiteralPath $Script:CredentialPath
                tunDetected = Test-TunLikeAdapterPresent
                internet = $true
            })
        }
        else {
            Write-Host 'Portal:     not required while Internet is reachable'
        }
        return 0
    }

    $resolved = $null
    try {
        $resolved = Resolve-PortalSession
        if ($null -eq $resolved) { return 0 }

        $fingerprint = Get-CurrentNetworkFingerprint -UserIpHint $resolved.UserIpHint
        $config = $null
        $trustedMatch = $null
        if (Test-Path -LiteralPath $Script:ConfigPath) {
            $config = Read-Config
            if ($null -ne $fingerprint) {
                $trustedMatch = Find-TrustedNetworkMatch -Config $config -Current $fingerprint
            }
        }

        $status = Get-WhutAccountStatus `
            -Context $resolved.Session `
            -PortalUri $resolved.Portal `
            -ApiBasePath $resolved.ApiBasePath `
            -CsrfToken $resolved.CsrfToken

        $statusCode = [int](Get-ObjectProperty -Object $status -Name 'code')

        if ($Script:JsonMode) {
            Write-ResultJson ([pscustomobject]@{
                state = 'WhutPortal'
                internet = $false
                portalVerified = $true
                portalHost = $resolved.Portal.Host
                bootstrapRecognized = $null -ne $resolved.Bootstrap
                nasIdPresent = -not [string]::IsNullOrWhiteSpace([string]$resolved.NasId)
                physicalResolved = $null -ne $fingerprint
                interface = if ($fingerprint) { $fingerprint.interfaceAlias } else { $null }
                ipv4Prefix = if ($fingerprint) { $fingerprint.ipv4Prefix } else { $null }
                networkTrusted = $null -ne $trustedMatch
                trustedNetworkId = if ($trustedMatch) { Get-ObjectProperty $trustedMatch 'id' } else { $null }
                apiBase = $resolved.ApiBasePath
                csrf = 'OK'
                accountCode = $statusCode
                tunDetected = Test-TunLikeAdapterPresent
            })
        }
        else {
            Write-Host "Portal:     trusted ($($resolved.Portal.Host))"
            Write-Host "Bootstrap:  $(if ($resolved.Bootstrap) { 'recognized /api/r/<nasId>' } else { 'not required / not observed' })"
            Write-Host "nasId:      $(if ($resolved.NasId) { 'present' } else { 'missing; login unavailable' })"
            Write-Host "Physical:   $(if ($fingerprint) { 'OK (' + $fingerprint.interfaceAlias + ', ' + $fingerprint.ipv4Prefix + ')' } else { 'unresolved' })"
            Write-Host "Trusted:    $(if ($trustedMatch) { 'yes (' + [string](Get-ObjectProperty $trustedMatch 'label' '') + ')' } else { 'no - Trust & Connect required' })"
            Write-Host "API base:   $($resolved.ApiBasePath)"
            Write-Host 'CSRF:       OK (value intentionally hidden)'
            Write-Host "Account:    code=$statusCode"
        }

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

    $existingConfig = $null
    if (Test-Path -LiteralPath $Script:ConfigPath) {
        try { $existingConfig = Read-Config } catch {}
    }

    $user = $RequestedUsername
    if ([string]::IsNullOrWhiteSpace($user) -and $null -ne $existingConfig) {
        $user = [string](Get-ObjectProperty $existingConfig 'username' '')
    }
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

    $trustedNetworks = @()
    if ($null -ne $existingConfig) {
        $trustedNetworks = @(Get-TrustedNetworks -Config $existingConfig)
    }

    $fingerprint = $null
    $setupSession = $null

    # setup may store credentials anywhere, but a network is added to the trust store
    # only after the current WHUT bootstrap/API/status protocol has been verified.
    try {
        if (-not (Test-Internet)) {
            $setupSession = Resolve-PortalSession
            if ($null -ne $setupSession -and -not [string]::IsNullOrWhiteSpace([string]$setupSession.NasId)) {
                [void](Get-WhutAccountStatus `
                    -Context $setupSession.Session `
                    -PortalUri $setupSession.Portal `
                    -ApiBasePath $setupSession.ApiBasePath `
                    -CsrfToken $setupSession.CsrfToken)

                $fingerprint = Get-CurrentNetworkFingerprint -UserIpHint $setupSession.UserIpHint
            }
        }
    }
    catch {
        Write-Log WARN 'Current network was not added to trust during setup because WHUT protocol verification did not complete.'
        $fingerprint = $null
    }
    finally {
        if ($null -ne $setupSession) {
            Close-HttpContext $setupSession.Session
        }
    }

    try {
        $baseConfig = [pscustomobject][ordered]@{
            version = 3
            username = $user
            trustedNetworks = @($trustedNetworks)
        }

        if ($null -ne $fingerprint) {
            $entry = New-TrustedNetworkEntry -Fingerprint $fingerprint -RequestedLabel $Label
            $merged = [Collections.Generic.List[object]]::new()
            $updated = $false

            foreach ($item in $trustedNetworks) {
                if (Test-NetworkFingerprintMatch -Trusted $item -Current $fingerprint) {
                    if ([string]::IsNullOrWhiteSpace($Label)) {
                        $entry.label = [string](Get-ObjectProperty $item 'label' $entry.label)
                    }
                    $entry.id = [string](Get-ObjectProperty $item 'id' $entry.id)
                    $merged.Add($entry)
                    $updated = $true
                }
                else {
                    $merged.Add($item)
                }
            }

            if (-not $updated) { $merged.Add($entry) }
            $baseConfig.trustedNetworks = @($merged.ToArray())
        }

        $encrypted = $password | ConvertFrom-SecureString
        Set-Content -LiteralPath $Script:CredentialPath -Value $encrypted -Encoding utf8
        Save-Config -Config $baseConfig
    }
    finally {
        $password.Dispose()
        $password = $null
        $encrypted = $null
    }

    Write-Log INFO 'Configuration v3 saved. Password is protected with Windows DPAPI CurrentUser.'
    if ($null -ne $fingerprint) {
        Write-Log INFO 'Current protocol-verified WHUT physical network was added/updated without removing other trusted networks.'
    }
    else {
        Write-Log WARN 'Credentials were saved, but no new network was trusted. Reconnect while captive and use trust-current.'
    }
    Write-Log WARN 'The WHUT portal currently uses HTTP; the network transport itself is not end-to-end encrypted.'
    if ($Script:JsonMode) { Write-ResultJson ([pscustomobject]@{state='Configured';exitCode=0;count=@($baseConfig.trustedNetworks).Count}) }
    return 0
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
    if (@(Get-TrustedNetworks -Config $config).Count -eq 0) {
        Throw-Whut 50 'Install requires at least one trusted WHUT physical network. Use setup or trust-current first.'
    }

    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path -LiteralPath $PSCommandPath)) {
        Throw-Whut 50 'The script must be saved as a .ps1 file before installing the scheduled task.'
    }

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $root = $service.GetFolder('\')
    $task = $service.NewTask(0)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    $task.RegistrationInfo.Description = 'WHUT-Net v1.4.0 auto-login on user logon and network connection.'
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
    $spec = New-WhutTaskActionSpec -ScriptPath $PSCommandPath
    $action.Path = $spec.Execute
    $action.Arguments = $spec.Arguments
    $action.WorkingDirectory = $spec.WorkingDirectory

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

Default:
  .\whut-net.ps1
      Smart mode: online -> exit; known WHUT -> connect; new verified WHUT ->
      ask once whether to Trust & Connect.

Commands:
  setup [-Username <id>] [-Label <name>]
      Save/update DPAPI credential and preserve existing trusted networks.
      If the current captive WHUT network is verifiable, add/update it too.

  setup -AddNetwork [-Label <name>]
      Compatibility alias for trust-current; preserve the saved credential.

  login
      Authenticate once; ask for explicit trust on a new verified network.

  status
      Check Internet / WHUT authentication state. Never logs in.

  auto
      Non-interactive Task Scheduler mode. Known trusted WHUT networks only.

  trust-current [-Label <name>]
      Verify the current captive WHUT portal, then explicitly trust this physical network.

  networks
      List trusted physical WHUT networks.

  remove-network -NetworkId <id>
      Remove one trusted network fingerprint.

  diagnose
      Inspect portal, bootstrap, physical network, trust status, API and account state.

  install
      Register the per-user Task Scheduler task.

  uninstall
      Remove the task and all local WHUT-Net state.

  help
      Show this help.

Options:
  -Json
      Machine-readable JSON output for status/diagnose/networks/trust operations and errors.

  -Yes
      Approve Trust & Connect without an interactive y/N prompt in smart mode.

Exit codes:
   0  online / login successful
  10  WHUT portal reached, account offline
  11  PortalNotFound / session nasId missing
  12  untrusted portal/network or unsafe API path
  13  UnsupportedProtocol / ProtocolChanged
  14  verified new WHUT network requires explicit trust
  20  authentication rejected
  21  additional verification / code check required
  22  CSRF acquisition failed
  30  PortalUnreachable / WHUT API unavailable
  31  ProbeTimeout
  40  network or post-auth Internet failure
  50  local configuration / credential error

Security:
  - Password at rest: Windows DPAPI CurrentUser.
  - Credentials are released only after portal/protocol checks and a trusted physical network match.
  - trustedNetworks[] stores multiple explicitly trusted physical WHUT environments.
  - SSID/Profile names are labels only; they never auto-authorize a network.
  - Unknown verified WHUT networks require one explicit Trust & Connect action.
  - Proxy variables are ignored for authentication traffic.
  - TUN-like 198.18.0.0/15 interfaces are excluded from physical network fingerprinting.
  - Task auto-login is single-instance and uses cooldown/backoff to avoid repeated requests.
  - CSRF token, cookies and password are never written to the log.
  - The current WHUT portal is HTTP; DPAPI protects storage, not network transport.
"@ | Write-Host
    return 0
}

# Dot-sourcing loads functions for repeatable offline tests; direct invocation remains the CLI.
if ($MyInvocation.InvocationName -eq '.') { return }

$exitCode = 0

try {
    switch ($Command) {
        'run'            { $exitCode = Invoke-RunCommand }
        'help'           { $exitCode = Show-Help }
        'setup'          {
            if ($AddNetwork) {
                if ($Username) { Throw-Whut 50 'Use setup without -AddNetwork to change credentials.' }
                $exitCode = Invoke-TrustCurrentCommand -RequestedLabel $Label
            }
            else { $exitCode = Invoke-SetupCommand -RequestedUsername $Username }
        }
        'status'         { $exitCode = Invoke-StatusCommand }
        'login'          { $exitCode = Invoke-LoginCommand -PromptForTrust }
        'auto'           { $exitCode = Invoke-AutoCommand }
        'diagnose'       { $exitCode = Invoke-DiagnoseCommand }
        'trust-current'  { $exitCode = Invoke-TrustCurrentCommand -RequestedLabel $Label }
        'networks'       { $exitCode = Invoke-NetworksCommand }
        'remove-network' { $exitCode = Invoke-RemoveNetworkCommand -Id $NetworkId }
        'install'        { $exitCode = Install-WhutScheduledTask }
        'uninstall'      { $exitCode = Uninstall-Whut }
        default          { $exitCode = Invoke-RunCommand }
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

    if ($Script:JsonMode) {
        $safeMessage = if ($null -ne $_.Exception.Data['ExitCode']) {
            [string]$_.Exception.Message
        }
        else {
            'Unexpected operation failure.'
        }
        Write-ResultJson ([pscustomobject]@{
            state = 'Error'
            exitCode = $exitCode
            message = $safeMessage
        })
    }
    else {
        # Only deliberate WHUT errors contain messages safe for persistent logging.
        # Unexpected exceptions may include request URLs or other session details.
        if ($null -ne $_.Exception.Data['ExitCode']) {
            Write-Log ERROR $_.Exception.Message
        }
        else {
            Write-Log ERROR 'Unexpected operation failure; no request or credential details were logged.'
        }
    }
}

exit $exitCode
