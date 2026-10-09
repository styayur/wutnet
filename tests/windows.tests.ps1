#requires -Version 7.2
#requires -PSEdition Core
# Dependency-free offline regression suite. All network and stored credentials are synthetic.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tokens = $null
$syntaxErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'whut-net.ps1'), [ref]$tokens, [ref]$syntaxErrors)
if ($syntaxErrors.Count) { throw 'whut-net.ps1 syntax failed' }
Write-Host 'PASS Parser::ParseFile'
. (Join-Path $root 'whut-net.ps1')
$script:realNewHttpContext = ${function:New-HttpContext}
$script:passed = 0
$script:failed = 0
function Assert-True($Value, [string]$Message = 'Assertion failed') { if (-not $Value) { throw $Message } }
function Assert-Equal($Actual, $Expected) { if ($Actual -cne $Expected) { throw "Expected <$Expected>, got <$Actual>" } }
function Assert-Code([scriptblock]$Body, [int]$Code) {
    $seen = $null
    try { & $Body | Out-Null } catch { $seen = $_.Exception.Data['ExitCode'] }
    Assert-Equal $seen $Code
}
function Test-Case([string]$Name, [scriptblock]$Body) {
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
function Write-Log { param($Level, $Message, [switch]$Quiet) $script:messages.Add([string]$Message) }
$script:messages = [Collections.Generic.List[string]]::new()
$portal = [Uri]'http://172.30.21.100/tpl/whut/login.html?nasId=test-session'
function Response([int]$Code = 200, [string]$Body = '', $Location = $null) {
    [pscustomobject]@{ StatusCode = $Code; Body = $Body; Location = $Location }
}
function Network {
    [pscustomobject]@{ profileName = 'WHUT-DORM 2'; interfaceAlias = 'Wi-Fi'; interfaceType = '71';
        ipv4Address = '10.91.4.5'; ipv4Prefix = '10.91.0.0/16'; defaultGateway = '10.91.0.1'; portalHost = '172.30.21.100' }
}
function New-HttpContext { param($TimeoutSeconds) [pscustomobject]@{ Client = $null } }
function Close-HttpContext { param($Context) }

Test-Case 'portal exact allowlist accepts known URI and rejects lookalikes' {
    Assert-True (Test-TrustedPortalUri $portal)
    Assert-True (Test-TrustedPortalUri ([Uri]'http://172.30.21.100/tpl/whut/login.html'))
    foreach ($bad in @('http://172.30.21.101/tpl/whut/login.html',
        'http://172.30.21.100.evil.example/tpl/whut/login.html', 'http://evil.example/?next=172.30.21.100',
        'http://172.30.21.100/other/path', 'http://172.30.21.100/tpl/whut/login.html/',
        'http://172.30.21.100/x/../tpl/whut/login.html', 'http://172.30.21.100/tpl/whut/%6cogin.html',
        'http://172.30.21.100:8080/tpl/whut/login.html', 'http://u@172.30.21.100/tpl/whut/login.html',
        'http://172.30.21.100/tpl/whut/login.html#fragment', 'http://172.30.21.100/tpl/whut/Login.html',
        "http://172.30.21.100/tpl/whut/login.html`n")) {
        Assert-True (-not (Test-TrustedPortalUri ([Uri]$bad))) "Accepted $bad"
    }
}
Test-Case 'API base exact path grammar' {
    foreach ($good in @('/api','/eportal/api','/foo/bar')) { Assert-True (Test-SafeApiBasePath $good) }
    foreach ($bad in @('http://evil.example/api','https://evil.example/api','//evil.example/api',
        '/api/../evil','\api','/api?x=1','/api#fragment','/api//evil','/api/%2e%2e','/','/api/','',"/api`n")) {
        Assert-True (-not (Test-SafeApiBasePath $bad)) "Accepted $bad"
    }
}
Test-Case 'timeouts on Microsoft probes allow NeverSSL trusted redirect' {
    $script:calls = 0
    function Invoke-HttpText {
        param($Context,$Method,$Uri,$TimeoutMilliseconds)
        $script:calls++
        Assert-True ($TimeoutMilliseconds -gt 0 -and $TimeoutMilliseconds -le 4000)
        if ($script:calls -lt 3) { throw [Threading.Tasks.TaskCanceledException]::new('synthetic') }
        Response 302 '' $portal
    }
    $found = Find-WhutPortal
    Assert-Equal $found.State 'PortalRedirectFound'
    Assert-Equal $script:calls 3
    Assert-True ($script:messages -contains 'probe=msft-redirect result=timeout state=ProbeTimeout')
}
Test-Case 'foreign redirects are ignored without following them or reading credentials' {
    $script:calls = 0
    function Invoke-HttpText { $script:calls++; Response 302 '' ([Uri]'http://evil.example/') }
    function Read-ProtectedPassword { throw 'Credential read must never occur' }
    function Test-Internet { $false }
    Assert-Code { Invoke-LoginCommand -Automatic } 11
    Assert-Equal $script:calls 4
}
Test-Case 'relative redirect normalization cannot bypass allowlist' {
    function Invoke-HttpText { Response 302 '' '/x/../tpl/whut/login.html' }
    Assert-Equal (Find-WhutPortal).State 'ProtocolChanged'
}
Test-Case 'known Internet content ends discovery early' {
    $script:calls = 0
    function Invoke-HttpText {
        $script:calls++
        if ($script:calls -eq 1) { Response 200 '<html>unknown</html>' } else { Response 200 'Microsoft Connect Test' }
    }
    Assert-Equal (Find-WhutPortal).State 'InternetOnline'
    Assert-Equal $script:calls 2
}
Test-Case 'first Internet probe timeout still permits independent fallback' {
    $script:calls = 0
    function Invoke-HttpText {
        $script:calls++
        if ($script:calls -eq 1) { throw [Threading.Tasks.TaskCanceledException]::new() }
        Response 200 '<title>NeverSSL</title>'
    }
    Assert-True (Test-Internet)
    Assert-Equal $script:calls 2
}
Test-Case 'all probes time out with 31, not portal-not-found' {
    $script:calls = 0
    function Invoke-HttpText { $script:calls++; throw [Threading.Tasks.TaskCanceledException]::new() }
    $found = Find-WhutPortal
    Assert-Equal $found.State 'ProbeTimeout'
    Assert-Equal $found.ExitCode 31
    Assert-Equal $script:calls 4
}
Test-Case 'budget exhaustion prevents further probes' {
    $saved = $Script:DiscoveryBudgetSeconds
    try { $Script:DiscoveryBudgetSeconds = 0; Assert-Equal (Find-WhutPortal).State 'ProbeTimeout' }
    finally { $Script:DiscoveryBudgetSeconds = $saved }
}
Test-Case 'direct reachability remains distinct from a discovered session' {
    function Invoke-HttpText { param($Context,$Method,$Uri) if ($Uri.Host -eq '172.30.21.100') { Response 200 'login' } else { Response 503 } }
    $found = Find-WhutPortal
    Assert-Equal $found.State 'WhutPortalReachable'
    Assert-Equal (Get-QueryValue $found.Portal 'nasId') $null
}
Test-Case 'not-found and direct-unreachable have distinct codes' {
    function Invoke-HttpText { Response 404 }
    Assert-Equal (Find-WhutPortal).ExitCode 11
    function Invoke-HttpText { throw [Net.Http.HttpRequestException]::new('synthetic') }
    Assert-Equal (Find-WhutPortal).ExitCode 30
}
Test-Case 'HTTP 200 CSRF schema mismatch is protocol error' {
    foreach ($body in @('{}','[]','null','{"csrf_token":1}','{"csrf_token":""}',
        '{"csrf_token":"first","csrf_token":"second"}','<html>login</html>')) {
        Assert-Code { Read-WhutProtocolResponse (Response 200 $body) Csrf } 13
    }
    Assert-Equal (Read-WhutProtocolResponse (Response 200 '{"csrf_token":"synthetic"}') Csrf) 'synthetic'
    Assert-Code { Read-WhutProtocolResponse (Response 503) Csrf } 22
}
Test-Case 'status and login shapes distinguish protocol changes from rejection' {
    foreach ($body in @('{}','{"code":"0"}','{"code":false}','{"code":1.5}',
        '{"code":0,"code":2}','{"data":{"code":0}}','{"code":2147483648}')) {
        Assert-Code { Read-WhutProtocolResponse (Response 200 $body) Status } 13
    }
    Assert-Equal (Read-WhutProtocolResponse (Response 200 '{"code":0}') Status).code 0
    Assert-Code { Read-WhutProtocolResponse (Response 200 '{"code":0}') Login } 13
    Assert-Code { Read-WhutProtocolResponse (Response 200 '{"code":0,"msg":null}') Login } 13
    $data = Read-WhutProtocolResponse (Response 200 '{"code":2,"msg":"synthetic server secret"}') Login
    Assert-Equal $data.code 2
    Assert-Equal @($data.PSObject.Properties).Count 1
    Assert-Code { Read-WhutProtocolResponse (Response 500) Login } 30
}
Test-Case 'config API path and actively validated fallback' {
    function Invoke-HttpText { Response 200 "var host_url = '/eportal/api';" }
    Assert-Equal (Get-ApiBasePath $null $portal) '/eportal/api'
    function Invoke-HttpText { Response 200 "var host_url = '//evil.example/api';" }
    Assert-Code { Get-ApiBasePath $null $portal } 12
    function Invoke-HttpText { Response 200 "var host_url = '/api';`nvar host_url = '/other';" }
    Assert-Code { Get-ApiBasePath $null $portal } 13
    function Invoke-HttpText { param($Context,$Method,$Uri) if ($Uri.AbsolutePath.EndsWith('config.js')) { Response 404 } else { Response 200 '{"csrf_token":"synthetic"}' } }
    Assert-Equal (Get-ApiBasePath $null $portal) '/api'
    function Invoke-HttpText { Response 200 '{}' }
    Assert-Code { Get-ApiBasePath $null $portal } 13
}
Test-Case 'endpoint helper rejects unsafe origin/base independently' {
    Assert-Code { Get-WhutApiUri ([Uri]'http://evil.example/') '/api' '/account/status' } 12
    Assert-Code { Get-WhutApiUri $portal '//evil.example' '/account/login' } 12
    Assert-Equal (Get-WhutApiUri $portal '/api' $Script:WhutProtocol.LoginPath).AbsoluteUri 'http://172.30.21.100/api/account/login'
}
Test-Case 'DHCP host and profile rename preserve strict network trust' {
    $config = [pscustomobject]@{version=2;trustedNetwork=(Network)}
    function Get-CurrentNetworkFingerprint { $n = Network; $n.profileName = 'WHUT-DORM 3'; $n.ipv4Address = '10.91.22.6'; $n }
    Assert-True (Test-TrustedLocalNetwork $config -Automatic)
    Assert-Equal (Get-IPv4Prefix '10.91.22.6' 16) '10.91.0.0/16'
    Assert-Equal (Get-IPv4Prefix '10.91.22.6' 23) '10.91.22.0/23'
}
Test-Case 'changed gateway/prefix/portal or absent physical route refuses auto' {
    function Get-CurrentNetworkFingerprint { Network }
    foreach ($field in @('defaultGateway','ipv4Prefix','portalHost','interfaceType','interfaceAlias')) {
        $trusted = Network; $trusted.$field = 'different'
        Assert-True (-not (Test-TrustedLocalNetwork ([pscustomobject]@{version=2;trustedNetwork=$trusted}) -Automatic))
    }
    function Get-CurrentNetworkFingerprint { $null }
    Assert-True (-not (Test-TrustedLocalNetwork ([pscustomobject]@{version=1}) -Automatic))
}
Test-Case 'manual policy tolerates interface rename but never subnet/gateway mismatch' {
    function Get-CurrentNetworkFingerprint { $n = Network; $n.interfaceAlias = 'Ethernet'; $n }
    $config = [pscustomobject]@{version=2;trustedNetwork=(Network)}
    Assert-True (Test-TrustedLocalNetwork $config)
    $config.trustedNetwork.defaultGateway = '192.168.1.1'
    Assert-True (-not (Test-TrustedLocalNetwork $config))
}
Test-Case 'v1 config reads without mutation; auto requires upgrade' {
    $saved = $Script:ConfigPath
    $tempFile = [IO.Path]::GetTempFileName()
    try {
        $Script:ConfigPath = $tempFile
        $old = '{"version":1,"username":"synthetic","trustedProfiles":["WHUT-DORM 2"]}'
        [IO.File]::WriteAllText($tempFile, $old)
        $config = Read-Config
        Assert-Equal $config.version 1
        Assert-Equal ([IO.File]::ReadAllText($tempFile)) $old
        function Get-CurrentNetworkFingerprint { Network }
        Assert-True (Test-TrustedLocalNetwork $config)
        Assert-True (-not (Test-TrustedLocalNetwork $config -Automatic))
    }
    finally { $Script:ConfigPath = $saved; Remove-Item -LiteralPath $tempFile }
}
Test-Case 'malformed bootstrap never reads credential' {
    function Test-Internet { $false }
    function Find-WhutPortal { [pscustomobject]@{State='PortalRedirectFound';ExitCode=0;Portal=$portal;NasId=$null;UserIpHint=$null;Bootstrap=$null} }
    function Start-WhutSession { [pscustomobject]@{Client=$null} }
    function Invoke-HttpText { Response 200 '{}' }
    function Read-ProtectedPassword { throw 'Credential read must never occur' }
    Assert-Code { Invoke-LoginCommand -Automatic } 13
}
Test-Case 'Internet online never reads config or credentials' {
    function Test-Internet { $true }
    function Read-Config { throw 'Must not read config' }
    function Read-ProtectedPassword { throw 'Must not read credential' }
    Assert-Equal (Invoke-LoginCommand -Automatic) 0
}
Test-Case 'status fingerprint is required before credential release' {
    function Test-Internet { $false }
    function Find-WhutPortal { [pscustomobject]@{State='PortalRedirectFound';ExitCode=0;Portal=$portal;NasId=$null;UserIpHint=$null;Bootstrap=$null} }
    function Start-WhutSession { [pscustomobject]@{Client=$null} }
    function Invoke-HttpText {
        param($Context,$Method,$Uri)
        switch -Wildcard ($Uri.AbsolutePath) {
            '*config.js' { Response 200 "var host_url = '/api';" }
            '*csrf-token' { Response 200 '{"csrf_token":"synthetic"}' }
            default { Response 200 '{"status":"offline"}' }
        }
    }
    function Read-ProtectedPassword { throw 'Credential read must never occur' }
    Assert-Code { Invoke-LoginCommand -Automatic } 13
}
Test-Case 'login command requires both account and Internet verification' {
    $script:internetCalls = 0
    $script:statusCalls = 0
    $script:postCalls = 0
    function Test-Internet { $script:internetCalls++; return ($script:internetCalls -gt 1) }
    function Resolve-PortalSession {
        [pscustomobject]@{Session=$null;Portal=$portal;ApiBasePath='/api';CsrfToken='synthetic';NasId='test-session';UserIpHint=$null}
    }
    function Get-WhutAccountStatus {
        $script:statusCalls++
        [pscustomobject]@{code=$(if ($script:statusCalls -eq 1) {1} else {0})}
    }
    function Read-Config { [pscustomobject]@{version=2;username='synthetic';trustedNetwork=(Network)} }
    function Invoke-WhutLogin { $script:postCalls++; [pscustomobject]@{code=0} }
    function Start-Sleep { }
    Assert-Equal (Invoke-LoginCommand -Automatic) 0
    Assert-Equal $script:postCalls 1
    Assert-Equal $script:statusCalls 2
    function Get-WhutAccountStatus { [pscustomobject]@{code=1} }
    function Test-Internet { $false }
    Assert-Code { Invoke-LoginCommand -Automatic } 40
    $script:statusCalls = 0
    function Get-WhutAccountStatus { $script:statusCalls++; [pscustomobject]@{code=$(if ($script:statusCalls -eq 1) {1} else {0})} }
    Assert-Code { Invoke-LoginCommand -Automatic } 40
}

# A fake HttpMessageHandler exercises real serialization, HttpClient, and disposal without a socket.
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
public sealed class WhutTestHandler : HttpMessageHandler {
    public string Reply = "{\"code\":0,\"msg\":\"ok\"}";
    public bool Fail;
    public int Calls;
    public string Captured;
    public byte[] BodyBuffer;
    public string Destination;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) {
        Calls++;
        Destination = request.RequestUri.AbsoluteUri;
        // Test-only inspection of the application's ByteArrayContent backing buffer.
        // ReadAsByteArrayAsync returns a separate transport-owned copy on modern .NET.
        BodyBuffer = (byte[])typeof(ByteArrayContent).GetField("_content",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(request.Content);
        Captured = System.Text.Encoding.UTF8.GetString(await request.Content.ReadAsByteArrayAsync());
        if (Fail) throw new HttpRequestException("synthetic password Cookie csrf secret transport failure");
        return new HttpResponseMessage(HttpStatusCode.OK) {Content = new StringContent(Reply)};
    }
}
public sealed class WhutCancelHandler : HttpMessageHandler {
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) {
        await Task.Delay(Timeout.Infinite, token);
        return new HttpResponseMessage(HttpStatusCode.OK);
    }
}
'@
Test-Case 'real HttpClient cancellation remains ProbeTimeout through PowerShell wrapping' {
    $savedProbe = $Script:DiscoveryProbeSeconds
    $savedBudget = $Script:DiscoveryBudgetSeconds
    try {
        $Script:DiscoveryProbeSeconds = 0.05
        $Script:DiscoveryBudgetSeconds = 2
        $script:calls = 0
        function New-HttpContext {
            $script:calls++
            [pscustomobject]@{Client=[Net.Http.HttpClient]::new([WhutCancelHandler]::new())}
        }
        function Close-HttpContext { param($Context) if ($null -ne $Context) { $Context.Client.Dispose() } }
        $found = Find-WhutPortal
        Assert-Equal $found.State 'ProbeTimeout'
        Assert-Equal $found.ExitCode 31
        Assert-Equal $script:calls 4
    }
    finally {
        $Script:DiscoveryProbeSeconds = $savedProbe
        $Script:DiscoveryBudgetSeconds = $savedBudget
    }
}
Test-Case 'credential POST correctly encodes Unicode and clears body after success/failure' {
    function Get-CurrentNetworkFingerprint { Network }
    $script:credentialReads = 0
    function Read-ProtectedPassword {
        $script:credentialReads++
        ConvertTo-SecureString 'p& +%=中文😀' -AsPlainText -Force
    }
    $config = [pscustomobject]@{version=2;trustedNetwork=(Network)}
    $handler = [WhutTestHandler]::new()
    $client = [Net.Http.HttpClient]::new($handler)
    $context = [pscustomobject]@{Client=$client}
    try {
        $data = Invoke-WhutLogin $context $portal '/api' 'synthetic-csrf' 'test-session' 'test-user' $config -Automatic
        Assert-Equal $data.code 0
        Assert-Equal $handler.Destination 'http://172.30.21.100/api/account/login'
        Assert-True ($handler.Captured.Contains('password=p%26+%2B%25%3D%E4%B8%AD%E6%96%87%F0%9F%98%80'))
        Assert-True (@($handler.BodyBuffer | Where-Object { $_ -ne 0 }).Count -eq 0) 'buffer not cleared'
        $handler.Fail = $true
        Assert-Code { Invoke-WhutLogin $context $portal '/api' 'synthetic-csrf' 'test-session' 'test-user' $config -Automatic } 30
        Assert-True (@($handler.BodyBuffer | Where-Object { $_ -ne 0 }).Count -eq 0) 'buffer not cleared'
        $handler.Fail = $false
        foreach ($case in @(@('{"code":2,"msg":"verify"}',21), @('{"code":1,"msg":"reject"}',20), @('{"code":0}',13))) {
            $handler.Reply = $case[0]
            Assert-Code { Invoke-WhutLogin $context $portal '/api' 'synthetic-csrf' 'test-session' 'test-user' $config } $case[1]
        }
        $reads = $script:credentialReads
        Assert-Code { Invoke-WhutLogin $context $portal '/api' 'synthetic-csrf' '' 'test-user' $config } 11
        $config.trustedNetwork.defaultGateway = 'other'
        Assert-Code { Invoke-WhutLogin $context $portal '/api' 'synthetic-csrf' 'test-session' 'test-user' $config -Automatic } 12
        Assert-Equal $script:credentialReads $reads
    }
    finally { $client.Dispose() }
}
Test-Case 'logs exclude raw portal values and credential material' {
    $logs = $script:messages -join "`n"
    foreach ($secret in @('test-session','synthetic-csrf','synthetic server secret','p& +%=','Cookie')) {
        Assert-True (-not $logs.Contains($secret))
    }
}
Test-Case 'production HTTP context disables proxies and automatic redirects' {
    $context = & $script:realNewHttpContext -TimeoutSeconds 4
    try {
        Assert-True (-not $context.Handler.UseProxy)
        Assert-True (-not $context.Handler.AllowAutoRedirect)
        Assert-Equal $context.Client.Timeout.TotalSeconds 4
    }
    finally { $context.Client.Dispose() }
}
Test-Case 'foreign Internet preflight redirects continue without establishing trust' {
    function Invoke-HttpText { Response 302 '' 'http://evil.example/' }
    Assert-True (-not (Test-Internet))
}
Test-Case 'physical WLAN selection ignores Meta routing and excludes benchmark/APIPA addresses' {
    function Find-NetRoute { throw 'Route lookup must not select the fingerprint' }
    function Get-NetAdapter {
        param([switch]$Physical)
        Assert-True $Physical
        [pscustomobject]@{ifIndex=3;Status='Up';Name='Meta';InterfaceType=6}
        [pscustomobject]@{ifIndex=7;Status='Up';Name='WLAN';InterfaceType=71}
    }
    function Get-NetIPConfiguration {
        param($InterfaceIndex)
        if ($InterfaceIndex -eq 3) {
            [pscustomobject]@{IPv4DefaultGateway=@([pscustomobject]@{NextHop='198.18.0.2'});
                IPv4Address=@([pscustomobject]@{IPAddress='198.18.0.1';PrefixLength=15})}
        } else {
            [pscustomobject]@{IPv4DefaultGateway=@([pscustomobject]@{NextHop='10.82.0.1'});
                IPv4Address=@([pscustomobject]@{IPAddress='10.82.155.225';PrefixLength=15})}
        }
    }
    function Get-NetRoute { [pscustomobject]@{DestinationPrefix='0.0.0.0/0';RouteMetric=10} }
    function Get-NetIPInterface { [pscustomobject]@{InterfaceMetric=5} }
    function Get-NetConnectionProfile { [pscustomobject]@{Name='WHUT-DORM 3'} }
    $network = Get-CurrentNetworkFingerprint -UserIpHint '10.82.155.225'
    Assert-Equal $network.interfaceAlias 'WLAN'
    Assert-Equal $network.interfaceType '71'
    Assert-Equal $network.ipv4Prefix '10.82.0.0/15'
    Assert-Equal $network.profileName 'WHUT-DORM 3'
    Assert-Equal (Get-CurrentNetworkFingerprint -UserIpHint '10.91.175.52') $null
    foreach ($bad in @('169.254.1.2','198.18.0.1','198.19.255.254','127.0.0.1','::1')) {
        Assert-True (-not (Test-UsablePhysicalIPv4 $bad))
    }
    function Get-NetAdapter { [pscustomobject]@{ifIndex=3;Status='Up';Name='Meta';InterfaceType=6} }
    Assert-Equal (Get-CurrentNetworkFingerprint) $null
}
Test-Case 'config comments are excluded and duplicate active values are deduplicated' {
    function Invoke-HttpText { Response 200 "//var host_url = 'http://192.168.85.20/api'`nvar host_url = '/api'" }
    Assert-Equal (Get-ApiBasePath $null $portal) '/api'
    function Invoke-HttpText { Response 200 "var host_url = '/api'`nconst host_url = '/api'" }
    Assert-Equal (Get-ApiBasePath $null $portal) '/api'
    function Invoke-HttpText { Response 200 "/*`nvar host_url = '/test'`n*/`nlet host_url = '/api'" }
    Assert-Equal (Get-ApiBasePath $null $portal) '/api'
    function Invoke-HttpText { Response 200 "var host_url = '/api'`nvar host_url = '/api2'" }
    Assert-Code { Get-ApiBasePath $null $portal } 13
    function Invoke-HttpText { Response 200 "var host_url = '/api'`nvar host_url = '/API'" }
    Assert-Code { Get-ApiBasePath $null $portal } 13
}
# Historical private DHCP examples supplied by the maintainer; no account/credential data.
$fieldBootstraps = @(
    @{NasId='52';UserIp='10.82.155.225';AcIp='172.30.1.223';AcName='WHUT-Bras-ME60-A'},
    @{NasId='59';UserIp='10.91.175.52';AcIp='172.30.1.220';AcName='WHUT-YQ-Bras-ME60'},
    @{NasId='731';UserIp='10.90.24.17';AcIp='172.30.2.19';AcName='SYNTHETIC-BRAS'}
)
Test-Case 'cross-campus bootstrap metadata and canonical portal remain dynamic' {
    foreach ($case in $fieldBootstraps) {
        $uri = [Uri]("http://172.30.21.100/api/r/{0}?userip={1}&wlanacname=&acip={2}&acname={3}" -f
            $case.NasId,$case.UserIp,$case.AcIp,$case.AcName)
        Assert-True (Test-TrustedBootstrapUri $uri)
        $meta = Get-WhutBootstrapMetadata $uri
        Assert-Equal $meta.NasId $case.NasId
        Assert-Equal $meta.UserIp $case.UserIp
        Assert-Equal $meta.AcIp $case.AcIp
        Assert-Equal $meta.AcName $case.AcName
        Assert-Equal $meta.WlanAcName ''
        $canonical = Convert-BootstrapToPortalUri $uri
        Assert-True (Test-TrustedPortalUri $canonical)
        Assert-Equal (Get-QueryValue $canonical 'nasId') $case.NasId
        Assert-Equal (Get-QueryValue $canonical 'userip') $case.UserIp
    }
}
Test-Case 'bootstrap allowlist rejects foreign hosts and raw-path lookalikes' {
    foreach ($bad in @('http://172.30.21.101/api/r/52','http://172.30.21.100.evil.example/api/r/52',
        'https://172.30.21.100/api/r/52','http://172.30.21.100:8080/api/r/52',
        'http://user@172.30.21.100/api/r/52','http://172.30.21.100/api/r/52#x',
        'http://172.30.21.100/api/x/../r/52','http://172.30.21.100/api/r/%35%32',
        'http://172.30.21.100/api/r/12345678901','http://172.30.21.100/api/r/x',
        'http://172.30.21.100/api/r/52/','http://172.30.21.100/api/account/login')) {
        Assert-True (-not (Test-TrustedBootstrapUri ([Uri]$bad))) 'Unsafe bootstrap accepted'
    }
}
Test-Case 'foreign discovery redirect is skipped then trusted bootstrap succeeds' {
    $script:calls = 0
    function Invoke-HttpText {
        param($Context,$Method,$Uri)
        $script:calls++
        Assert-True ($Uri.Host -ne 'evil.example')
        if ($script:calls -eq 1) { Response 302 '' 'http://evil.example/' }
        else { Response 302 '' 'http://172.30.21.100/api/r/52?userip=10.82.155.225' }
    }
    $found = Find-WhutPortal
    Assert-Equal $found.State 'WhutBootstrapFound'
    Assert-Equal $found.NasId '52'
    Assert-Equal $script:calls 2
}
Test-Case 'unknown WHUT destinations and malformed bootstrap metadata are protocol errors' {
    function Invoke-HttpText { Response 302 '' 'http://172.30.21.100/unknown' }
    Assert-Equal (Find-WhutPortal).ExitCode 13
    Assert-Code { Test-Internet } 13
    function Invoke-HttpText { Response 302 '' 'http://172.30.21.100/api/r/52?userip=invalid' }
    Assert-Code { Find-WhutPortal } 13
}
Test-Case 'bootstrap replay uses one context before opening canonical page' {
    $bootstrap = [Uri]'http://172.30.21.100/api/r/52?userip=10.82.155.225'
    $canonical = Convert-BootstrapToPortalUri $bootstrap
    $script:replayCalls = [Collections.Generic.List[object]]::new()
    function Invoke-HttpText {
        param($Context,$Method,$Uri)
        $script:replayCalls.Add([pscustomobject]@{Context=$Context;Uri=$Uri})
        if ($script:replayCalls.Count -eq 1) { Response 302 '' '/tpl/whut/login.html?nasId=52' }
        else { Response 200 'portal' }
    }
    $context = Start-WhutSession $canonical $bootstrap
    Assert-Equal $script:replayCalls.Count 2
    Assert-Equal $script:replayCalls[0].Uri $bootstrap
    Assert-Equal $script:replayCalls[1].Uri $canonical
    Assert-True ([object]::ReferenceEquals($script:replayCalls[0].Context,$script:replayCalls[1].Context))
    function Invoke-HttpText { Response 302 '' '/x/../tpl/whut/login.html' }
    Assert-Code { Start-WhutSession $canonical $bootstrap } 13
    function Invoke-HttpText { Response 302 '' 'http://evil.example/' }
    Assert-Code { Start-WhutSession $canonical $bootstrap } 13
}
Test-Case 'pwsh resolver prefers stable Store alias and returns System.String' {
    $aliasPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pwsh.exe'
    function Test-Path { param($LiteralPath,$PathType) $LiteralPath -eq $aliasPath }
    function Get-Command { throw 'Must not enumerate multiple Store executables when alias exists' }
    $actual = Resolve-PwshExecutable
    Assert-True ($actual -is [string])
    Assert-Equal $actual $aliasPath
}
Test-Case 'pwsh resolver falls back to PSHOME then a unique safe application' {
    function Test-Path { param($LiteralPath,$PathType) $LiteralPath -eq (Join-Path $PSHOME 'pwsh.exe') }
    Assert-Equal (Resolve-PwshExecutable) (Join-Path $PSHOME 'pwsh.exe')
    function Test-Path { param($LiteralPath,$PathType) $LiteralPath -in @('C:\Tools\pwsh.exe','C:\Other\pwsh.exe') }
    function Get-Command {
        [pscustomobject]@{Source='C:\Tools\pwsh.exe'}
        [pscustomobject]@{Source='C:\Tools\pwsh.exe'}
    }
    $actual = Resolve-PwshExecutable
    Assert-True ($actual -is [string])
    Assert-Equal $actual 'C:\Tools\pwsh.exe'
    function Get-Command {
        [pscustomobject]@{Source='C:\Tools\pwsh.exe'}
        [pscustomobject]@{Source='C:\Other\pwsh.exe'}
    }
    Assert-Code { Resolve-PwshExecutable } 50
}
Test-Case 'scheduled task action contains scalar Execute, quoted script, and working directory' {
    function Resolve-PwshExecutable { [string]'C:\Users\Synthetic\AppData\Local\Microsoft\WindowsApps\pwsh.exe' }
    function Test-Path { $true }
    $spec = New-WhutTaskActionSpec 'C:\Synthetic Folder\whut-net.ps1'
    Assert-True ($spec.Execute -is [string])
    Assert-Equal $spec.Execute 'C:\Users\Synthetic\AppData\Local\Microsoft\WindowsApps\pwsh.exe'
    Assert-Equal $spec.Arguments '-NoLogo -NoProfile -NonInteractive -File "C:\Synthetic Folder\whut-net.ps1" auto'
    Assert-Equal $spec.WorkingDirectory 'C:\Synthetic Folder'
    Assert-True (($spec | ConvertTo-Json) -notmatch 'String\[\]')
}
Test-Case 'release version and bootstrap log redaction' {
    Assert-Equal $Script:Version '1.3.2'
    $logs = $script:messages -join "`n"
    foreach ($secret in @('10.82.155.225','10.91.175.52','synthetic-csrf','test-user','password=')) {
        Assert-True (-not $logs.Contains($secret)) 'Sensitive log value found'
    }
}
Test-Case 'v2 migration preserves account, credential and original trust registration' {
    $savedConfig = $Script:ConfigPath
    $tempFile = [IO.Path]::GetTempFileName()
    try {
        $Script:ConfigPath = $tempFile
        [pscustomobject]@{version=2;username='synthetic-account';trustedNetwork=(Network)} |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $tempFile
        $config = Read-Config
        Assert-Equal $config.version 3
        Assert-Equal $config.username 'synthetic-account'
        Assert-Equal @($config.trustedNetworks).Count 1
        Assert-Equal $config.trustedNetworks[0].ipv4Prefix '10.91.0.0/16'
        $stored = Get-Content -LiteralPath $tempFile -Raw | ConvertFrom-Json
        Assert-Equal $stored.version 3
        Assert-Equal @($stored.trustedNetworks).Count 1
        Assert-Equal $stored.PSObject.Properties['trustedNetwork'] $null
    }
    finally { $Script:ConfigPath = $savedConfig; Remove-Item -LiteralPath $tempFile }
}
Test-Case 'auto accepts any registered fingerprint and never enrolls matching profile names' {
    $first = Network
    $second = Network
    $second.ipv4Prefix = '10.82.0.0/15'; $second.defaultGateway = '10.82.0.1'; $second.interfaceAlias = 'WLAN'
    $config = [pscustomobject]@{version=3;username='synthetic';trustedNetworks=@($first,$second)}
    function Get-CurrentNetworkFingerprint { $second }
    Assert-True (Test-TrustedLocalNetwork $config -Automatic)
    function Get-CurrentNetworkFingerprint { $first }
    Assert-True (Test-TrustedLocalNetwork $config -Automatic)
    $before = $config | ConvertTo-Json -Depth 5
    function Get-CurrentNetworkFingerprint { $n = Network; $n.ipv4Prefix = '192.168.0.0/24'; $n }
    Assert-True (-not (Test-TrustedLocalNetwork $config -Automatic))
    Assert-Equal ($config | ConvertTo-Json -Depth 5) $before
    function Get-CurrentNetworkFingerprint { $n = Network; $n.defaultGateway = $second.defaultGateway; $n }
    Assert-True (-not (Test-TrustedLocalNetwork $config -Automatic)) 'Fields from different registrations must not combine'
}
Test-Case 'explicit AddNetwork appends once without requesting or changing credentials' {
    $savedPaths = @($Script:DataDir,$Script:ConfigPath,$Script:CredentialPath)
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('wutnet-tests-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($directory)
    try {
        $Script:DataDir = $directory
        $Script:ConfigPath = Join-Path $directory 'config.json'
        $Script:CredentialPath = Join-Path $directory 'credential.dat'
        Write-Config ([pscustomobject]@{version=3;username='synthetic-account';trustedNetworks=@((Network))})
        Set-Content -LiteralPath $Script:CredentialPath -Value 'synthetic-encrypted-placeholder'
        $credentialHash = (Get-FileHash -LiteralPath $Script:CredentialPath).Hash
        function Read-Host { throw 'AddNetwork must not prompt for a password' }
        function Read-ProtectedPassword { throw 'AddNetwork must not decrypt a credential' }
        function Get-WhutNetworkHint { '10.82.155.225' }
        function Get-CurrentNetworkFingerprint {
            $n = Network; $n.ipv4Prefix = '10.82.0.0/15'; $n.defaultGateway = '10.82.0.1'; $n.interfaceAlias = 'WLAN'; $n
        }
        Assert-Equal (Invoke-SetupCommand -AddNetwork) 0
        Assert-Equal @((Read-Config).trustedNetworks).Count 2
        Assert-Equal (Invoke-SetupCommand -AddNetwork) 0
        Assert-Equal @((Read-Config).trustedNetworks).Count 2
        Assert-Equal (Read-Config).username 'synthetic-account'
        Assert-Equal (Get-FileHash -LiteralPath $Script:CredentialPath).Hash $credentialHash
        Assert-Code { Invoke-SetupCommand -AddNetwork -RequestedUsername 'different-account' } 50
        function Get-CurrentNetworkFingerprint { $null }
        Assert-Code { Invoke-SetupCommand -AddNetwork } 12
        Assert-Equal @((Read-Config).trustedNetworks).Count 2
    }
    finally {
        Remove-Item -LiteralPath (Join-Path $directory 'config.json'),(Join-Path $directory 'credential.dat') -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $directory
        $Script:DataDir,$Script:ConfigPath,$Script:CredentialPath = $savedPaths
    }
}
Write-Host "$script:passed passed; $script:failed failed"
if ($script:failed) { exit 1 }
exit 0
