#requires -Version 7.2
# Loaded by windows.tests.ps1; doubles never register a real task or launch WSH.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='COM and filesystem doubles preserve the signatures under test.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Scoped filesystem/COM doubles are deliberate offline isolation.')]
param()

function New-TestTaskCollection {
    param([switch]$Actions)
    $collection = [pscustomobject]@{Items=[Collections.Generic.List[object]]::new(); Actions=[bool]$Actions}
    $collection | Add-Member ScriptProperty Count { $this.Items.Count }
    $collection | Add-Member ScriptMethod Create {
        param($Type)
        if ($this.Actions) {
            if ($Type -ne 0) { throw 'Unexpected action type' }
            $item = [pscustomobject]@{Type=$Type; Path=''; Arguments=''; WorkingDirectory=''}
        }
        else {
            $properties = @{Type=$Type; Enabled=$false}
            switch ($Type) {
                9 { $properties.UserId=''; $properties.Delay='' }
                0 { $properties.Delay=''; $properties.Subscription='' }
                11 { $properties.UserId=''; $properties.Delay=''; $properties.StateChange=0 }
                2 {
                    $properties.StartBoundary=''; $properties.DaysInterval=0
                    $properties.Repetition=[pscustomobject]@{Interval='';Duration='';StopAtDurationEnd=$true}
                }
                default { throw 'Unexpected trigger type' }
            }
            $item = [pscustomobject]$properties
        }
        $this.Items.Add($item)
        return $item
    }
    return $collection
}

function New-TestScheduleService {
    $service = [pscustomobject]@{
        Calls=[Collections.Generic.List[object]]::new()
        Installed=$null; LauncherReady=$false; RejectValidation=$false; RejectRegistration=$false
    }
    $service | Add-Member ScriptMethod Connect {}
    $service | Add-Member ScriptMethod GetFolder { param($Path) return $this }
    $service | Add-Member ScriptMethod NewTask {
        param($Flags)
        [pscustomobject]@{
            RegistrationInfo=[pscustomobject]@{Description=''}
            Settings=[pscustomobject]@{
                Enabled=$false; Hidden=$false; StartWhenAvailable=$false; MultipleInstances=0
                ExecutionTimeLimit=''; DisallowStartIfOnBatteries=$true; StopIfGoingOnBatteries=$true
            }
            Principal=[pscustomobject]@{UserId='';LogonType=0;RunLevel=1}
            Triggers=(New-TestTaskCollection)
            Actions=(New-TestTaskCollection -Actions)
        }
    }
    $service | Add-Member ScriptMethod RegisterTaskDefinition {
        param($Name,$Definition,$Flags,$Identity,[AllowNull()][securestring]$Password,$LogonType,$Sddl)
        $this.Calls.Add([pscustomobject]@{Name=$Name;Task=$Definition;Flags=$Flags;Identity=$Identity;Password=$Password;LogonType=$LogonType})
        if ($Flags -eq 1) {
            if ($this.RejectValidation) { throw 'Synthetic invalid task XML' }
        }
        elseif ($Flags -eq 6) {
            if (-not $this.LauncherReady) { throw 'Task registered before launcher ready' }
            if ($this.RejectRegistration) { throw 'Synthetic registration access denied' }
            $this.Installed=$Definition
        }
        else { throw 'Unexpected task registration flags' }
    }
    return $service
}

Test-Case 'launcher quotes spaces, Unicode and VBS literals; hides, waits and propagates exit' {
    $content = New-WhutLauncherContent 'C:\Program Files\PowerShell\7\pwsh.exe' 'C:\Synthetic 空间\campus & net.ps1'
    Assert-True ($content.Contains('""C:\Program Files\PowerShell\7\pwsh.exe"" -NoLogo -NoProfile -NonInteractive -File ""C:\Synthetic 空间\campus & net.ps1"" auto'))
    Assert-True ($content.Contains('result = shell.Run(commandLine, 0, True)'))
    Assert-True ($content.Contains('WScript.Quit result'))
    Assert-True ($content.Contains('-Command ""exit 73""'))
    Assert-True ($content.Contains('If Err.Number <> 0 Then WScript.Quit 50'))
    Assert-True (-not ($content -match 'credential|username|password|csrf|cookie|While|Do Until'))
    foreach ($bad in @('relative.ps1', 'C:\bad"path.ps1', "C:\bad`npath.ps1")) {
        Assert-Code { New-WhutLauncherContent 'C:\pwsh.exe' $bad } 50
    }
}

Test-Case 'missing script, PowerShell and WSH fail closed before launcher creation' {
    function Test-Path { $false }
    Assert-Code { New-WhutTaskActionSpec 'C:\missing\whut-net.ps1' } 50
    Assert-Code { Resolve-WhutScriptHost } 50
    function Test-Path { param($LiteralPath,$PathType) $LiteralPath -eq 'C:\Synthetic\whut-net.ps1' }
    function Resolve-PwshExecutable { 'C:\missing\pwsh.exe' }
    function Resolve-WhutScriptHost { 'C:\Windows\System32\wscript.exe' }
    Assert-Code { New-WhutTaskActionSpec 'C:\Synthetic\whut-net.ps1' } 50
}

Test-Case 'launcher is UTF16, readback-validated, atomic and leaves previous file on probe failure' {
    $saved = $Script:DataDir
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('whut-launcher-' + [guid]::NewGuid().ToString('N'))
    $Script:DataDir=$directory
    $spec=[pscustomobject]@{Execute='C:\Synthetic\wscript.exe';LauncherPath=(Join-Path $directory 'wutnet-hidden.vbs');LauncherContent=(New-WhutLauncherContent 'C:\Synthetic\pwsh.exe' 'C:\Synthetic\whut-net.ps1')}
    function Test-WhutLauncher {
        param($Spec)
        Assert-True (Test-Path -LiteralPath $Spec.LauncherPath)
        Assert-True ($Spec.LauncherPath.EndsWith('.tmp.vbs'))
    }
    try {
        Initialize-WhutLauncher $spec
        Assert-Equal ([IO.File]::ReadAllText($spec.LauncherPath)) $spec.LauncherContent
        $bytes=[IO.File]::ReadAllBytes($spec.LauncherPath)
        Assert-Equal $bytes[0] 255; Assert-Equal $bytes[1] 254
        $original=(Get-FileHash -LiteralPath $spec.LauncherPath).Hash
        function Test-WhutLauncher { throw 'Synthetic WSH policy disabled' }
        $spec.LauncherContent='invalid replacement'
        Assert-Code { Initialize-WhutLauncher $spec } 50
        Assert-Equal (Get-FileHash -LiteralPath $spec.LauncherPath).Hash $original
        Assert-Equal @(Get-ChildItem -LiteralPath $directory).Count 1
        function Initialize-WhutDataDirectory { throw 'Synthetic write denial' }
        Assert-Code { Initialize-WhutLauncher $spec } 50
    }
    finally {
        Remove-Item -LiteralPath $spec.LauncherPath -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $directory
        $Script:DataDir=$saved
    }
}

Test-Case 'complete task definition has five valid triggers, finite limits and least privilege' {
    $service=New-TestScheduleService
    $spec=[pscustomobject]@{Execute='C:\Windows\System32\wscript.exe';Arguments='//B //NoLogo "C:\Synthetic Data\wutnet-hidden.vbs"';WorkingDirectory='C:\Synthetic Scripts'}
    $task=New-WhutTaskDefinition $service $spec 'SYNTHETIC\User'
    Assert-Equal $task.Triggers.Count 5
    Assert-Equal (($task.Triggers.Items | ForEach-Object Type) -join ',') '9,0,11,0,2'
    $logon,$network,$unlock,$resume,$periodic=$task.Triggers.Items
    foreach ($trigger in $task.Triggers.Items) { Assert-True $trigger.Enabled }
    Assert-Equal $logon.UserId 'SYNTHETIC\User'; Assert-Equal $logon.Delay 'PT5S'
    Assert-Equal $network.Delay 'PT3S'
    Assert-Equal ([xml]$network.Subscription).QueryList.Query.Path 'Microsoft-Windows-NetworkProfile/Operational'
    Assert-True ($network.Subscription.Contains('EventID=10000'))
    Assert-Equal $unlock.UserId 'SYNTHETIC\User'; Assert-Equal $unlock.StateChange 8; Assert-Equal $unlock.Delay 'PT3S'
    Assert-Equal ([xml]$resume.Subscription).QueryList.Query.Path 'System'
    Assert-True ($resume.Subscription.Contains("Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1"))
    Assert-Equal $resume.Delay 'PT3S'
    Assert-Equal $periodic.DaysInterval 1
    Assert-Equal ([DateTime]::Parse($periodic.StartBoundary)) ([DateTime]::Today)
    Assert-Equal $periodic.Repetition.Interval 'PT2M'; Assert-Equal $periodic.Repetition.Duration 'P1D'
    Assert-True (-not $periodic.Repetition.StopAtDurationEnd)
    Assert-Equal $task.Settings.MultipleInstances 2; Assert-Equal $task.Settings.ExecutionTimeLimit 'PT2M'
    Assert-True $task.Settings.Hidden; Assert-True $task.Settings.StartWhenAvailable
    Assert-True (-not $task.Settings.DisallowStartIfOnBatteries); Assert-True (-not $task.Settings.StopIfGoingOnBatteries)
    Assert-Equal $task.Principal.LogonType 3; Assert-Equal $task.Principal.RunLevel 0
    Assert-Equal $task.Actions.Count 1; Assert-Equal $task.Actions.Items[0].Path $spec.Execute
    Assert-Equal $task.Actions.Items[0].Arguments $spec.Arguments
    Assert-Equal $task.Actions.Items[0].WorkingDirectory $spec.WorkingDirectory
}

foreach ($scenario in @('repeat','launcher-fails','validation-fails','registration-fails','missing-config','untrusted')) {
    Test-Case "installation lifecycle: $scenario" {
        $service=New-TestScheduleService
        $service.Installed='synthetic old direct PowerShell action'
        function Test-Path { param($LiteralPath,$PathType) $scenario -ne 'missing-config' }
        function Read-Config { [pscustomobject]@{version=3;trustedNetworks=@()} }
        function Get-TrustedNetworks { if ($scenario -ne 'untrusted') { New-TestNetwork } }
        function Resolve-PwshExecutable { 'C:\Synthetic PowerShell\pwsh.exe' }
        function Resolve-WhutScriptHost { 'C:\Windows\System32\wscript.exe' }
        function New-Object { param($ComObject) Assert-Equal $ComObject 'Schedule.Service'; return $service }
        function Initialize-WhutLauncher {
            param($Spec)
            Assert-Equal $service.Calls.Count 1
            Assert-Equal $service.Calls[0].Flags 1
            if ($scenario -eq 'launcher-fails') { Stop-Whut 50 'Synthetic launcher write/probe failure' }
            $service.LauncherReady=$true
        }
        if ($scenario -eq 'validation-fails') { $service.RejectValidation=$true }
        if ($scenario -eq 'registration-fails') { $service.RejectRegistration=$true }
        if ($scenario -eq 'repeat') {
            Assert-Equal (Install-WhutScheduledTask) 0
            $first=$service.Installed
            Assert-Equal $first.Triggers.Count 5
            Assert-Equal $first.Actions.Items[0].Path 'C:\Windows\System32\wscript.exe'
            $service.Calls.Clear(); $service.LauncherReady=$false
            Assert-Equal (Install-WhutScheduledTask) 0
            Assert-Equal $service.Installed.Triggers.Count 5
            Assert-True (-not [object]::ReferenceEquals($first,$service.Installed))
            Assert-Equal ($first | ConvertTo-Json -Depth 8) ($service.Installed | ConvertTo-Json -Depth 8)
            Assert-Equal $service.Calls[1].Name 'WHUT-Net AutoLogin'
            Assert-Equal $service.Calls[1].Flags 6
            Assert-Equal $service.Calls[1].Password $null
            Assert-Equal $service.Calls[1].LogonType 3
        }
        else {
            $seen=$false
            try { Install-WhutScheduledTask | Out-Null }
            catch {
                $seen=$true
                if ($scenario -eq 'registration-fails') {
                    Assert-Equal $_.Exception.Data['ExitCode'] 40
                    Assert-True ($_.Exception.Message.Contains('Synthetic registration access denied'))
                }
            }
            Assert-True $seen
            Assert-Equal $service.Installed 'synthetic old direct PowerShell action'
            $expected=if ($scenario -eq 'registration-fails') {2} elseif ($scenario -in @('missing-config','untrusted')) {0} else {1}
            Assert-Equal $service.Calls.Count $expected
        }
    }
}

Test-Case 'approved production verbs and command contracts retain all public commands' {
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'whut-net.ps1'),[ref]$tokens,[ref]$errors)
    $verbs=@(Get-Verb | ForEach-Object Verb)
    foreach ($function in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
        Assert-True (($function.Name -split '-',2)[0] -in $verbs) $function.Name
    }
    foreach ($commandName in @('run','setup','status','login','auto','diagnose','trust-current','networks','install','uninstall','help')) {
        Test-WhutCommandParameters $commandName @{}
    }
    foreach ($pair in @(@('setup','Username'),@('remove-network','NetworkId'),@('setup','Label'),@('trust-current','Label'),@('setup','AddNetwork'),@('run','Yes'),@('login','Yes'))) {
        $arguments=@{}; $arguments[$pair[1]]='synthetic'
        Test-WhutCommandParameters $pair[0] $arguments
    }
    foreach ($commandName in @('run','setup','status','login','auto','diagnose','trust-current','networks','remove-network')) {
        $arguments=@{Json=$true}
        if ($commandName -eq 'remove-network') { $arguments.NetworkId='synthetic' }
        Test-WhutCommandParameters $commandName $arguments
    }
}

Test-Case 'unsupported parameter combinations fail before command work with exit 50' {
    foreach ($pair in @(@('status','Username'),@('run','Label'),@('login','AddNetwork'),@('auto','Yes'),@('help','Json'),@('install','Json'),@('uninstall','NetworkId'))) {
        $arguments=@{}; $arguments[$pair[1]]='synthetic'
        Assert-Code { Test-WhutCommandParameters $pair[0] $arguments } 50
    }
    Assert-Code { Test-WhutCommandParameters setup @{AddNetwork=$true;Username='synthetic'} } 50
    Assert-Code { Test-WhutCommandParameters run @{Yes=$true;Json=$true} } 50
    Assert-Code { Test-WhutCommandParameters remove-network @{} } 50
}

Test-Case 'auto retains mutex and cooldown skips without credential or network work' {
    function Invoke-LoginCommand { throw 'Unexpected login during skip' }
    function Read-ProtectedPassword { throw 'Unexpected credential during skip' }
    function Enter-AutoMutex { $null }
    Assert-Equal (Invoke-AutoCommand) 0
    $mutex=[pscustomobject]@{Released=$false;Disposed=$false}
    $mutex | Add-Member ScriptMethod ReleaseMutex { $this.Released=$true }
    $mutex | Add-Member ScriptMethod Dispose { $this.Disposed=$true }
    function Enter-AutoMutex { $mutex }
    function Get-AutoCooldownRemaining { 25 }
    Assert-Equal (Invoke-AutoCommand) 0
    Assert-True $mutex.Released; Assert-True $mutex.Disposed
}

Test-Case 'success cooldown and increasing failure backoff remain bounded' {
    $state=[pscustomobject]@{failureCount=0;nextAllowedUtc=$null}
    function Get-AutoState { $state }
    function Save-AutoState {
        param($FailureCount,$NextAllowedUtc)
        $state.failureCount=$FailureCount; $state.nextAllowedUtc=$NextAllowedUtc
    }
    foreach ($expected in @(30,120,300,300)) {
        Register-AutoFailure
        $remaining=Get-AutoCooldownRemaining
        Assert-True ($remaining -ge ($expected-2) -and $remaining -le $expected)
    }
    Register-AutoSuccess
    Assert-Equal $state.failureCount 0
    Assert-True ((Get-AutoCooldownRemaining) -ge 28 -and (Get-AutoCooldownRemaining) -le 30)
}
