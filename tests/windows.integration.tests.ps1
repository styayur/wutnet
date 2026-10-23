#requires -Version 7.2
#requires -PSEdition Core
# Safe local integration; no WUTNet authentication and no actual task registration.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'whut-net.ps1')
$directory=Join-Path ([IO.Path]::GetTempPath()) ('whut-integration 空间-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
try {
    $Script:DataDir=$directory
    $child=Join-Path $directory 'synthetic child.ps1'
    [IO.File]::WriteAllText($child, 'param([string]$Command) if ($Command -eq ''auto'') { exit 37 } else { exit 51 }')
    # Resolve the running executable rather than a Store alias to keep this test isolated.
    $pwshPath=Join-Path $PSHOME 'pwsh.exe'
    $spec=[pscustomobject]@{
        Execute=(Resolve-WhutScriptHost)
        LauncherPath=(Join-Path $directory 'wutnet-hidden.vbs')
        LauncherContent=(New-WhutLauncherContent $pwshPath $child)
        Arguments=('//B //NoLogo "{0}"' -f (Join-Path $directory 'wutnet-hidden.vbs'))
        WorkingDirectory=$directory
    }
    Initialize-WhutLauncher $spec
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$spec.Execute; $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    foreach ($argument in @('//B','//NoLogo',$spec.LauncherPath)) { $start.ArgumentList.Add($argument) }
    $process=[Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(15000)) { $process.Kill($true); throw 'WSH exit-code integration timed out' }
        if ($process.ExitCode -ne 37) { throw "WSH lost child exit code: $($process.ExitCode)" }
    }
    finally { $process.Dispose() }
    Write-Host 'PASS real WSH: generated UTF16/Unicode launcher waits and returns synthetic child exit 37'

    $service=New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    $task=New-WhutTaskDefinition $service $spec $identity
    $folder=$service.GetFolder('\')
    # TASK_VALIDATE_ONLY = 1: Windows validates full task XML without creating it.
    [void]$folder.RegisterTaskDefinition('WUTNet validation only', $task, 1, $identity, $null, 3, $null)
    [xml]$xml=$task.XmlText
    $namespace=[Xml.XmlNamespaceManager]::new($xml.NameTable)
    $namespace.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    if ($xml.SelectNodes('/t:Task/t:Triggers/*',$namespace).Count -ne 5) { throw 'COM XML lost triggers' }
    if ($xml.SelectSingleNode('//t:SessionStateChangeTrigger/t:StateChange',$namespace).InnerText -ne 'SessionUnlock') { throw 'COM unlock enum mismatch' }
    if ($xml.SelectSingleNode('//t:CalendarTrigger/t:ScheduleByDay/t:DaysInterval',$namespace).InnerText -ne '1') { throw 'COM daily recurrence mismatch' }
    if ($xml.SelectSingleNode('//t:CalendarTrigger/t:Repetition/t:Interval',$namespace).InnerText -ne 'PT2M') { throw 'COM repetition mismatch' }
    Write-Host 'PASS real Task Scheduler COM: five-trigger XML validated with TASK_VALIDATE_ONLY; no task registered'
}
finally {
    Get-ChildItem -LiteralPath $directory -File | Remove-Item -Force
    Remove-Item -LiteralPath $directory
}
exit 0
