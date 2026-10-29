param(
    [Parameter(Mandatory = $true)][string]$SuperKey,
    [string]$Serial,
    [string]$Adb = 'adb'
)
$ErrorActionPreference = 'Stop'
if ($SuperKey -notmatch '^[A-Za-z0-9_.+-]+$') { throw 'This test runner requires a shell-safe key.' }
$ModuleDir = Split-Path $PSScriptRoot -Parent
$RepoDir = (Resolve-Path (Join-Path $ModuleDir '../..')).Path
$RunId = 'kclf-test-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$Remote = '/data/local/tmp/' + $RunId
$Results = Join-Path $RepoDir ('build/' + $RunId)
New-Item -ItemType Directory -Path $Results | Out-Null
$Transcript = [Collections.Generic.List[string]]::new()
$Targets = [Collections.Generic.List[int]]::new()
$Loaded = $false

function Invoke-Adb([string[]]$Arguments, [switch]$AllowFailure) {
    # Windows PowerShell 5.1 turns native stderr into terminating errors when
    # ErrorActionPreference is Stop; adb writes progress there. Keep the call
    # non-terminating and decide from the exit code below.
    $Saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $Output = & $Adb -s $Serial @Arguments 2>&1
        $Code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $Saved
    }
    $Text = ($Output | ForEach-Object { "$_" }) -join "`n"
    if ($Code -ne 0 -and -not $AllowFailure) { throw "adb rc=$Code : $Text" }
    return @{ Text = $Text; Code = $Code }
}
function Root([string]$Command) {
    if ($Command.Contains("'")) { throw 'Internal quoting error' }
    (Invoke-Adb @('shell', "/data/local/tmp/kpatch $SuperKey su -c '$Command'")).Text
}
function Kpm([string[]]$Arguments, [switch]$AllowFailure) {
    $Result = Invoke-Adb (@('shell', '/data/local/tmp/kpatch', $SuperKey, 'kpm') + $Arguments) -AllowFailure:$AllowFailure
    $Line = ($Arguments -join ' ') + " => rc=$($Result.Code) $($Result.Text)"
    $Transcript.Add($Line)
    Write-Host $Line
    return $Result
}
function Ctl([string]$Command, [switch]$AllowFailure) {
    Kpm @('ctl0', 'kclf', $Command) -AllowFailure:$AllowFailure
}
function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $Transcript.Add('PASS: ' + $Message)
    Write-Host ('PASS: ' + $Message)
}
function Start-Target([string]$Mode) {
    $Text = Root "sh $Remote/launch.sh $Mode"
    Check ($Text.Trim() -match '^\d+$') 'test target returned a PID'
    $TargetId = [int]$Text.Trim()
    $Targets.Add($TargetId)
    return $TargetId
}
function Inject([int]$TargetId, [string]$Flags = '', [string]$Library = "$Remote/libkclf_payload.so") {
    Ctl "inject,$TargetId,$Library,linker$Flags"
}
function Await-State([string]$Expected, [int]$Milliseconds = 10000) {
    $Watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $Result = Ctl 'status'
        if ($Result.Text -match $Expected -and $Result.Text -notmatch 'pending=| map=') { return $Result.Text }
        Start-Sleep -Milliseconds 150
    } while ($Watch.ElapsedMilliseconds -lt $Milliseconds)
    throw "Timed out waiting for $Expected"
}
function Stop-Target([int]$TargetId) {
    # Validate the exact process before signalling; never use killall/pkill.
    Root "if [ -r /proc/$TargetId/cmdline ] && grep -q $Remote/kclf_target /proc/$TargetId/cmdline; then kill -KILL $TargetId; fi" | Out-Null
}
function Await-Running {
    for ($i = 0; $i -lt 20; $i++) {
        $State = Ctl 'status'
        if ($State.Text -match 'state=running.*map=([0-9a-f]+)\+(\d+)') { return $State.Text }
        Start-Sleep -Milliseconds 100
    }
    throw 'Did not observe running constructor'
}

if (-not $Serial) {
    $Devices = & $Adb devices
    $Connected = @($Devices | ForEach-Object { if ($_ -match '^(\S+)\s+device$') { $Matches[1] } })
    if ($Connected.Count -ne 1) { throw 'Select exactly one authorised device with -Serial.' }
    $Serial = $Connected[0]
}

try {
    $Existing = Kpm @('list')
    Check ($Existing.Text -notmatch '(?m)^kclf$') 'no pre-existing kclf module (other modules are untouched)'
    $Identity = (Invoke-Adb @('shell', 'uname', '-a')).Text
    $BootBefore = Root 'cat /proc/sys/kernel/random/boot_id'
    $Transcript.Add($Identity)
    $Transcript.Add('boot_id=' + $BootBefore)
    $Transcript.Add('kclf.kpm SHA256=' + (Get-FileHash -Algorithm SHA256 (Join-Path $ModuleDir 'kclf.kpm')).Hash)
    $PolicyBefore = Root 'getenforce'
    $Transcript.Add('SELinux=' + $PolicyBefore)
    $DmesgBefore = Root 'dmesg'
    $DmesgBefore | Set-Content -LiteralPath (Join-Path $Results 'dmesg-before.txt') -Encoding utf8
    Invoke-Adb @('shell', 'mkdir', $Remote) | Out-Null
    foreach ($Name in @('kclf_target', 'libkclf_payload.so', 'launch.sh')) {
        Invoke-Adb @('push', (Join-Path $PSScriptRoot $Name), "$Remote/$Name") | Out-Null
    }
    Invoke-Adb @('push', (Join-Path $ModuleDir 'kclf.kpm'), "$Remote/kclf.kpm") | Out-Null
    Invoke-Adb @('shell', 'chmod', '755', "$Remote/kclf_target") | Out-Null
    Kpm @('load', "$Remote/kclf.kpm") | Out-Null
    $Loaded = $true
    $Probe = (Ctl 'probe').Text
    Check ($Probe -match 'pt_regs=ok' -and $Probe -match 'page=(\d+)') 'runtime layout validated'
    $PageSize = [UInt64]$Matches[1]
    Check ((Ctl 'sym').Text.Length -le 1023) 'symbol diagnostics bounded'

    $Normal = Start-Target 'normal'
    Inject $Normal | Out-Null
    $Status = Await-State 'state=done'
    Check ($Status -match 'via=__loader_dlopen' -and $Status -match 'loading=0') 'normal loader completion and cleanup'
    Check ((Root "cat $Remote/hit_$Normal") -match "pid=$Normal ") 'constructor independently witnessed'
    Check ((Root "cat /proc/$Normal/maps") -match 'libkclf_payload.so') 'normal mode retains payload mapping'
    Ctl 'reap' | Out-Null

    $Unload = Start-Target 'unload'
    Inject $Unload ',unload' | Out-Null
    Check ((Await-State 'state=done') -match 'unload=ok') 'dlclose completion'
    Check ((Root "cat /proc/$Unload/maps") -notmatch 'libkclf_payload.so') 'dlclose removes payload mapping'
    Check ((Root "cat $Remote/hit_$Unload") -match "pid=$Unload ") 'unload-mode constructor witnessed'
    Ctl 'reap' | Out-Null

    $Fp = Start-Target 'fp'
    Inject $Fp ',unload' | Out-Null
    Await-State 'state=done' | Out-Null
    Start-Sleep -Seconds 3
    $FpLog = Root "cat $Remote/fp.log"
    Check ($FpLog -match 'payload constructed' -and $FpLog -match 'tick 25' -and $FpLog -notmatch 'fp-state-failure') 'q0/q8/q31, FPCR/FPSR survive deliberate payload clobber'
    Ctl 'reap' | Out-Null

    $Filtered = Start-Target 'seccomp'
    Start-Sleep -Milliseconds 200
    Check ((Root "cat $Remote/seccomp.log") -match 'seccomp-test-ready') 'isolated allow-all seccomp filter installed on test target only'
    Inject $Filtered | Out-Null
    Check ((Await-State 'state=done') -match 'via=') 'seccomp-filtered target completes through its own policy'
    Check ((Root "cat $Remote/hit_$Filtered") -match "pid=$Filtered ") 'seccomp-filtered constructor independently witnessed'
    Ctl 'reap' | Out-Null

    Inject $Normal '' "$Remote/missing.so" | Out-Null
    Check ((Await-State 'state=failed') -match 'stage=prepare.*rc=-2') 'missing library fails without mapping'
    Ctl 'reap' | Out-Null
    Root "dd if=$Remote/libkclf_payload.so of=$Remote/truncated.so bs=64 count=1 2>/dev/null" | Out-Null
    Inject $Normal '' "$Remote/truncated.so" | Out-Null
    Check ((Await-State 'state=failed') -match 'stage=loader.*err=') 'truncated ELF yields loader error and restores target'
    Ctl 'reap' | Out-Null

    foreach ($Bad in @("inject,999999999999999999999999,$Remote/libkclf_payload.so", "inject,$Normal,$Remote/libkclf_payload.so,notforce", 'cancel,4294967296', ('help,' + ('a' * 520)), 'help,a,b,c,d,e,f,g,h', 'status,unexpected')) {
        Check ((Ctl $Bad -AllowFailure).Code -ne 0) 'invalid/overflowing command rejected'
    }

    $Slow = Start-Target 'slow'
    Inject $Slow | Out-Null
    Check ((Ctl 'status').Text -match 'state=armed') 'resume mode waits for natural return'
    Check ((Ctl "inject,$Slow,$Remote/libkclf_payload.so" -AllowFailure).Code -ne 0) 'duplicate target rejected'
    Ctl 'cancel,0' | Out-Null
    Check ((Ctl 'status').Text -match 'state=cancelled') 'queued callback cancellation verified'
    Ctl 'reap' | Out-Null

    for ($i = 0; $i -lt 4; $i++) {
        $SlotTarget = Start-Target 'slow'
        Inject $SlotTarget | Out-Null
    }
    Check (([regex]::Matches((Ctl 'status').Text, 'state=armed')).Count -eq 4) 'four independent request slots'
    Check ((Ctl "inject,$Normal,$Remote/libkclf_payload.so" -AllowFailure).Code -ne 0) 'fifth request rejected when slots are full'
    for ($i = 0; $i -lt 4; $i++) { Ctl "cancel,$i" | Out-Null }
    Ctl 'reap' | Out-Null
    Check ((Ctl 'status').Text -match 'no requests') 'all cancelled slots reusable'

    $Wake = Start-Target 'slow'
    if ($Probe -match 'wake=(notify_signal|task_work_signal)') {
        Inject $Wake ',wake,unload' | Out-Null
        Check ((Await-State 'state=done' 4000) -match 'unload=ok') 'task-work signal wake mode completes'
    } else {
        Check ((Ctl "inject,$Wake,$Remote/libkclf_payload.so,wake,unload" -AllowFailure).Code -ne 0) 'unsupported legacy wake mode explicitly rejected'
    }
    Ctl 'reap' | Out-Null

    $Exiting = Start-Target 'slow'
    Inject $Exiting | Out-Null
    Stop-Target $Exiting
    Start-Sleep -Milliseconds 500
    Ctl 'reap' | Out-Null
    Check ((Ctl 'status').Text -match 'no requests') 'target exits with queued work; slot reclaimed'

    $KilledLoader = Start-Target 'hold'
    Inject $KilledLoader | Out-Null
    Await-Running | Out-Null
    Stop-Target $KilledLoader
    Start-Sleep -Milliseconds 500
    Ctl 'reap' | Out-Null
    Check ((Ctl 'status').Text -match 'no requests[\s\S]*loading=0') 'target exits inside loader; loading count and request slot reclaimed'

    $Holding = Start-Target 'hold'
    Inject $Holding ',unload' | Out-Null
    $Running = Await-Running
    Check ($Running -match 'map=([0-9a-f]+)\+(\d+)') 'transient mapping reported while constructor runs'
    $MapStart = [Convert]::ToUInt64($Matches[1], 16)
    $MapSize = [UInt64]$Matches[2]
    $Maps = Root "cat /proc/$Holding/maps"
    $GuardStart = ($MapStart + 2 * $PageSize).ToString('x')
    $GuardEnd = ($MapStart + 3 * $PageSize).ToString('x')
    Check ($Maps -match "(?m)^$GuardStart-$GuardEnd ---p ") 'exact trampoline stack guard visible'
    Check ($MapSize -eq 11 * $PageSize) 'transient mapping matches page-size-aware eleven-page layout'
    Check ($Maps -notmatch '(?m)^\S+ rwxp ') 'no RWX mapping'
    $Quiet = Ctl 'quiesce' -AllowFailure
    Check ($Quiet.Code -ne 0 -and $Quiet.Text -match 'quiesce=busy') 'busy quiesce does not remove completion hook'
    Check ((Ctl "inject,$Normal,$Remote/libkclf_payload.so" -AllowFailure).Code -ne 0) 'quiescing rejects new requests'
    Check ((Await-State 'state=done') -match 'unload=ok') 'in-flight constructor still completes during quiesce'
    $AfterMaps = Root "cat /proc/$Holding/maps"
    $Overlap = $false
    foreach ($Line in ($AfterMaps -split "`n")) {
        if ($Line -match '^([0-9a-f]+)-([0-9a-f]+) ') {
            $First = [Convert]::ToUInt64($Matches[1], 16)
            $Last = [Convert]::ToUInt64($Matches[2], 16)
            if ($First -lt ($MapStart + $MapSize) -and $Last -gt $MapStart) { $Overlap = $true }
        }
    }
    Check (-not $Overlap) 'entire transient interval unmapped after completion'
    Check ($AfterMaps -notmatch 'libkclf_payload.so') 'holding payload unloaded'
    Ctl 'reap' | Out-Null
    Check ((Ctl 'quiesce').Text -match 'quiesce=idle') 'drain complete before legacy-host unload'
    Kpm @('unload', 'kclf') | Out-Null
    $Loaded = $false
    Kpm @('load', "$Remote/kclf.kpm") | Out-Null
    $Loaded = $true
    Check ((Ctl 'probe').Text -match 'quiescing=0') 'module reload resets lifecycle state'
    Check ((Root 'cat /proc/sys/kernel/random/boot_id') -eq $BootBefore) 'device did not reboot'
    Check ((Root 'getenforce') -eq $PolicyBefore) 'SELinux policy mode unchanged'
    Check ((Root "if [ -f $Remote/hit_$Slow ]; then echo hit; else echo absent; fi") -eq 'absent') 'cancelled target never ran constructor'
    $Transcript.Add('ALL DEVICE CASES PASSED')
} catch {
    $Transcript.Add('ERROR: ' + $_.Exception.Message)
    throw
} finally {
    foreach ($TargetId in $Targets) {
        try { Stop-Target $TargetId } catch { $Transcript.Add("cleanup target $TargetId : " + $_.Exception.Message) }
    }
    if ($Loaded) {
        try {
            Start-Sleep -Milliseconds 500
            Ctl 'reap' | Out-Null
            $Quiet = Ctl 'quiesce' -AllowFailure
            if ($Quiet.Code -eq 0 -and $Quiet.Text -match 'quiesce=idle') {
                Kpm @('unload', 'kclf') | Out-Null
                Check ((Kpm @('list')).Text -notmatch '(?m)^kclf$') 'test module unloaded during final cleanup'
            } else {
                $Transcript.Add('Module retained: not safe to unload on legacy host.')
            }
        } catch { $Transcript.Add('module cleanup: ' + $_.Exception.Message) }
    }
    try {
        $DmesgAfter = Root 'dmesg'
        $DmesgAfter | Set-Content -LiteralPath (Join-Path $Results 'dmesg-after.txt') -Encoding utf8
        $NewFaults = @($DmesgAfter -split "`n" | Where-Object {
            $_ -match 'BUG:|WARNING:|Oops:|Kernel panic' -and -not $DmesgBefore.Contains($_)
        })
        Check ($NewFaults.Count -eq 0) 'no new BUG/WARNING/Oops/panic lines in retained kernel log'
    } catch { $Transcript.Add('kernel-log verification: ' + $_.Exception.Message) }
    $Transcript | Set-Content -LiteralPath (Join-Path $Results 'results.txt') -Encoding utf8
    Invoke-Adb @('pull', $Remote, $Results) -AllowFailure | Out-Null
    Write-Host "Evidence: $Results ; device artifacts retained at $Remote"
}
