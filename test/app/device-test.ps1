param(
    [Parameter(Mandatory = $true)][string]$SuperKey,
    [string]$Serial,
    [string]$Adb = 'adb',
    [string]$Apk,
    [string]$Kpm,
    [ValidateSet('manual', 'linker')][string]$Backend = 'manual',
    [switch]$ExpectPoll,
    [switch]$RootInstall,
    [ValidateRange(1, 100)][int]$Repeat = 10
)
$ErrorActionPreference = 'Stop'
if ($SuperKey -notmatch '^[A-Za-z0-9_@.+-]+$') { throw 'Use a shell-safe superkey with this test runner.' }
$ModuleDir = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$RepoDir = $ModuleDir
if (-not $Apk) { $Apk = Join-Path $RepoDir 'build/kclf-apptest/app.apk' }
$Apk = (Resolve-Path -LiteralPath $Apk).Path
if (-not $Kpm) { $Kpm = Join-Path $ModuleDir 'kclf.kpm' }
$Kpm = (Resolve-Path -LiteralPath $Kpm).Path
$RunId = 'kclf-app-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$Results = Join-Path $RepoDir ('build/' + $RunId)
$Remote = '/data/local/tmp/' + $RunId
$Package = 'com.kclf.apptest'
$Transcript = [Collections.Generic.List[string]]::new()
$Loaded = $false
$Passed = $false
$CleanupFailed = $false
New-Item -ItemType Directory -Path $Results | Out-Null

function Log([string]$Text) { $Transcript.Add($Text); Write-Host $Text }
function Invoke-Adb([string[]]$Arguments, [switch]$AllowFailure) {
    $Saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $Output = & $Adb -s $Serial @Arguments 2>&1
        $Code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $Saved }
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
    Log (($Arguments -join ' ') + " => rc=$($Result.Code) $($Result.Text)")
    return $Result
}
function Ctl([string]$Command, [switch]$AllowFailure) {
    if ($Command.StartsWith('inject,')) { $Command += ",$Backend" }
    Kpm @('ctl0', 'kclf', $Command) -AllowFailure:$AllowFailure
}
function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    Log ('PASS: ' + $Message)
}
function Start-App {
    $OldText = (Invoke-Adb @('shell', 'pidof', $Package) -AllowFailure).Text.Trim()
    $OldIds = @($OldText -split '\s+' | Where-Object { $_ -match '^\d+$' })
    Invoke-Adb @('shell', 'am', 'force-stop', $Package) | Out-Null
    # ActivityManager may prestart a replacement before am start, which then
    # reports WARM. Prove process death/replacement, not the UI launch label.
    foreach ($OldId in $OldIds) {
        $Watch = [Diagnostics.Stopwatch]::StartNew()
        do {
            $Exists = Invoke-Adb @('shell', 'test', '-d', "/proc/$OldId") -AllowFailure
            if ($Exists.Code -eq 1) { break }
            if ($Exists.Code -ne 0) { throw "Cannot check old process $OldId : $($Exists.Text)" }
            Start-Sleep -Milliseconds 100
        } while ($Watch.ElapsedMilliseconds -lt 5000)
        Check ($Exists.Code -eq 1) "old app process $OldId exited before restart"
    }
    $Result = Invoke-Adb @('shell', 'am', 'start', '-W', '-n', "$Package/.MainActivity")
    Log $Result.Text
    Check ($Result.Text -match 'Status: ok') 'test app activity starts successfully'
    $Text = (Invoke-Adb @('shell', 'pidof', $Package)).Text.Trim()
    Check ($Text -match '^\d+$') 'one test app process is running'
    Check ($Text -notin $OldIds) 'test app starts in a fresh process'
    Log ("process restart: old=$OldText new=$Text")
    # Wait for onCreate to create filesDir and the sleeper, not a fixed delay.
    for ($i = 0; $i -lt 40; $i++) {
        if ((Root "ps -T -p $Text -o TID,CMD") -match 'kclf-sleeper') { return [int]$Text }
        Start-Sleep -Milliseconds 100
    }
    throw 'test app sleeper did not start'
}
function Await-State([string]$Expected) {
    $Watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $Result = Ctl 'status'
        if ($Result.Text -match 'state=(done|failed|cancelled)' -and $Result.Text -notmatch 'pending=| map=') {
            Check ($Result.Text -match $Expected) "request completes as $Expected with no callback/mapping left"
            if ($ExpectPoll -and $Expected -eq 'state=done') {
                Check ($Result.Text -match 'done=poll') 'completion uses sleepable controller poll'
            }
            return $Result.Text
        }
        Start-Sleep -Milliseconds 100
    } while ($Watch.ElapsedMilliseconds -lt 15000)
    throw 'app injection timed out'
}
function Verify-Marker([int]$TargetId, [int]$ThreadId) {
    $Text = (Invoke-Adb @('shell', 'run-as', $Package, 'cat', "files/hit_$TargetId")).Text
    Log ('marker: ' + $Text)
    Check ($Text -match "pid=$TargetId tid=$ThreadId marker=0x[0-9a-f]+") 'payload constructor witnessed in the exact target thread'
    $LiveIds = (Invoke-Adb @('shell', 'pidof', $Package) -AllowFailure).Text.Trim()
    Check ($LiveIds -eq "$TargetId") "app survives injection without process replacement (expected=$TargetId actual=$LiveIds)"
}
function Inject-App([int]$TargetId, [int]$ThreadId, [string]$Flags, [string]$Payload = $Library) {
    Invoke-Adb @('shell', 'run-as', $Package, 'rm', '-f', "files/hit_$TargetId") | Out-Null
    Ctl "inject,$ThreadId,$Payload$Flags" | Out-Null
    $Status = Await-State 'state=done'
    $Via = if ($Backend -eq 'manual') { 'via=manual' } else { 'via=__loader_dlopen' }
    Check ($Status -match $Via -and $Status -match 'loading=0') "$Backend backend used and loading count cleared"
    Check ($Status -match 'done=(syscall|poll)') 'EL0 completion independently observed'
    Verify-Marker $TargetId $ThreadId
    $Maps = Root "cat /proc/$TargetId/maps"
    $PayloadName = [regex]::Escape(($Payload -split '/')[-1])
    $Marker = (Invoke-Adb @('shell', 'run-as', $Package, 'cat', "files/hit_$TargetId")).Text
    Check ($Marker -match 'marker=0x([0-9a-f]+)') 'fresh constructor address recorded'
    $ConstructorPc = [Convert]::ToUInt64($Matches[1], 16)
    $ConstructorMaps = @($Maps -split "`n" | Where-Object {
        $_ -match '^([0-9a-f]+)-([0-9a-f]+) ' -and
        [Convert]::ToUInt64($Matches[1], 16) -le $ConstructorPc -and
        [Convert]::ToUInt64($Matches[2], 16) -gt $ConstructorPc
    })
    if ($Flags -match ',unload') {
        Check ($Status -match 'unload=ok rc=0') 'payload finalization succeeded'
        Check ($ConstructorMaps.Count -eq 0) 'constructor address unmapped after payload finalization'
        if ($Backend -eq 'linker') { Check ($Maps -notmatch $PayloadName) 'payload file mappings absent after dlclose' }
        if ($Backend -eq 'manual') {
            Check ($Status -match 'refs=0 resident=0\+0') 'manual resident allocation reclaimed'
            Check ((Ctl 'images').Text -match 'no manual images') 'manual image registry empty'
        }
    } else {
        Check ($ConstructorMaps.Count -eq 1 -and $ConstructorMaps[0] -match ' r-xp ') 'retained constructor is mapped executable'
        if ($Backend -eq 'manual') {
            Check ($Status -match 'refs=1 resident=[1-9a-f][0-9a-f]*\+[1-9]\d*') 'normal injection retains a manual resident image'
        } else { Check ($Maps -match $PayloadName) 'normal injection retains payload mappings' }
    }
    Ctl 'reap' | Out-Null
}
function Find-Thread([int]$TargetId, [string]$Name) {
    $Threads = Root "ps -T -p $TargetId -o TID,CMD"
    if ($Threads -notmatch ('(?m)^\s*(\d+)\s+' + [regex]::Escape($Name) + '\s*$')) {
        throw "Missing app thread $Name"
    }
    return [int]$Matches[1]
}
function Await-Running {
    $Watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $Text = (Ctl 'status').Text
        if ($Text -match 'state=running.*map=([0-9a-f]+)\+(\d+)') { return $Text }
        if ($Text -match 'state=failed') { throw $Text }
        Start-Sleep -Milliseconds 50
    } while ($Watch.ElapsedMilliseconds -lt 5000)
    throw 'Did not observe app constructor running'
}

if (-not $Serial) {
    $Connected = @(& $Adb devices | ForEach-Object { if ($_ -match '^(\S+)\s+device$') { $Matches[1] } })
    if ($Connected.Count -ne 1) { throw 'Select one device with -Serial.' }
    $Serial = $Connected[0]
}

try {
    Check ((Kpm @('list')).Text -notmatch '(?m)^kclf$') 'no pre-existing kclf module; other modules untouched'
    Log ((Invoke-Adb @('shell', 'uname', '-a')).Text)
    Log ('serial=' + $Serial)
    Log ('backend=' + $Backend)
    Log ('module SHA256=' + (Get-FileHash -Algorithm SHA256 $Kpm).Hash)
    Log ('APK SHA256=' + (Get-FileHash -Algorithm SHA256 $Apk).Hash)
    $BootBefore = Root 'cat /proc/sys/kernel/random/boot_id'
    $PolicyBefore = Root 'getenforce'
    $DmesgBefore = Root 'dmesg'
    $DmesgBefore | Set-Content -LiteralPath (Join-Path $Results 'dmesg-before.txt') -Encoding utf8
    # libc can report Fatal signal in main before debuggerd produces a crash
    # record. Its 15-byte thread name is om.kclf.apptest on this device.
    $CrashBefore = (Invoke-Adb @('logcat', '-b', 'main', '-b', 'crash', '-d',
        '-s', 'libc:F', 'DEBUG:F', 'AndroidRuntime:E')).Text
    $CrashBefore | Set-Content -LiteralPath (Join-Path $Results 'crash-before.txt') -Encoding utf8

    Invoke-Adb @('shell', 'mkdir', $Remote) | Out-Null
    if ($RootInstall) {
        Invoke-Adb @('push', $Apk, "$Remote/app.apk") | Out-Null
        $Install = @{ Text = (Root "pm install -r -t $Remote/app.apk") }
    } else {
        $Install = Invoke-Adb @('install', '-r', '-t', $Apk)
    }
    Log $Install.Text
    Check ($Install.Text -match 'Success') 'freshly built APK installed without uninstalling or clearing app data'
    $TargetId = Start-App
    $BaseApk = (Invoke-Adb @('shell', 'pm', 'path', $Package)).Text.Trim() -replace '^package:', ''
    Check ($BaseApk -match '^/data/app/[^\s]+/base.apk$') 'installed APK path resolved'
    $Library = ($BaseApk -replace '/base.apk$', '/lib/arm64/libkclfapp_payload.so')
    $FpLibrary = $Library -replace 'libkclfapp_payload.so$', 'libkclfapp_fp.so'
    $HoldLibrary = $Library -replace 'libkclfapp_payload.so$', 'libkclfapp_hold.so'
    Log ('payload=' + $Library)
    $AppStatus = Root "cat /proc/$TargetId/status"
    $AppStatus | Set-Content -LiteralPath (Join-Path $Results 'app-status.txt') -Encoding utf8
    Check ($AppStatus -match 'Seccomp:\s+2' -and $AppStatus -match 'Uid:\s+[1-9]\d+') 'ordinary non-root app retains zygote seccomp filter'
    Check ((Root "cat /proc/$TargetId/attr/current") -match 'untrusted_app') 'test app stays in untrusted_app SELinux domain'

    Invoke-Adb @('push', $Kpm, "$Remote/kclf.kpm") | Out-Null
    Kpm @('load', "$Remote/kclf.kpm") | Out-Null
    Check ((Kpm @('list')).Text -match '(?m)^kclf$') 'module really loaded (not just adb exit code)'
    $Loaded = $true
    $Probe = (Ctl 'probe').Text
    Check ($Probe -match 'pt_regs=ok' -and $Probe -match 'completion=el0') 'register layout and EL0 completion available'

    Log 'CASE: main thread, wake + unload'
    Inject-App $TargetId $TargetId ',wake,unload'
    $Threads = Root "ps -T -p $TargetId -o TID,CMD"
    $Threads | Set-Content -LiteralPath (Join-Path $Results 'threads.txt') -Encoding utf8
    Check ($Threads -match '(?m)^\s*(\d+)\s+kclf-sleeper\s*$') 'periodic Java sleeper located'
    $SleeperId = [int]$Matches[1]
    Log 'CASE: sleeper thread, natural resume + unload'
    Inject-App $TargetId $SleeperId ',unload'
    Check ($Threads -match '(?m)^\s*(\d+)\s+[Bb]inder:\d+_\d+\s*$') 'app Binder thread located'
    $BinderId = [int]$Matches[1]
    Log 'CASE: Binder thread, wake + unload'
    Inject-App $TargetId $BinderId ',wake,unload'

    Log 'CASE: app FPSIMD sentinels survive deliberately clobbering constructor'
    $FpId = Find-Thread $TargetId 'kclf-fp'
    Inject-App $TargetId $FpId ',unload' $FpLibrary
    Start-Sleep -Milliseconds 1200
    $FpLog = (Invoke-Adb @('shell', 'run-as', $Package, 'cat', "files/fp_$TargetId")).Text
    $FpLog | Set-Content -LiteralPath (Join-Path $Results 'fp-log.txt') -Encoding utf8
    Check ($FpLog -match 'tick=[1-9]\d* fp-state-failure=0' -and $FpLog -notmatch 'fp-state-failure=[1-9]') 'app q0/q8/q31 + FPCR/FPSR restored; probe continues'

    Log 'CASE: four app threads queued, duplicate/full slots, cancellation'
    $MarkerBefore = (Invoke-Adb @('shell', 'run-as', $Package, 'cat', "files/hit_$TargetId")).Text
    $IdleIds = @(0..3 | ForEach-Object { Find-Thread $TargetId "kclf-idle$_" })
    foreach ($ThreadId in $IdleIds) { Ctl "inject,$ThreadId,$Library,unload" | Out-Null }
    $Queued = (Ctl 'status').Text
    Check (([regex]::Matches($Queued, 'state=armed')).Count -eq 4) 'all four ordinary-app requests remain queued without wake'
    Check ((Ctl "inject,$($IdleIds[0]),$Library,unload" -AllowFailure).Code -ne 0) 'duplicate request does not corrupt existing queue'
    Check ((Ctl "inject,$TargetId,$Library,wake" -AllowFailure).Code -ne 0) 'full request table reports failure without corrupting slots'
    foreach ($Slot in 0..3) { Ctl "cancel,$Slot" | Out-Null }
    Check (([regex]::Matches((Ctl 'status').Text, 'state=cancelled')).Count -eq 4) 'all app callbacks cancelled before execution'
    Ctl 'reap' | Out-Null
    Check ((Ctl 'status').Text -match 'no requests') 'all cancelled app slots reclaimed'
    Check ((Invoke-Adb @('shell', 'run-as', $Package, 'cat', "files/hit_$TargetId")).Text -eq $MarkerBefore) 'cancelled requests did not run a constructor'
    Inject-App $TargetId $IdleIds[0] ',wake,unload'

    Log 'CASE: missing SO failure and recovery'
    Ctl "inject,$TargetId,$Library.missing,wake" | Out-Null
    Check ((Await-State 'state=failed') -match 'stage=prepare.*rc=-2') 'missing SO fails in prepare without retained resources'
    Ctl 'reap' | Out-Null
    Inject-App $TargetId $TargetId ',wake,unload'

    Log 'CASE: truncated ELF reaches loader failure and restores app'
    Invoke-Adb @('shell', 'run-as', $Package, 'dd', "if=$Library", 'of=files/truncated.so', 'bs=64', 'count=1') | Out-Null
    Ctl "inject,$TargetId,/data/user/0/$Package/files/truncated.so,wake" | Out-Null
    $FailureStage = if ($Backend -eq 'manual') { 'prepare' } else { 'loader' }
    Check ((Await-State 'state=failed') -match "stage=$FailureStage.*err=") 'invalid ELF fails at the selected backend stage'
    Check ((Invoke-Adb @('shell', 'pidof', $Package)).Text.Trim() -eq "$TargetId") 'app survives invalid payload'
    Ctl 'reap' | Out-Null

    Log "CASE: $Repeat consecutive main-thread loads/unloads"
    for ($i = 1; $i -le $Repeat; $i++) {
        Log "iteration=$i"
        Inject-App $TargetId $TargetId ',wake,unload'
    }

    Log 'CASE: force-stop after completion WITHOUT reap; cold restart'
    Ctl "inject,$TargetId,$Library,wake" | Out-Null
    Await-State 'state=done' | Out-Null
    Verify-Marker $TargetId $TargetId
    if ($Backend -eq 'manual') {
        Check ((Ctl 'images').Text -match 'state=live refs=1') 'normal load registers a live manual image'
    } else { Check ((Root "cat /proc/$TargetId/maps") -match 'libkclfapp_payload.so') 'normal load keeps the SO in the app' }
    $OldTargetId = $TargetId
    $TargetId = Start-App
    Check ($TargetId -ne $OldTargetId) 'force-stop replaces the old process while completed request still exists'
    Check ((Invoke-Adb @('shell', 'ls', "-d", "/proc/$OldTargetId") -AllowFailure).Code -ne 0) 'old process really exited'
    Ctl 'reap' | Out-Null

    Log 'CASE: force-stop while app callback is queued'
    $IdleId = Find-Thread $TargetId 'kclf-idle0'
    Ctl "inject,$IdleId,$Library,unload" | Out-Null
    Check ((Ctl 'status').Text -match 'state=armed') 'app work queued before target exit'
    $TargetId = Start-App
    Ctl 'reap' | Out-Null
    Check ((Ctl 'status').Text -match 'no requests[\s\S]*loading=0') 'exiting app drains queued task_work'

    Log 'CASE: force-stop while app constructor is running'
    $IdleId = Find-Thread $TargetId 'kclf-idle0'
    Ctl "inject,$IdleId,$HoldLibrary,wake,unload" | Out-Null
    Await-Running | Out-Null
    $TargetId = Start-App
    Ctl 'reap' | Out-Null
    Check ((Ctl 'status').Text -match 'no requests[\s\S]*loading=0') 'running-target death releases request/loading count'

    Log 'CASE: transient mapping/guard and busy quiesce in ordinary app'
    $IdleId = Find-Thread $TargetId 'kclf-idle0'
    Ctl "inject,$IdleId,$HoldLibrary,wake,unload" | Out-Null
    $Running = Await-Running
    Check ($Running -match 'map=([0-9a-f]+)\+(\d+)') 'app trampoline mapping observed'
    $MapStart = [Convert]::ToUInt64($Matches[1], 16)
    $MapSize = [UInt64]$Matches[2]
    Check ($Running -match 'code=([0-9a-f]+) guard=([0-9a-f]+)') 'randomized code and guard positions reported'
    $CodeStart = [Convert]::ToUInt64($Matches[1], 16)
    $GuardStart = [Convert]::ToUInt64($Matches[2], 16)
    Check ($Probe -match 'page=(\d+)') 'page size reported'
    $PageSize = [UInt64]$Matches[1]
    $MapEnd = $MapStart + $MapSize
    $CodeHex = $CodeStart.ToString('x')
    $CodeEndHex = ($CodeStart + $PageSize).ToString('x')
    $GuardHex = $GuardStart.ToString('x')
    $GuardEndHex = ($GuardStart + $PageSize).ToString('x')
    $StackHex = ($GuardStart + $PageSize).ToString('x')
    $Maps = Root "cat /proc/$TargetId/maps"
    $Maps | Set-Content -LiteralPath (Join-Path $Results 'maps-running.txt') -Encoding utf8
    $Range = @($Maps -split "`n" | Where-Object {
        if ($_ -match '^([0-9a-f]+)-([0-9a-f]+) ') {
            $Begin = [Convert]::ToUInt64($Matches[1], 16)
            $Begin -ge $MapStart -and $Begin -lt $MapEnd
        }
    })
    Check ($CodeStart -ge $MapStart -and $CodeStart + $PageSize -le $MapEnd) 'code lies inside the transient region'
    Check (@($Range | Where-Object { $_ -match "^$CodeHex-$CodeEndHex r-xp " }).Count -eq 1) 'exactly one RX page at the reported random code offset'
    if ($Running -match 'stack=task/') {
        Check ($MapSize -ge 3 * $PageSize -and $MapSize -le 11 * $PageSize -and $GuardStart -eq 0) 'borrowed stack uses 3..11 transient pages without an extra guard'
    } else {
        Check ($MapSize -ge 10 * $PageSize -and $MapSize -le 28 * $PageSize) 'dedicated stack uses 10..28 transient pages'
        Check ($GuardStart -ge $MapStart -and $GuardStart + $PageSize -le $MapEnd) 'guard lies inside the transient region'
        Check (@($Range | Where-Object { $_ -match "^$GuardHex-$GuardEndHex ---p " }).Count -eq 1) 'PROT_NONE guard at the reported random position'
        Check (@($Range | Where-Object { $_ -match "^$StackHex-\S+ rw-p " }).Count -eq 1) 'transient stack starts immediately above the guard'
    }
    Check ($Maps -notmatch '(?m)^\S+ rwxp ') 'no RWX mapping in app'
    $Quiet = Ctl 'quiesce' -AllowFailure
    Check ($Quiet.Code -ne 0 -and $Quiet.Text -match 'quiesce=busy') 'busy quiesce keeps app completion hook alive'
    Check ((Await-State 'state=done') -match 'unload=ok') 'app constructor completes and unloads during quiesce'
    Verify-Marker $TargetId $IdleId
    $Maps = Root "cat /proc/$TargetId/maps"
    $Maps | Set-Content -LiteralPath (Join-Path $Results 'maps-after.txt') -Encoding utf8
    $Overlap = $false
    foreach ($Line in ($Maps -split "`n")) {
        if ($Line -match '^([0-9a-f]+)-([0-9a-f]+) ') {
            if ([Convert]::ToUInt64($Matches[1], 16) -lt $MapStart + $MapSize -and
                [Convert]::ToUInt64($Matches[2], 16) -gt $MapStart) { $Overlap = $true }
        }
    }
    Check (-not $Overlap -and $Maps -notmatch 'libkclfapp_hold.so') 'whole transient range and held payload reclaimed'
    Ctl 'reap' | Out-Null
    Check ((Ctl 'quiesce').Text -match 'quiesce=idle') 'app work fully drained before unload'
    Kpm @('unload', 'kclf') | Out-Null
    $Loaded = $false
    Kpm @('load', "$Remote/kclf.kpm") | Out-Null
    $Loaded = $true
    Check ((Ctl 'probe').Text -match 'quiescing=0') 'module reload resets quiesce state'
    Inject-App $TargetId $TargetId ',wake,unload'
    Check ((Ctl 'status').Text -match 'no requests[\s\S]*loading=0') 'request table empty after all app tests'
    $Passed = $true
} catch {
    Log ('ERROR: ' + $_.Exception.Message)
    throw
} finally {
    try {
        if (-not $Passed) { Invoke-Adb @('shell', 'am', 'force-stop', $Package) | Out-Null }
        if ($Loaded) {
            Ctl 'reap' | Out-Null
            $Quiet = Ctl 'quiesce' -AllowFailure
            if ($Quiet.Code -eq 0 -and $Quiet.Text -match 'quiesce=idle') {
                Kpm @('unload', 'kclf') | Out-Null
                Check ((Kpm @('list')).Text -notmatch '(?m)^kclf$') 'test module safely drained and unloaded'
            } else { throw 'Module retained: callbacks not drained; DO NOT force unload.' }
        }
        Invoke-Adb @('shell', 'am', 'force-stop', $Package) | Out-Null
        Check ((Root 'cat /proc/sys/kernel/random/boot_id') -eq $BootBefore) 'boot ID unchanged'
        Check ((Root 'getenforce') -eq $PolicyBefore) 'SELinux enforcement unchanged'
        $DmesgAfter = Root 'dmesg'
        $DmesgAfter | Set-Content -LiteralPath (Join-Path $Results 'dmesg-after.txt') -Encoding utf8
        $NewFaults = @($DmesgAfter -split "`n" | Where-Object {
            $_ -match 'BUG:|WARNING:|Oops:|Kernel panic' -and -not $DmesgBefore.Contains($_)
        })
        Check ($NewFaults.Count -eq 0) 'no new retained kernel BUG/WARNING/Oops/panic'
        $CrashAfter = (Invoke-Adb @('logcat', '-b', 'main', '-b', 'crash', '-d',
            '-s', 'libc:F', 'DEBUG:F', 'AndroidRuntime:E')).Text
        $CrashAfter | Set-Content -LiteralPath (Join-Path $Results 'crash-after.txt') -Encoding utf8
        $NewCrashes = @($CrashAfter -split "`n" | Where-Object {
            $_ -match 'com\.kclf\.apptest|Fatal signal.*\(om\.kclf\.apptest\)' -and -not $CrashBefore.Contains($_)
        })
        Check ($NewCrashes.Count -eq 0) 'no new test-app fatal signal/Java crash in main or crash logs'
        if ($Passed) { Log 'ALL APP CASES PASSED; APK retained, test app stopped.' }
    } catch {
        $CleanupFailed = $true
        Log ('FINAL VERIFICATION ERROR: ' + $_.Exception.Message)
    }
    $Transcript | Set-Content -LiteralPath (Join-Path $Results 'results.txt') -Encoding utf8
    Write-Host "Evidence: $Results"
}
if ($CleanupFailed) { throw 'App test cleanup/final verification failed; see results.txt.' }
