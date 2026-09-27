$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
foreach ($name in @('Ensure-EnumNative', 'Clear-EnumCaptureState', 'Publish-EnumTerminal', 'Read-EnumTerminal', 'Invoke-CapturedProcess', 'Start-EnumJob', 'Stop-EnumJob', 'Complete-EnumJob', 'Watch-EnumOutput')) {
    $fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $testRoot | Out-Null
$passed = $false
$failed = $false
$sharedLock = $null
try {
    $ToolTimeoutSeconds = 10
    $script:ShowRawOutput = $false
    $script:enumOffsets = @{}
    $seen = @{}
    $worker = Join-Path $testRoot 'worker.ps1'
    "Write-Output ('start:' + [DateTime]::UtcNow.Ticks); Write-Output 'CVE-2021-44228'; Start-Sleep -Seconds 2; Write-Output ('end:' + [DateTime]::UtcNow.Ticks); Write-Output 'finished'" |
        Set-Content -LiteralPath $worker -Encoding ASCII
    $exe = (Get-Process -Id $PID).Path
    $first = Start-EnumJob 'first' $exe "-NoProfile -File `"$worker`"" (Join-Path $testRoot 'first.txt')
    $second = Start-EnumJob 'second' $exe "-NoProfile -File `"$worker`"" (Join-Path $testRoot 'second.txt')
    while ($first.Job.State -in @('NotStarted', 'Running') -or $second.Job.State -in @('NotStarted', 'Running')) {
        Watch-EnumOutput $first $seen
        Watch-EnumOutput $second $seen
        Start-Sleep -Milliseconds 100
    }
    Watch-EnumOutput $first $seen
    Watch-EnumOutput $second $seen
    if ((Complete-EnumJob $first) -ne 'checked' -or (Complete-EnumJob $second) -ne 'checked') {
        throw 'Concurrent captures did not complete'
    }
    if (-not $seen.ContainsKey('CVE-2021-44228')) { throw 'Live CVE alert screen missed output' }
    $starts = @()
    $ends = @()
    foreach ($name in @('first.txt', 'second.txt')) {
        $raw = Get-Content -LiteralPath (Join-Path $testRoot $name) -Raw
        if ($raw -notmatch 'finished') {
            throw "Final output absent: $name"
        }
        $startMark = [regex]::Match($raw, 'start:([0-9]+)')
        $endMark = [regex]::Match($raw, 'end:([0-9]+)')
        if (-not $startMark.Success -or -not $endMark.Success) { throw "Timing markers absent: $name" }
        $starts += [long]$startMark.Groups[1].Value
        $ends += [long]$endMark.Groups[1].Value
    }
    if ([Math]::Max($starts[0], $starts[1]) -ge [Math]::Min($ends[0], $ends[1])) {
        throw 'Collectors did not overlap'
    }
    $sharedWorker = Join-Path $testRoot 'shared-worker.ps1'
    "Write-Output started; Start-Sleep -Seconds 15" | Set-Content -LiteralPath $sharedWorker -Encoding ASCII
    $ToolTimeoutSeconds = 6
    $sharedOutput = Join-Path $testRoot 'shared-timeout.txt'
    $shared = Start-EnumJob 'shared-timeout' $exe "-NoProfile -File `"$sharedWorker`"" $sharedOutput
    $sharedReady = Join-Path $testRoot 'shared-ready.txt'
    $sharedLock = Start-Job -ScriptBlock {
        param($path, $ready)
        $stream = $null
        for ($i = 0; $i -lt 100 -and -not $stream; $i++) {
            try {
                $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write,
                    ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            } catch [IO.IOException] { Start-Sleep -Milliseconds 100 }
        }
        if (-not $stream) { throw 'Outside writer could not open the live capture' }
        try {
            [IO.File]::WriteAllText($ready, 'ready')
            Start-Sleep -Seconds 15
        } finally { $stream.Dispose() }
    } -ArgumentList "$sharedOutput.stdout", $sharedReady
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $sharedReady) -and [DateTime]::UtcNow -lt $readyDeadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $sharedReady)) { throw 'Outside writer never held the live capture' }
    if ((Complete-EnumJob $shared) -ne 'timeout') { throw 'Timed-out shared capture lost its terminal status' }
    $sharedMarker = Get-Content -LiteralPath $shared.Terminal -Raw | ConvertFrom-Json
    if ($sharedMarker.status -ne 'timeout' -or -not (Test-Path -LiteralPath $sharedOutput) -or
        -not (Test-Path -LiteralPath "$sharedOutput.stdout")) {
        throw 'Timed-out shared snapshot or raw part was not retained'
    }
    if (-not (Wait-Job -Job $sharedLock -Timeout 20)) { throw 'Outside writer did not exit' }
    Remove-Job -Job $sharedLock -Force
    $sharedLock = $null
    $ToolTimeoutSeconds = 10
    $slow = Join-Path $testRoot 'slow.ps1'
    "Write-Output 'started'; Start-Sleep -Seconds 8; Write-Output 'late'" |
        Set-Content -LiteralPath $slow -Encoding ASCII
    $stopped = Start-EnumJob 'stopped' $exe "-NoProfile -File `"$slow`"" (Join-Path $testRoot 'stopped.txt')
    Start-Sleep -Milliseconds 400
    Stop-EnumJob $stopped
    if ((Complete-EnumJob $stopped) -ne 'partial-after-proof') { throw 'Stopped collector was not partial' }
    Stop-EnumJob $stopped
    if ((Complete-EnumJob $stopped) -ne 'partial-after-proof') { throw 'Repeated stop downgraded terminal collector' }

    $immediate = Start-EnumJob 'immediate' $exe "-NoProfile -File `"$slow`"" (Join-Path $testRoot 'immediate.txt')
    Stop-EnumJob $immediate
    if ((Complete-EnumJob $immediate) -ne 'partial-after-proof') { throw 'Immediate stop was not bounded partial' }

    $descendantMarker = Join-Path $testRoot 'stopped-descendant.txt'
    $descendantReady = Join-Path $testRoot 'descendant-ready.txt'
    $descendantCode = "Set-Content -LiteralPath '$($descendantReady.Replace("'", "''"))' -Value ready -Encoding ASCII; Start-Sleep -Seconds 4; Set-Content -LiteralPath '$($descendantMarker.Replace("'", "''"))' -Value late -Encoding ASCII"
    $descendantEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($descendantCode))
    $descendantWorker = Join-Path $testRoot 'descendant.ps1'
    "Start-Process -FilePath '$($exe.Replace("'", "''"))' -ArgumentList '-NoProfile -EncodedCommand $descendantEncoded'; Write-Output started; Start-Sleep -Seconds 8" |
        Set-Content -LiteralPath $descendantWorker -Encoding ASCII
    $descendant = Start-EnumJob 'descendant' $exe "-NoProfile -File `"$descendantWorker`"" (Join-Path $testRoot 'descendant.txt')
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $descendantReady) -and [DateTime]::UtcNow -lt $readyDeadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $descendantReady)) { throw 'Descendant did not start before cancellation' }
    Stop-EnumJob $descendant
    if ((Complete-EnumJob $descendant) -ne 'partial-after-proof') { throw 'Descendant stop was not partial' }
    Start-Sleep -Seconds 5
    if (Test-Path -LiteralPath $descendantMarker) { throw 'Descendant survived cancellation' }

    $expiredReady = Join-Path $testRoot 'expired-descendant-ready.txt'
    $expiredMarker = Join-Path $testRoot 'expired-descendant-late.txt'
    $expiredCode = "Set-Content -LiteralPath '$($expiredReady.Replace("'", "''"))' -Value ready -Encoding ASCII; Start-Sleep -Seconds 8; Set-Content -LiteralPath '$($expiredMarker.Replace("'", "''"))' -Value late -Encoding ASCII"
    $expiredEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($expiredCode))
    $expiredWorker = Join-Path $testRoot 'expired-descendant.ps1'
    "Start-Process -FilePath '$($exe.Replace("'", "''"))' -ArgumentList '-NoProfile -EncodedCommand $expiredEncoded'; Write-Output started; Start-Sleep -Seconds 60" |
        Set-Content -LiteralPath $expiredWorker -Encoding ASCII
    $ToolTimeoutSeconds = 30
    $expired = Start-EnumJob 'expired' $exe "-NoProfile -File `"$expiredWorker`"" (Join-Path $testRoot 'expired.txt')
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $expiredReady) -and [DateTime]::UtcNow -lt $readyDeadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $expiredReady)) { throw 'Expired-deadline descendant did not start' }
    $expired.Deadline = [DateTime]::UtcNow.AddSeconds(-([int]$expired.GraceSeconds + 1))
    $expiredStatus = Complete-EnumJob $expired
    if ($expiredStatus -ne 'partial-after-proof') {
        throw "Expired deadline skipped the fresh cancellation grace: $expiredStatus"
    }
    if (-not (Test-Path -LiteralPath $expired.Terminal)) { throw 'Expired-deadline terminal was not published' }
    Start-Sleep -Seconds 9
    if (Test-Path -LiteralPath $expiredMarker) { throw 'Expired-deadline descendant survived cancellation' }
    $ToolTimeoutSeconds = 10

    $terminal = Start-EnumJob 'terminal' $exe "-NoProfile -File `"$worker`"" (Join-Path $testRoot 'terminal.txt')
    if ((Complete-EnumJob $terminal) -ne 'checked') { throw 'Normal terminal collector failed' }
    Stop-EnumJob $terminal
    if ((Complete-EnumJob $terminal) -ne 'checked') { throw 'Stop-after-terminal downgraded collector' }

    $reuseOutput = Join-Path $testRoot 'reuse.txt'
    '{"version":1,"launch_id":"00000000000000000000000000000000","status":"checked","exit_code":0}' |
        Set-Content -LiteralPath "$reuseOutput.terminal.json" -Encoding ASCII
    $reuse = Start-EnumJob 'reuse' $exe "-NoProfile -File `"$worker`"" $reuseOutput
    if ((Complete-EnumJob $reuse) -ne 'checked') { throw 'Stale terminal marker was reused' }
    $reuseMarker = Get-Content -LiteralPath "$reuseOutput.terminal.json" -Raw | ConvertFrom-Json
    if ($reuseMarker.launch_id -cne $reuse.LaunchId) { throw 'Terminal marker launch binding was not refreshed' }
    if (-not (Get-ChildItem -LiteralPath $testRoot -Filter 'reuse.txt.terminal.json.stale.*' -File)) {
        throw 'Stale terminal marker was not quarantined'
    }

    $missing = Start-EnumJob 'missing' $exe "-NoProfile -File `"$worker`"" (Join-Path $testRoot 'missing.txt')
    while ($missing.Job.State -in @('NotStarted', 'Running') -and -not (Test-Path -LiteralPath $missing.Terminal)) {
        Start-Sleep -Milliseconds 100
    }
    if (Test-Path -LiteralPath $missing.Terminal) { Remove-Item -LiteralPath $missing.Terminal -Force }
    $missing.Deadline = [DateTime]::UtcNow.AddSeconds(-1)
    if ((Complete-EnumJob $missing) -ne 'cleanup-failed') { throw 'Missing terminal marker was accepted' }

    $runnerText = Get-Content -LiteralPath $source -Raw
    $cleanupGate = $runnerText.IndexOf('if ($enumCleanupFailed)', [StringComparison]::Ordinal)
    $rawPromotion = $runnerText.IndexOf('Move-Item -LiteralPath $from -Destination', [StringComparison]::Ordinal)
    $zipPromotion = $runnerText.IndexOf("Move-Item -LiteralPath `$sharpCollectedZip.FullName", [StringComparison]::Ordinal)
    if ($cleanupGate -lt 0 -or $rawPromotion -lt $cleanupGate -or $zipPromotion -lt $cleanupGate) {
        throw 'Cleanup failure gate does not precede raw and ZIP promotion'
    }
    $successWrites = [regex]::Matches($runnerText, 'ConvertTo-Json -Compress \| Set-Content -LiteralPath \(Join-Path \$runDir ''success\.json''\)')
    if ($successWrites.Count -eq 0) { throw 'Final success marker write was not found' }
    foreach ($write in $successWrites) {
        if ($write.Index -lt $cleanupGate) { throw 'Cleanup failure gate does not precede success marker publication' }
    }
    if ($runnerText.IndexOf('$winpeasStatus -ne ''cleanup-failed''', [StringComparison]::Ordinal) -lt 0) {
        throw 'WinPEAS fallback is not blocked after cleanup failure'
    }
    $stopBeforeProof = $runnerText.IndexOf("if (-not `$FinishBgEnum -and -not `$NoShell -and `$fastRecipe -in @('already-system', 'already-admin'))", [StringComparison]::Ordinal)
    $stopAfterProof = $runnerText.IndexOf("if (-not `$FinishBgEnum -and -not `$NoShell) {`n                foreach (`$entry in `$enumJobs) { Stop-EnumJob `$entry }", [StringComparison]::Ordinal)
    if ($stopBeforeProof -lt 0 -or $stopAfterProof -lt 0 -or $stopBeforeProof -ge $stopAfterProof) {
        throw 'Foreground collector cleanup policy is missing or reordered'
    }
    $passed = $true
    'PowerShell concurrent capture and live CVE screening passed'
} catch {
    $failed = $true
    [Console]::Error.WriteLine($_.Exception.ToString())
} finally {
    if ($sharedLock) {
        Stop-Job -Job $sharedLock -ErrorAction SilentlyContinue
        Remove-Job -Job $sharedLock -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
if ($failed -or -not $passed) { exit 1 }
