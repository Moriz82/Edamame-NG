$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
foreach ($name in @('Invoke-CapturedProcess', 'Start-EnumJob', 'Stop-EnumJob', 'Complete-EnumJob', 'Watch-EnumOutput')) {
    $fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $ToolTimeoutSeconds = 10
    $script:ShowRawOutput = $false
    $script:enumOffsets = @{}
    $seen = @{}
    $worker = Join-Path $testRoot 'worker.ps1'
    "Write-Output 'CVE-2021-44228'; Start-Sleep -Seconds 2; Write-Output 'finished'" |
        Set-Content -LiteralPath $worker -Encoding ASCII
    $exe = (Get-Process -Id $PID).Path
    $first = Start-EnumJob 'first' $exe "-NoProfile -File `"$worker`"" (Join-Path $testRoot 'first.txt')
    $second = Start-EnumJob 'second' $exe "-NoProfile -File `"$worker`"" (Join-Path $testRoot 'second.txt')
    $watch = [Diagnostics.Stopwatch]::StartNew()
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
    if ($watch.Elapsed.TotalSeconds -ge 3.8) { throw 'Collectors ran sequentially' }
    if (-not $seen.ContainsKey('CVE-2021-44228')) { throw 'Live CVE alert screen missed output' }
    foreach ($name in @('first.txt', 'second.txt')) {
        if ((Get-Content -LiteralPath (Join-Path $testRoot $name) -Raw) -notmatch 'finished') {
            throw "Final output absent: $name"
        }
    }
    $slow = Join-Path $testRoot 'slow.ps1'
    "Write-Output 'started'; Start-Sleep -Seconds 8; Write-Output 'late'" |
        Set-Content -LiteralPath $slow -Encoding ASCII
    $stopped = Start-EnumJob 'stopped' $exe "-NoProfile -File `"$slow`"" (Join-Path $testRoot 'stopped.txt')
    Start-Sleep -Milliseconds 400
    Stop-EnumJob $stopped
    if ((Complete-EnumJob $stopped) -ne 'partial-after-proof') { throw 'Stopped collector was not partial' }
    'PowerShell concurrent capture and live CVE screening passed'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
