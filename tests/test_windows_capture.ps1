$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
foreach ($name in @('Ensure-EnumNative', 'Publish-EnumTerminal', 'Invoke-CapturedProcess')) {
    $fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}

$testRoot = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $testRoot | Out-Null
$passed = $false
$failed = $false
try {
    $script:ShowRawOutput = $false
    $cmdExe = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    $psExe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $output = Join-Path $testRoot 'success.txt'
    if ((Invoke-CapturedProcess $cmdExe '/d /c echo smoke' $output 10) -ne 'checked') { throw 'good process was not checked' }
    if ((Get-Content -LiteralPath $output -Raw) -notmatch 'smoke') { throw 'stdout was not captured' }
    $output = Join-Path $testRoot 'timeout.txt'
    $status = Invoke-CapturedProcess $psExe '-NoProfile -Command "Write-Output started; Start-Sleep -Seconds 4"' $output 1
    if ($status -ne 'timeout') { throw "slow process status: $status" }
    if ((Get-Content -LiteralPath $output -Raw) -notmatch 'started') { throw 'partial output was not preserved' }
    $output = Join-Path $testRoot 'nested-timeout.txt'
    $status = Invoke-CapturedProcess $cmdExe '/d /c "echo started & ping -n 5 127.0.0.1 > nul"' $output 1
    if ($status -ne 'timeout') { throw "nested process status: $status" }
    if ((Get-Content -LiteralPath $output -Raw) -notmatch 'started') { throw 'nested partial output was not preserved' }
    $lateTimeout = Join-Path $testRoot 'late-timeout-child.txt'
    $rootStartedTimeout = Join-Path $testRoot 'root-started-timeout.txt'
    $lateTimeoutCommand = "Start-Sleep -Seconds 4; Set-Content -LiteralPath '$($lateTimeout.Replace("'", "''"))' -Value late -Encoding ASCII"
    $lateTimeoutEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($lateTimeoutCommand))
    $timeoutRootCommand = "Start-Process -FilePath '$($psExe.Replace("'", "''"))' -ArgumentList '-NoProfile -EncodedCommand $lateTimeoutEncoded'; Set-Content -LiteralPath '$($rootStartedTimeout.Replace("'", "''"))' -Value started -Encoding ASCII; Write-Output root-exited"
    $timeoutRootArgs = '/NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($timeoutRootCommand))
    $output = Join-Path $testRoot 'root-first-timeout.txt'
    if ((Invoke-CapturedProcess $psExe $timeoutRootArgs $output 1) -ne 'timeout') {
        throw 'root-exits-first timeout status was not timeout'
    }
    if (-not (Test-Path -LiteralPath $rootStartedTimeout)) { throw 'Timeout case did not start a descendant' }
    Start-Sleep -Seconds 5
    if (Test-Path -LiteralPath $lateTimeout) { throw 'descendant survived Job Object timeout' }
    $output = Join-Path $testRoot 'failure.txt'
    if ((Invoke-CapturedProcess $cmdExe '/d /c exit 7' $output 10) -ne 'partial') { throw 'nonzero exit was accepted' }
    if (-not (Test-Path -LiteralPath "$output.terminal.json")) { throw 'terminal marker missing' }
    $output = Join-Path $testRoot 'exit-259.txt'
    if ((Invoke-CapturedProcess $cmdExe '/d /c exit 259' $output 10) -ne 'partial') {
        throw 'exit code 259 was treated as a live process'
    }
    $marker = Get-Content -LiteralPath "$output.terminal.json" -Raw | ConvertFrom-Json
    if ($marker.exit_code -ne 259) { throw 'exit code 259 was not preserved' }

    $late = Join-Path $testRoot 'late-child.txt'
    $lateCommand = "Start-Sleep -Seconds 2; Set-Content -LiteralPath '$($late.Replace("'", "''"))' -Value child-late -Encoding ASCII"
    $lateEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($lateCommand))
    $rootCommand = "Start-Process -FilePath '$($psExe.Replace("'", "''"))' -ArgumentList '-NoProfile -EncodedCommand $lateEncoded'; Write-Output root-exited"
    $rootArgs = '/NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($rootCommand))
    $output = Join-Path $testRoot 'root-first.txt'
    if ((Invoke-CapturedProcess $psExe $rootArgs $output 10) -ne 'checked') { throw 'root-exits-first process was not checked' }
    if (-not (Test-Path -LiteralPath $late)) { throw 'job tree was not held until delayed child exited' }
    if ((Get-Content -LiteralPath $late -Raw).Trim() -ne 'child-late') { throw 'delayed child output was unstable' }
    $stable = Get-Content -LiteralPath $output -Raw
    Start-Sleep -Seconds 1
    if ((Get-Content -LiteralPath $output -Raw) -cne $stable) { throw 'final output changed after child delay' }

    $passed = $true
    'Windows capture, exit status, and timeout passed'
} catch {
    $failed = $true
    [Console]::Error.WriteLine($_.Exception.ToString())
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
if ($failed -or -not $passed) { exit 1 }
