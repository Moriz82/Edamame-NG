$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
$fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-CapturedProcess' }, $true)
. ([scriptblock]::Create($fn.Extent.Text))

$testRoot = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $output = Join-Path $testRoot 'success.txt'
    if ((Invoke-CapturedProcess 'cmd.exe' '/d /c echo smoke' $output 10) -ne 'checked') { throw 'good process was not checked' }
    if ((Get-Content -LiteralPath $output -Raw) -notmatch 'smoke') { throw 'stdout was not captured' }
    $output = Join-Path $testRoot 'timeout.txt'
    $status = Invoke-CapturedProcess 'powershell.exe' '-NoProfile -Command "Write-Output started; Start-Sleep -Seconds 4"' $output 1
    if ($status -ne 'timeout') { throw "slow process status: $status" }
    if ((Get-Content -LiteralPath $output -Raw) -notmatch 'started') { throw 'partial output was not preserved' }
    $output = Join-Path $testRoot 'nested-timeout.txt'
    $status = Invoke-CapturedProcess 'cmd.exe' '/d /c "echo started & ping -n 5 127.0.0.1 > nul"' $output 1
    if ($status -ne 'timeout') { throw "nested process status: $status" }
    if ((Get-Content -LiteralPath $output -Raw) -notmatch 'started') { throw 'nested partial output was not preserved' }
    $output = Join-Path $testRoot 'failure.txt'
    if ((Invoke-CapturedProcess 'cmd.exe' '/d /c exit 7' $output 10) -ne 'partial') { throw 'nonzero exit was accepted' }
    'Windows capture, exit status, and timeout passed'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
