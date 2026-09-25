param([switch]$Worker)

$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
foreach ($name in @('Write-CapturedTail', 'Invoke-CapturedProcess')) {
    $fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}

if ($Worker) {
    $script:ShowRawOutput = $true
    $child = (Get-Process -Id $PID).Path
    $output = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    try {
        $status = Invoke-CapturedProcess $child '-NoProfile -Command "Write-Output started; Start-Sleep -Seconds 2; Write-Output done"' $output 10
        if ($status -ne 'checked') { throw "capture status: $status" }
        if ((Get-Content -LiteralPath $output -Raw) -notmatch 'started.*(?s:.)*done') { throw 'raw capture incomplete' }
    } finally { Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue }
    exit 0
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $console = Join-Path $testRoot 'console.txt'
    $child = (Get-Process -Id $PID).Path
    $process = Start-Process -FilePath $child -ArgumentList "-NoProfile -File `"$PSCommandPath`" -Worker" -RedirectStandardOutput $console -PassThru -NoNewWindow
    $live = $false
    $deadline = (Get-Date).AddSeconds(8)
    while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
        if (Test-Path -LiteralPath $console) {
            $stream = [IO.File]::Open($console, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            try {
                $reader = [IO.StreamReader]::new($stream)
                if ($reader.ReadToEnd().Contains('started')) { $live = $true; break }
            } finally { $reader.Dispose() }
        }
        Start-Sleep -Milliseconds 100
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "verbose worker failed: $($process.ExitCode)" }
    if (-not $live) { throw 'raw output was not visible while the enumerator ran' }
    if ((Get-Content -LiteralPath $console -Raw) -notmatch 'started.*(?s:.)*done') { throw 'console output incomplete' }
    'Verbose captured output was visible before process completion and preserved in the raw file'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
