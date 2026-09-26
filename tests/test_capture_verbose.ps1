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
    $child = 'cmd.exe'
    $output = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    try {
        $status = Invoke-CapturedProcess $child '/d /c "echo started & ping -n 4 127.0.0.1 >nul & echo done"' $output 10
        if ($status -ne 'checked') { throw "capture status: $status" }
        if ((Get-Content -LiteralPath $output -Raw) -notmatch 'started.*(?s:.)*done') { throw 'raw capture incomplete' }
        'worker-verified'
    } finally { Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue }
    exit 0
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $console = Join-Path $testRoot 'console.txt'
    $child = (Get-Process -Id $PID).Path
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $child
    $start.Arguments = "-NoProfile -File `"$PSCommandPath`" -Worker"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $consoleStream = New-Object IO.FileStream -ArgumentList @($console, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1)
    $errorStream = New-Object IO.FileStream -ArgumentList @((Join-Path $testRoot 'console.err'), [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1)
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($consoleStream)
    $stderrTask = $process.StandardError.BaseStream.CopyToAsync($errorStream)
    $live = $false
    $deadline = (Get-Date).AddSeconds(8)
    while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
        if (Test-Path -LiteralPath $console) {
            $stream = [IO.File]::Open($console, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $reader = $null
            try {
                $reader = New-Object IO.StreamReader -ArgumentList $stream
                if ($reader.ReadToEnd().Contains('started')) { $live = $true; break }
            } finally {
                if ($reader) { $reader.Dispose() } else { $stream.Dispose() }
            }
        }
        Start-Sleep -Milliseconds 100
    }
    $process.WaitForExit()
    [void]$stdoutTask.Wait(5000)
    [void]$stderrTask.Wait(5000)
    if ((Get-Content -LiteralPath $console -Raw) -notmatch 'worker-verified') {
        throw "verbose worker failed: $(Get-Content -LiteralPath (Join-Path $testRoot 'console.err') -Raw)"
    }
    if (-not $live) { throw 'raw output was not visible while the enumerator ran' }
    if ((Get-Content -LiteralPath $console -Raw) -notmatch 'started.*(?s:.)*done') { throw 'console output incomplete' }
    'Verbose captured output was visible before process completion and preserved in the raw file'
} finally {
    if ($consoleStream) { $consoleStream.Dispose() }
    if ($errorStream) { $errorStream.Dispose() }
    if ($process) { $process.Dispose() }
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
