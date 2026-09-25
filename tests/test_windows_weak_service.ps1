#requires -Version 5.1
param([switch]$ExpectedNotSystem)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($relative in @('Edamame-NG.ps1', 'lib\WeakServiceLab.ps1', 'tests\fixtures\windows\WeakServiceLab.ps1')) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root $relative), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "PowerShell parse failed in $relative`: $($errors[0].Message)" }
}
. (Join-Path $root 'lib\WeakServiceLab.ps1')
$trustedSc = Get-TrustedServiceControl
if ($trustedSc -cne (Join-Path ([Environment]::SystemDirectory) 'sc.exe')) {
    throw 'Service control path did not follow the Windows system directory'
}

$stream = [IO.MemoryStream]::new()
$writer = [IO.BinaryWriter]::new($stream, [Text.Encoding]::UTF8)
Write-PipeFrame $writer 'hello'
$stream.Position = 0
if ((Read-PipeFrame $stream 256) -cne 'hello') { throw 'Pipe round trip failed' }
$stream.Position = 0
try { [void](Read-PipeFrame $stream 2); throw 'Oversized pipe frame accepted' }
catch { if ($_.Exception.Message -ne 'Invalid pipe frame length') { throw } }
$writer.Dispose()

$stream = [IO.MemoryStream]::new()
$writer = [IO.BinaryWriter]::new($stream, [Text.Encoding]::UTF8)
$writer.Write([int]5)
$writer.Write([Text.Encoding]::UTF8.GetBytes('ab'))
$stream.Position = 0
try { [void](Read-PipeFrame $stream 256); throw 'Incomplete pipe frame accepted' }
catch { if ($_.Exception.Message -ne 'Incomplete pipe frame') { throw } }
$writer.Dispose()

$pipeName = 'EdamameNG-test-' + [Guid]::NewGuid().ToString('N')
$server = [IO.Pipes.NamedPipeServerStream]::new(
    $pipeName, [IO.Pipes.PipeDirection]::InOut, 1,
    [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous)
$client = [IO.Pipes.NamedPipeClientStream]::new(
    '.', $pipeName, [IO.Pipes.PipeDirection]::InOut,
    [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)
try {
    $connected = $server.WaitForConnectionAsync()
    $client.Connect(5000)
    if (-not $connected.Wait(5000)) { throw 'Pipe connection did not complete' }
    $expectedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($ExpectedNotSystem -and $expectedSid -eq 'S-1-5-18') { throw 'Test did not run as an ordinary user' }
    if ([EdamameWeakServiceNative]::ConnectedClientSid($server) -cne $expectedSid) {
        throw 'Pipe client token SID did not match independent impersonation'
    }
} finally { $client.Dispose(); $server.Dispose() }
Write-Host 'PASS weak-service parser, trusted service control, native adapter, and bounded pipe framing'
