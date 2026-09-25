# Exact-name disposable lab fixture only. Loaded when -EnableWeakServiceLab is set.
if (-not ('EdamameWeakServiceNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class EdamameWeakServiceNative {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct QueryConfig {
        public uint Type, StartType, ErrorControl;
        public IntPtr BinaryPath, LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies, StartName, DisplayName;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool QueryServiceConfigW(IntPtr service, IntPtr config, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level, IntPtr status, uint size, out uint needed);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool ChangeServiceConfigW(IntPtr service, uint type, uint start, uint error,
        string binaryPath, string loadGroup, IntPtr tagId, string dependencies, string startName,
        string password, string displayName);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    private static void Check(bool ok) {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    private static IntPtr OpenManager() {
        IntPtr handle = OpenSCManagerW(null, null, 1);
        Check(handle != IntPtr.Zero);
        return handle;
    }
    private static IntPtr OpenService(IntPtr manager, uint rights) {
        IntPtr handle = OpenServiceW(manager, "EdamameWeakSvc", rights);
        Check(handle != IntPtr.Zero);
        return handle;
    }
    // Opening with 0x17 checks effective QUERY_CONFIG, CHANGE_CONFIG,
    // QUERY_STATUS, and START rights on the current token.
    public static string[] Read() {
        IntPtr manager = OpenManager(), service = IntPtr.Zero, config = IntPtr.Zero, status = IntPtr.Zero;
        try {
            service = OpenService(manager, 0x17);
            uint needed;
            QueryServiceConfigW(service, IntPtr.Zero, 0, out needed);
            if (needed < Marshal.SizeOf(typeof(QueryConfig)) || needed > 65536)
                throw new InvalidOperationException("Invalid service configuration length");
            config = Marshal.AllocHGlobal((int)needed);
            Check(QueryServiceConfigW(service, config, needed, out needed));
            QueryConfig record = (QueryConfig)Marshal.PtrToStructure(config, typeof(QueryConfig));
            status = Marshal.AllocHGlobal(36);
            Check(QueryServiceStatusEx(service, 0, status, 36, out needed));
            return new string[] {
                Marshal.PtrToStringUni(record.BinaryPath),
                Marshal.PtrToStringUni(record.StartName),
                record.StartType.ToString(),
                Marshal.ReadInt32(status, 4).ToString()
            };
        } finally {
            if (status != IntPtr.Zero) Marshal.FreeHGlobal(status);
            if (config != IntPtr.Zero) Marshal.FreeHGlobal(config);
            if (service != IntPtr.Zero) CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
    }
    public static void SetBinaryPath(string path) {
        IntPtr manager = OpenManager(), service = IntPtr.Zero;
        try {
            service = OpenService(manager, 2);
            Check(ChangeServiceConfigW(service, uint.MaxValue, uint.MaxValue, uint.MaxValue,
                path, null, IntPtr.Zero, null, null, null, null));
        } finally {
            if (service != IntPtr.Zero) CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
    }
    public static string ConnectedClientSid(NamedPipeServerStream pipe) {
        string sid = null;
        pipe.RunAsClient(() => { sid = WindowsIdentity.GetCurrent().User.Value; });
        return sid;
    }
}
'@
}

function Get-WeakServiceLabState {
    try {
        if ((Test-SystemIdentity) -or (Test-AdminIdentity) -or (Test-AdminMembership)) { return $null }
        $marker = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Edamame-NG\Lab\WeakService' -ErrorAction Stop
        if ($marker.ServiceName -cne 'EdamameWeakSvc' -or
            $marker.State -cne 'ready' -or
            $marker.FixtureId -cnotmatch '^[0-9a-f]{32}$' -or
            $marker.TestSid -cnotmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$' -or
            $marker.TestSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
            $marker.OriginalSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]::IsNullOrWhiteSpace($marker.OriginalPath)) { return $null }
        $digest = [BitConverter]::ToString(
            [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($marker.OriginalPath))
        ).Replace('-', '').ToLowerInvariant()
        if ($digest -cne $marker.OriginalSha256) { return $null }
        $service = [EdamameWeakServiceNative]::Read()
        if ($service[0] -cne $marker.OriginalPath -or
            $service[1] -cne 'LocalSystem' -or
            $service[2] -ne '3' -or $service[3] -ne '1') { return $null }
        return [pscustomobject]@{
            FixtureId = $marker.FixtureId
            OriginalPath = $marker.OriginalPath
        }
    } catch { return $null }
}

function Get-TrustedServiceControl {
    $path = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
    $file = Get-Item -LiteralPath $path -ErrorAction Stop
    $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft (Windows|Corporation),') {
        throw 'Trusted service control executable unavailable'
    }
    return $path
}

function Restore-WeakServiceLabPath([string]$OriginalPath, [string]$ExpectedChangedPath) {
    $current = [EdamameWeakServiceNative]::Read()[0]
    if ($current -ceq $OriginalPath) { return $true }
    if ($current -cne $ExpectedChangedPath) { throw 'Foreign service path; refusing rollback' }
    [EdamameWeakServiceNative]::SetBinaryPath($OriginalPath)
    return ([EdamameWeakServiceNative]::Read()[0] -ceq $OriginalPath)
}

function Confirm-WeakServiceChange {
    if ($ApproveServiceChange) { return $true }
    if (-not [Environment]::UserInteractive) { return $false }
    return (Read-Host 'Change and start disposable EdamameWeakSvc as SYSTEM? Type CHANGE EdamameWeakSvc') -ceq 'CHANGE EdamameWeakSvc'
}

function Write-PipeFrame([IO.BinaryWriter]$Writer, [string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    if ($bytes.Length -gt 1048576) { throw 'Pipe response exceeds limit' }
    $Writer.Write([int]$bytes.Length)
    $Writer.Write($bytes)
    $Writer.Flush()
}

function Read-PipeBytes([IO.Stream]$Stream, [int]$Count, [int]$TimeoutMilliseconds) {
    $bytes = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.ReadAsync($bytes, $offset, $Count - $offset)
        if (-not $read.Wait($TimeoutMilliseconds)) { throw 'Pipe read timed out' }
        if ($read.Result -le 0) { throw 'Incomplete pipe frame' }
        $offset += $read.Result
    }
    return ,$bytes
}

function Read-PipeFrame([IO.Stream]$Stream, [int]$Limit, [int]$TimeoutMilliseconds = 300000) {
    $header = Read-PipeBytes $Stream 4 $TimeoutMilliseconds
    $size = [BitConverter]::ToInt32($header, 0)
    if ($size -lt 0 -or $size -gt $Limit) { throw 'Invalid pipe frame length' }
    $bytes = Read-PipeBytes $Stream $size $TimeoutMilliseconds
    return [Text.Encoding]::UTF8.GetString($bytes)
}

function Invoke-WeakServiceLabRecipe([string]$ExpectedFixtureId) {
    $state = Get-WeakServiceLabState
    if (-not $state -or ($ExpectedFixtureId -and $state.FixtureId -cne $ExpectedFixtureId)) { return $false }
    $trustedPowerShell = Get-TrustedPowerShell
    $trustedSc = Get-TrustedServiceControl
    $trustedCmd = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    $cmdFile = Get-Item -LiteralPath $trustedCmd -ErrorAction Stop
    $cmdSignature = Get-AuthenticodeSignature -LiteralPath $trustedCmd -ErrorAction Stop
    if ($cmdFile.PSIsContainer -or ($cmdFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $cmdSignature.Status -ne 'Valid' -or
        $cmdSignature.SignerCertificate.Subject -notmatch '^CN=Microsoft (Windows|Corporation),') { return $false }
    $pipeName = 'EdamameNG-' + [Guid]::NewGuid().ToString('N')
    $nonceBytes = [byte[]]::new(32)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($nonceBytes) } finally { $random.Dispose() }
    $nonce = [BitConverter]::ToString($nonceBytes).Replace('-', '')
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $pipeAcl = New-Object IO.Pipes.PipeSecurity
    $pipeAcl.SetAccessRuleProtection($true, $false)
    foreach ($allowed in @($sid, ([Security.Principal.SecurityIdentifier]::new('S-1-5-18')))) {
        $rule = [IO.Pipes.PipeAccessRule]::new($allowed, [IO.Pipes.PipeAccessRights]::ReadWrite, [Security.AccessControl.AccessControlType]::Allow)
        $pipeAcl.AddAccessRule($rule)
    }
    $pipe = [IO.Pipes.NamedPipeServerStream]::new(
        $pipeName, [IO.Pipes.PipeDirection]::InOut, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous,
        4096, 4096, $pipeAcl)
    $clientCode = @"
`$p = [IO.Pipes.NamedPipeClientStream]::new('.', '$pipeName', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)
try {
    `$p.Connect(15000)
    `$r = [IO.BinaryReader]::new(`$p, [Text.Encoding]::UTF8)
    `$w = [IO.BinaryWriter]::new(`$p, [Text.Encoding]::UTF8)
    function send([string]`$s) {
        `$b = [Text.Encoding]::UTF8.GetBytes(`$s)
        if (`$b.Length -gt 1048576) { `$b = [Text.Encoding]::UTF8.GetBytes('Output exceeds 1 MiB limit') }
        `$w.Write([int]`$b.Length); `$w.Write(`$b); `$w.Flush()
    }
    send ('1|$nonce|' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    while (`$true) {
        `$n = `$r.ReadInt32()
        if (`$n -lt 0 -or `$n -gt 4096) { break }
        `$b = `$r.ReadBytes(`$n)
        if (`$b.Length -ne `$n) { break }
        `$command = [Text.Encoding]::UTF8.GetString(`$b)
        if (`$command -ceq 'exit') { break }
        try { `$result = (& ([scriptblock]::Create(`$command)) 2>&1 | Out-String) }
        catch { `$result = (`$_ | Out-String) }
        send `$result
    }
} finally { `$p.Dispose() }
"@
    $clientEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($clientCode))
    # SCM may terminate a non-service PowerShell before it initializes. The
    # trusted cmd.exe service image launches the encoded SYSTEM child promptly.
    $changedPath = '"' + $trustedCmd + '" /d /c ' + $trustedPowerShell +
        ' -NoProfile -WindowStyle Hidden -EncodedCommand ' + $clientEncoded
    if ($changedPath.Length -gt 30000) {
        $pipe.Dispose()
        Write-Warning 'Service command exceeds Windows process limit'
        return $false
    }

    # A separate current-user process restores the exact fixture path if the
    # operator process is killed while the service is being started.
    $watchId = [Guid]::NewGuid().ToString('N')
    $watchReady = Join-Path $capture "watchdog-$watchId.ready"
    $watchStatus = Join-Path $capture "watchdog-$watchId.status"
    $watchDigest = [BitConverter]::ToString(
        [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($changedPath))
    ).Replace('-', '')
    $parentId = $PID
    $parentTicks = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks
    $quotedReady = $watchReady.Replace("'", "''")
    $quotedStatus = $watchStatus.Replace("'", "''")
    $quotedSc = $trustedSc.Replace("'", "''")
    $watchCode = @"
`$ErrorActionPreference = 'Stop'
`$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\EdamameWeakSvc'
`$marker = 'HKLM:\SOFTWARE\Edamame-NG\Lab\WeakService'
`$ready = '$quotedReady'
`$status = '$quotedStatus'
`$original = (Get-ItemProperty -LiteralPath `$marker).OriginalPath
`$fixture = Get-ItemProperty -LiteralPath `$marker
if (`$fixture.FixtureId -cne '$($state.FixtureId)' -or `$fixture.State -cne 'ready') { exit 1 }
`$null = (Get-ItemProperty -LiteralPath `$key).ImagePath
Set-Content -LiteralPath `$ready -Value ready -Encoding ASCII
`$seen = `$false
`$changedAt = `$null
while (`$true) {
    try {
        `$current = (Get-ItemProperty -LiteralPath `$key).ImagePath
        `$parent = Get-Process -Id $parentId -ErrorAction SilentlyContinue
        `$alive = `$parent -and `$parent.StartTime.ToUniversalTime().Ticks -eq $parentTicks
        if (`$current -ceq `$original) {
            if (`$seen -or -not `$alive) { Set-Content -LiteralPath `$status -Value original -Encoding ASCII; exit 0 }
        } else {
            `$bytes = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(`$current))
            `$digest = [BitConverter]::ToString(`$bytes).Replace('-', '')
            if (`$digest -cne '$watchDigest') { Set-Content -LiteralPath `$status -Value foreign-change -Encoding ASCII; exit 2 }
            `$seen = `$true
            if (-not `$changedAt) { `$changedAt = [DateTime]::UtcNow }
            if (-not `$alive -or ([DateTime]::UtcNow - `$changedAt).TotalSeconds -ge 45) {
                if ((Get-ItemProperty -LiteralPath `$key).ImagePath -cne `$current) {
                    Set-Content -LiteralPath `$status -Value foreign-change -Encoding ASCII; exit 2
                }
                & '$quotedSc' config EdamameWeakSvc binPath= `$original *> `$null
                if (`$LASTEXITCODE -eq 0 -and (Get-ItemProperty -LiteralPath `$key).ImagePath -ceq `$original) {
                    Set-Content -LiteralPath `$status -Value restored -Encoding ASCII; exit 0
                }
                Set-Content -LiteralPath `$status -Value restore-failed -Encoding ASCII; exit 1
            }
        }
    } catch { Set-Content -LiteralPath `$status -Value watcher-failed -Encoding ASCII; exit 1 }
    Start-Sleep -Milliseconds 500
}
"@
    $watchEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($watchCode))

    $changed = $false
    $restored = $false
    $starter = $null
    $watchdog = $null
    $writer = $null
    try {
        $watchdog = Start-Process -FilePath $trustedPowerShell -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $watchEncoded" -WindowStyle Hidden -PassThru
        for ($i = 0; $i -lt 30 -and -not (Test-Path -LiteralPath $watchReady); $i++) {
            if ($watchdog.HasExited) { break }
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $watchReady) -or $watchdog.HasExited) {
            throw 'Rollback watchdog did not remain ready'
        }
        $freshState = Get-WeakServiceLabState
        if (-not $freshState -or $freshState.FixtureId -cne $state.FixtureId -or
            $freshState.OriginalPath -cne $state.OriginalPath -or $watchdog.HasExited) {
            throw 'Weak-service fixture changed before mutation'
        }
        [EdamameWeakServiceNative]::SetBinaryPath($changedPath)
        $changed = $true
        $changedState = [EdamameWeakServiceNative]::Read()
        if ($changedState[0] -cne $changedPath -or $changedState[1] -cne 'LocalSystem' -or
            $changedState[2] -ne '3' -or $changedState[3] -ne '1') {
            throw 'Weak-service fixture changed before start'
        }
        $starter = Start-Process -FilePath $trustedSc -ArgumentList @('start', 'EdamameWeakSvc') -PassThru -WindowStyle Hidden
        $connected = $pipe.WaitForConnectionAsync()
        if (-not $connected.Wait(20000)) { throw 'SYSTEM pipe connection timed out' }
        $writer = [IO.BinaryWriter]::new($pipe, [Text.Encoding]::UTF8)
        $hello = Read-PipeFrame $pipe 256 10000
        if ($hello -cne "1|$nonce|S-1-5-18") { throw 'SYSTEM pipe identity proof failed' }
        if ([EdamameWeakServiceNative]::ConnectedClientSid($pipe) -cne 'S-1-5-18') {
            throw 'Named pipe client token is not SYSTEM'
        }
        $restored = Restore-WeakServiceLabPath $state.OriginalPath $changedPath
        if (-not $restored) { throw 'Service path restoration failed' }
        $script:weakServiceEvidence = [pscustomobject]@{
            service = 'EdamameWeakSvc'; fixture_id = $state.FixtureId
            proof_sid = 'S-1-5-18'; configuration_restored = $true
        }
        if ($NoShell) { Write-Host '[PROOF] Weak-service fixture yielded SYSTEM token; shell suppressed.' }
        else {
            Write-Host '[PROOF] SYSTEM token verified; service configuration restored.'
            while ($true) {
                $command = Read-Host 'SYSTEM>'
                if ($command -ceq 'exit') { break }
                if ([Text.Encoding]::UTF8.GetByteCount($command) -gt 4096) { Write-Warning 'Command exceeds 4 KiB limit'; continue }
                Write-PipeFrame $writer $command
                Write-Host (Read-PipeFrame $pipe 1048576)
            }
        }
        if ([EdamameWeakServiceNative]::Read()[0] -cne $state.OriginalPath) {
            $restored = $false
            throw 'Service configuration changed before shell exit'
        }
        return $true
    } catch {
        Write-Warning "Weak-service lab route failed: $($_.Exception.Message)"
        return $false
    } finally {
        if ($writer -and $pipe.IsConnected) { try { Write-PipeFrame $writer 'exit' } catch { } }
        if ($changed -and -not $restored) {
            try {
                $restored = Restore-WeakServiceLabPath $state.OriginalPath $changedPath
            } catch { Write-Warning "Weak-service rollback failed: $($_.Exception.Message)" }
        }
        if (-not $restored -and $changed) { Write-Warning 'Service path requires manual restoration.' }
        if ($writer) { $writer.Dispose() }
        $pipe.Dispose()
        if ($starter -and -not $starter.HasExited) { try { $starter.Kill() } catch { } }
        if ($starter) { $starter.Dispose() }
        if ($watchdog) {
            if ($restored -and -not $watchdog.HasExited) { try { $watchdog.Kill() } catch { } }
            $watchdog.Dispose()
        }
    }
}
