#requires -Version 3.0
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Create')][switch]$Create,
    [Parameter(Mandatory, ParameterSetName = 'Create')][string]$TestUser,
    [Parameter(Mandatory, ParameterSetName = 'Remove')][switch]$Remove,
    [Parameter(Mandatory, ParameterSetName = 'Remove')][string]$FixtureId,
    [Parameter(Mandatory, ParameterSetName = 'Recover')][switch]$RecoverIncomplete,
    [Parameter(ParameterSetName = 'Status')][switch]$Status
)
$ErrorActionPreference = 'Stop'
$serviceName = 'EdamameWeakSvc'
$markerPath = 'HKLM:\SOFTWARE\Edamame-NG\Lab\WeakService'
$sc = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
. (Join-Path $PSScriptRoot '..\..\..\lib\WeakServiceLab.ps1')

if (-not ('EdamameLocalGroupNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class EdamameLocalGroupNative {
    [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string server, string group, int level,
        out IntPtr buffer, int preferredMaximum, out int entries, out int total, ref IntPtr resume);
    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
    public static bool ContainsSid(string group, string targetSid) {
        IntPtr buffer = IntPtr.Zero, resume = IntPtr.Zero;
        int entries, total;
        try {
            int result = NetLocalGroupGetMembers(null, group, 0, out buffer, -1,
                out entries, out total, ref resume);
            if (result != 0) throw new InvalidOperationException("Local group SID query failed: " + result);
            for (int i = 0; i < entries; i++) {
                IntPtr sid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                if (new SecurityIdentifier(sid).Value == targetSid) return true;
            }
            return false;
        } finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
    }
}
'@
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Fixture changes require an elevated Administrator token.'
    }
}

function Invoke-Sc([string[]]$Arguments) {
    $result = & $sc @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failed: $result" }
    return $result
}

function Get-FixtureServiceStatus {
    $null = & $sc query $serviceName 2>&1
    if ($LASTEXITCODE -eq 0) { return 'present' }
    if ($LASTEXITCODE -eq 1060) { return 'absent' }
    if ($LASTEXITCODE -eq 1072) { return 'pending-delete' }
    throw "Could not determine fixture service state (sc.exe exit $LASTEXITCODE)."
}

function Set-ProtectedMarkerAcl {
    $acl = Get-Acl -Path $markerPath
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')) {
        $sid = New-Object Security.Principal.SecurityIdentifier -ArgumentList $sidText
        $rights = if ($sidText -eq 'S-1-5-32-545') {
            [Security.AccessControl.RegistryRights]::ReadKey
        } else { [Security.AccessControl.RegistryRights]::FullControl }
        $rule = New-Object Security.AccessControl.RegistryAccessRule -ArgumentList @(
            $sid, $rights, [Security.AccessControl.InheritanceFlags]::None,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.SetAccessRule($rule)
    }
    Set-Acl -Path $markerPath -AclObject $acl
}

function Remove-VerifiedFixture([string]$ExpectedId) {
    $marker = Get-ItemProperty -LiteralPath $markerPath -ErrorAction Stop
    if ($marker.ServiceName -cne $serviceName -or $marker.FixtureId -cne $ExpectedId -or
        $ExpectedId -cnotmatch '^[0-9a-f]{32}$' -or
        $marker.State -cnotin @('creating', 'ready') -or
        $marker.TestSid -cnotmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$' -or
        $marker.OriginalSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace($marker.OriginalPath)) { throw 'Fixture identity mismatch.' }
    $digest = [BitConverter]::ToString(
        [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($marker.OriginalPath))
    ).Replace('-', '').ToLowerInvariant()
    if ($digest -cne $marker.OriginalSha256) { throw 'Fixture marker path digest mismatch.' }
    $serviceStatus = Get-FixtureServiceStatus
    if ($serviceStatus -eq 'present') {
        $service = [EdamameWeakServiceNative]::Read()
        if ($service[0] -cne $marker.OriginalPath -or $service[1] -cne 'LocalSystem' -or
            $service[2] -ne '3' -or $service[3] -ne '1') {
            throw 'Fixture service drifted; restore it deliberately before removal.'
        }
        Invoke-Sc @('delete', $serviceName) | Out-Null
    }
    if ($serviceStatus -ne 'absent') {
        $deleted = $false
        for ($i = 0; $i -lt 40; $i++) {
            if ((Get-FixtureServiceStatus) -eq 'absent') { $deleted = $true; break }
            Start-Sleep -Milliseconds 250
        }
        if (-not $deleted) { throw 'Service deletion is not confirmed; fixture marker retained.' }
    }
    Remove-Item -LiteralPath $markerPath -Recurse -Force
}

if ($Create) {
    Assert-Administrator
    if (Test-Path -LiteralPath $markerPath) { throw 'Fixture marker already exists.' }
    if ((Get-FixtureServiceStatus) -ne 'absent') { throw 'Fixture service already exists.' }
    $testSid = if ($TestUser -match '^S-1-(?:[0-9]+-)+[0-9]+$') {
        New-Object Security.Principal.SecurityIdentifier -ArgumentList $TestUser
    } else {
        $accountName = if ($TestUser.StartsWith('.\')) {
            [Environment]::MachineName + '\' + $TestUser.Substring(2)
        } else { $TestUser }
        (New-Object Security.Principal.NTAccount -ArgumentList $accountName).Translate([Security.Principal.SecurityIdentifier])
    }
    $localUsers = @(Get-WmiObject -Class Win32_UserAccount -Filter "SID='$($testSid.Value)' AND LocalAccount=TRUE")
    if ($localUsers.Count -ne 1 -or $localUsers[0].Disabled) {
        throw 'Test SID must identify one enabled local user account.'
    }
    $administrators = (New-Object Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value
    $administratorsName = $administrators.Substring($administrators.LastIndexOf('\') + 1)
    if ([EdamameLocalGroupNative]::ContainsSid($administratorsName, $testSid.Value)) {
        throw 'Test user must not be a local Administrator.'
    }
    $original = Join-Path ([Environment]::SystemDirectory) 'svchost.exe'
    $file = Get-Item -LiteralPath $original -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid benign service path.' }
    $id = [Guid]::NewGuid().ToString('N')
    $hash = [BitConverter]::ToString(
        [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($original))
    ).Replace('-', '').ToLowerInvariant()
    New-Item -Path $markerPath -Force | Out-Null
    try {
        New-ItemProperty -Path $markerPath -Name ServiceName -Value $serviceName -PropertyType String | Out-Null
        New-ItemProperty -Path $markerPath -Name FixtureId -Value $id -PropertyType String | Out-Null
        New-ItemProperty -Path $markerPath -Name TestSid -Value $testSid.Value -PropertyType String | Out-Null
        New-ItemProperty -Path $markerPath -Name OriginalPath -Value $original -PropertyType String | Out-Null
        New-ItemProperty -Path $markerPath -Name OriginalSha256 -Value $hash -PropertyType String | Out-Null
        New-ItemProperty -Path $markerPath -Name State -Value creating -PropertyType String | Out-Null
        Set-ProtectedMarkerAcl
        Invoke-Sc @('create', $serviceName, 'binPath=', $original, 'start=', 'demand', 'obj=', 'LocalSystem') | Out-Null
        $raw = Invoke-Sc @('sdshow', $serviceName)
        $sddl = ([regex]::Match($raw, 'D:.*')).Value.Trim()
        if (-not $sddl) { throw 'Service DACL unavailable.' }
        $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
        $ace = New-Object Security.AccessControl.CommonAce -ArgumentList @(
            [Security.AccessControl.AceFlags]::None,
            [Security.AccessControl.AceQualifier]::AccessAllowed,
            0x17, $testSid, $false, $null)
        $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count, $ace)
        Invoke-Sc @('sdset', $serviceName, $descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All)) | Out-Null
        $service = [EdamameWeakServiceNative]::Read()
        if ($service[0] -cne $original -or $service[1] -cne 'LocalSystem' -or
            $service[2] -ne '3' -or $service[3] -ne '1') { throw 'Created fixture service failed verification.' }
        Set-ItemProperty -LiteralPath $markerPath -Name State -Value ready
        Write-Host "Created $serviceName for $($testSid.Value); fixture ID $id"
    } catch {
        $originalError = $_
        try { Remove-VerifiedFixture $id }
        catch {
            $cleanupError = $_
            if ((Get-FixtureServiceStatus) -ne 'absent') {
                throw "Fixture creation failed ($($originalError.Exception.Message)) and confirmed cleanup failed; marker retained: $($cleanupError.Exception.Message)"
            }
            try { Remove-Item -LiteralPath $markerPath -Recurse -Force }
            catch { throw "Fixture creation failed and empty marker cleanup failed: $($_.Exception.Message)" }
        }
        throw $originalError
    }
} elseif ($Remove) {
    Assert-Administrator
    Remove-VerifiedFixture $FixtureId
    Write-Host "Removed $serviceName and protected marker."
} elseif ($RecoverIncomplete) {
    Assert-Administrator
    $marker = Get-ItemProperty -LiteralPath $markerPath -ErrorAction Stop
    if ($marker.State -ceq 'ready' -or
        ($marker.ServiceName -and $marker.ServiceName -cne $serviceName) -or
        ($marker.FixtureId -and $marker.FixtureId -cnotmatch '^[0-9a-f]{32}$') -or
        (Get-FixtureServiceStatus) -ne 'absent') {
        throw 'Incomplete marker recovery requires an absent fixture service and a non-ready marker.'
    }
    Remove-Item -LiteralPath $markerPath -Recurse -Force
    Write-Host 'Removed incomplete marker after confirming fixture service is absent.'
} else {
    $marker = Get-ItemProperty -LiteralPath $markerPath -ErrorAction Stop
    $serviceStatus = Get-FixtureServiceStatus
    $service = if ($serviceStatus -eq 'present') { [EdamameWeakServiceNative]::Read() } else { @('', '', '', '') }
    [pscustomobject]@{
        service = $serviceName; fixture_id = $marker.FixtureId; fixture_state = $marker.State
        service_status = $serviceStatus; test_sid = $marker.TestSid
        account = $service[1]; start_type = $service[2]; state = $service[3]
        path_matches = ($service[0] -ceq $marker.OriginalPath)
        sddl = if ($serviceStatus -eq 'present') { ([regex]::Match((Invoke-Sc @('sdshow', $serviceName)), 'D:.*')).Value.Trim() } else { '' }
    }
}
