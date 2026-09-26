#requires -Version 3.0
<# Edamame-NG: Windows host enumeration and bounded local elevation. #>
[CmdletBinding(DefaultParameterSetName = 'Auto')]
param(
    [Parameter(ParameterSetName = 'Scan')][switch]$Scan,
    [Parameter(ParameterSetName = 'Resume')][switch]$Resume,
    [Parameter(ParameterSetName = 'Resume')][string]$RunId,
    [string]$OutputDir = (Join-Path $env:LOCALAPPDATA 'Edamame-NG\runs'),
    [string]$ToolDir,
    [string]$CatalogDir,
    [string]$Cve,
    [string]$CveDetails,
    [string]$Poc,
    [switch]$Offline,
    [switch]$FinishBgEnum,
    [ValidateRange(15, 3600)][int]$ToolTimeoutSeconds = 300,
    [switch]$ApproveSystemService,
    [switch]$EnableWeakServiceLab,
    [switch]$ApproveServiceChange,
    [switch]$NoShell
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($CatalogDir)) { $CatalogDir = Join-Path $PSScriptRoot 'catalog' }
$hostName = $env:COMPUTERNAME
$cacheBase = Join-Path $env:LOCALAPPDATA 'Edamame-NG\cache'
$runDir = $null
$weakServiceEvidence = $null

# Get-FileHash and Expand-Archive are absent from Windows PowerShell 3.0.
if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
    function Get-FileHash {
        param([string]$LiteralPath, [string]$Path, [string]$Algorithm = 'SHA256')
        if ($Algorithm -ne 'SHA256') { throw 'Only SHA256 is supported.' }
        $target = if ($LiteralPath) { $LiteralPath } else { $Path }
        $stream = [IO.File]::OpenRead($target)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') }
        finally { $sha.Dispose(); $stream.Dispose() }
        return [pscustomobject]@{ Hash = $digest }
    }
}

function Get-CatalogEntries([string]$Path) {
    $rows = @()
    foreach ($name in @('local-eop.tsv', 'curated-eop.tsv')) {
        $index = Join-Path $Path $name
        if (Test-Path -LiteralPath $index -PathType Leaf) {
            $rows += @(Import-Csv -LiteralPath $index -Delimiter "`t")
        }
    }
    return $rows
}

function Get-GeneralCveState([string]$CatalogPath, [string]$Id) {
    $year = $Id.Substring(4, 4)
    $index = Join-Path (Join-Path $CatalogPath 'cve-ids') "$year.tsv"
    if (-not (Test-Path -LiteralPath $index -PathType Leaf)) { return 'unindexed' }
    $match = Select-String -LiteralPath $index -Pattern "^$Id`t(published|rejected|reserved)$" |
        Select-Object -First 1
    if (-not $match) { return 'unindexed' }
    return (($match.Line -split "`t")[1] + '-general')
}

function Test-CveDetailsCatalog([string]$CatalogPath) {
    $index = Join-Path $CatalogPath 'local-eop-details.tsv'
    $manifest = Join-Path $CatalogPath 'local-eop-details-source.json'
    $base = Join-Path $CatalogPath 'cve-ids-source.json'
    if (-not (Test-Path -LiteralPath $index -PathType Leaf) -or
        -not (Test-Path -LiteralPath $manifest -PathType Leaf) -or
        -not (Test-Path -LiteralPath $base -PathType Leaf)) { return $false }
    try {
        foreach ($path in @($index, $manifest, $base)) {
            if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        }
        $source = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        $indexSource = Get-Content -LiteralPath $base -Raw | ConvertFrom-Json
        if ($source.details_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $source.baseline_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $source.baseline_sha256 -cne $indexSource.baseline_sha256) { return $false }
        return (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $source.details_sha256
    } catch { return $false }
}

function Get-CveDetailsLine([string]$CatalogPath, [string]$Id) {
    $index = Join-Path $CatalogPath 'local-eop-details.tsv'
    $reviewState = 'not-in-local-details'
    if (Test-Path -LiteralPath $index -PathType Leaf) {
        if (Test-CveDetailsCatalog $CatalogPath) {
            $member = @(Get-CatalogEntries $CatalogPath | Where-Object cve -eq $Id | Select-Object -First 1)
            if ($member.Count) {
                foreach ($line in [IO.File]::ReadAllLines($index, [Text.Encoding]::UTF8)) {
                    if ($line.StartsWith("$Id`t", [StringComparison]::Ordinal)) { return $line }
                }
            }
        } else { $reviewState = 'integrity-failed' }
    }
    $state = Get-GeneralCveState $CatalogPath $Id
    if ($state.EndsWith('-general', [StringComparison]::Ordinal)) {
        $state = $state.Substring(0, $state.Length - 8)
    }
    return "$Id`t$state`t`t`t`t$reviewState"
}

function Write-CveIndex([string]$CatalogPath, [string[]]$Suggested, [string]$Destination) {
    $catalog = @{}
    $indexPath = Join-Path $CatalogPath 'local-eop.tsv'
    if (Test-Path -LiteralPath $indexPath -PathType Leaf) {
        foreach ($item in @(Get-CatalogEntries $CatalogPath)) {
            if (-not $catalog.ContainsKey($item.cve)) { $catalog[$item.cve] = $item }
        }
    } else {
        Write-Warning 'Offline CVE catalog unavailable; retaining CVE.org links.'
    }
    $indexed = @('cve' + "`t" + 'status' + "`t" + 'platform' + "`t" + 'product' + "`t" + 'kev_date' + "`t" + 'reference')
    foreach ($id in $Suggested) {
        if ($catalog.ContainsKey($id)) {
            $item = $catalog[$id]
            $status = if ($item.platform -eq 'windows') { 'indexed-review-only' } else { 'platform-mismatch' }
            $indexed += "$id`t$status`t$($item.platform)`t$($item.product)`t$($item.kev_date)`t$($item.reference)"
        } else {
            $state = Get-GeneralCveState $CatalogPath $id
            $indexed += "$id`t$state`t`t`t`thttps://www.cve.org/CVERecord?id=$id"
        }
    }
    $indexed | Set-Content -LiteralPath $Destination -Encoding ASCII
}

if ($Poc) {
    if ($Cve -or $CveDetails) { throw 'Choose one CVE query mode.' }
    if ($Poc -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,}$') { throw 'Invalid CVE ID.' }
    $manifest = Join-Path $CatalogDir 'poc_refs.tsv'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Offline PoC manifest unavailable.' }
    "cve`tstatus`tsource`tpath`tsha256`treview_state"
    $pocItems = @(Import-Csv -LiteralPath $manifest -Delimiter "`t" | Where-Object cve -eq $Poc)
    if (-not $pocItems.Count) { "$Poc`tnot-indexed`t`t`t`t" }
    foreach ($item in $pocItems) {
        if ($item.offline_path -eq '-') {
            "$Poc`treference-only`t$($item.source_url)`t`t`t$($item.review_state)"
            continue
        }
        if ($item.offline_path -cnotmatch '^pocs/CVE-[0-9]{4}-[0-9]{4,}/[A-Za-z0-9._-]+$' -or
            -not $item.offline_path.StartsWith("pocs/$Poc/", [StringComparison]::Ordinal) -or
            $item.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid PoC manifest entry.' }
        $asset = Join-Path $CatalogDir $item.offline_path
        $file = Get-Item -LiteralPath $asset -ErrorAction Stop
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PoC asset must not be a link.' }
        if ((Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash -ne $item.sha256) {
            throw 'PoC asset digest mismatch.'
        }
        "$Poc`tverified-bundle`t$($item.source_url)`t$asset`t$($item.sha256)`t$($item.review_state)"
    }
    return
}

if ($CveDetails) {
    if ($Cve) { throw 'Choose one CVE query mode.' }
    if ($CveDetails -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,}$') { throw 'Invalid CVE ID.' }
    if ((Test-Path -LiteralPath (Join-Path $CatalogDir 'local-eop-details.tsv') -PathType Leaf) -and
        -not (Test-CveDetailsCatalog $CatalogDir)) { throw 'Offline CVE details failed integrity checks.' }
    "cve`tstate`tdescription`taffected_json`treferences_json`treview_state"
    Get-CveDetailsLine $CatalogDir $CveDetails
    return
}

if ($Cve) {
    if ($Cve -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,}$') { throw 'Invalid CVE ID.' }
    if (-not (Test-Path -LiteralPath (Join-Path $CatalogDir 'local-eop.tsv') -PathType Leaf)) {
        throw 'Offline catalog unavailable.'
    }
    'cve' + "`t" + 'status' + "`t" + 'platform' + "`t" + 'product' + "`t" + 'kev_date' + "`t" + 'reference'
    $item = @(Get-CatalogEntries $CatalogDir | Where-Object cve -eq $Cve | Select-Object -First 1)
    if ($item.Count) {
        "$Cve`tindexed-review-only`t$($item[0].platform)`t$($item[0].product)`t$($item[0].kev_date)`t$($item[0].reference)"
    } else {
        $state = Get-GeneralCveState $CatalogDir $Cve
        "$Cve`t$state`t`t`t`thttps://www.cve.org/CVERecord?id=$Cve"
    }
    return
}

@'
   _____    _                                   _   _  _____
  | ____|__| | __ _ _ __ ___   __ _ _ __ ___   | \ | |/ ____|
  |  _| / _` |/ _` | '_ ` _ \ / _` | '_ ` _ \  |  \| | |  __
  | |__| (_| | (_| | | | | | | (_| | | | | | | | |\  | |__| |
  |_____\__,_|\__,_|_| |_| |_|\__,_|_| |_| |_| |_| \_|\_____|
                     Edamame-NG  /  Windows
'@ | Write-Host
$script:ShowRawOutput = $VerbosePreference -eq 'Continue'

if ($EnableWeakServiceLab) { . (Join-Path $PSScriptRoot 'lib\WeakServiceLab.ps1') }

function Set-PrivateDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Output path must be a regular directory: $Path"
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    # Build a DACL-only descriptor. Reusing Get-Acl can carry a SACL whose
    # write requires SeSecurityPrivilege from ordinary users.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    foreach ($sid in @($identity, (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'))) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $sid, $full, $inherit, $none, $allow
        $acl.AddAccessRule($rule)
    }
    $item.SetAccessControl($acl)
    $allowed = @($identity.Value, 'S-1-5-18')
    $verified = Get-Acl -LiteralPath $Path
    foreach ($rule in $verified.Access) {
        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq $allow -and $sid -notin $allowed) {
            throw "Could not restrict directory ACL: $Path"
        }
    }
}

function Get-LatestSuccess {
    if (-not (Test-Path -LiteralPath $OutputDir)) { return $null }
    Get-ChildItem -LiteralPath $OutputDir -Directory |
        Sort-Object Name -Descending |
        ForEach-Object {
            $candidate = Join-Path $_.FullName 'success.json'
            if (Test-Path -LiteralPath $candidate) {
                try {
                    $saved = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json
                    if ($saved.host -eq $hostName -and $saved.recipe -in @('already-system', 'already-admin', 'uac-admin', 'admin-system', 'uac-admin-system', 'weak-service-lab')) {
                        return $candidate
                    }
                } catch { }
            }
        } | Select-Object -First 1
}

function Write-Attempt([string]$Recipe, [string]$Status) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "$stamp`t$Recipe`t$Status"
    Add-Content -LiteralPath (Join-Path $runDir 'attempts.tsv') -Value $line -Encoding UTF8
}

function Write-Finding([string]$Category, [string]$Detail) {
    Add-Content -LiteralPath (Join-Path $runDir 'findings.tsv') -Value "$Category`t$Detail" -Encoding UTF8
    Write-Host "[FOUND] ${Category}: $Detail"
}

function Write-CapturedTail([string[]]$Paths, [long[]]$Offsets, [Text.Decoder[]]$Decoders) {
    $bytes = New-Object byte[] 8192
    $chars = New-Object char[] ([Console]::OutputEncoding.GetMaxCharCount($bytes.Length))
    for ($i = 0; $i -lt $Paths.Count; $i++) {
        $reader = [IO.File]::Open($Paths[$i], [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $reader.Position = $Offsets[$i]
            while (($read = $reader.Read($bytes, 0, $bytes.Length)) -gt 0) {
                $count = $Decoders[$i].GetChars($bytes, 0, $read, $chars, 0, $false)
                [Console]::Out.Write($chars, 0, $count)
            }
            $Offsets[$i] = $reader.Position
        } finally { $reader.Dispose() }
    }
    [Console]::Out.Flush()
}

function Invoke-CapturedProcess([string]$FilePath, [string]$Arguments, [string]$OutputPath, [int]$TimeoutSeconds) {
    $stdout = "$OutputPath.stdout"
    $stderr = "$OutputPath.stderr"
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $FilePath
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $stdoutStream = $null
    $stderrStream = $null
    $started = $false
    try {
        $stdoutStream = New-Object IO.FileStream -ArgumentList @($stdout, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1)
        $stderrStream = New-Object IO.FileStream -ArgumentList @($stderr, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1)
        [void]$process.Start()
        $started = $true
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        Set-Content -LiteralPath "$OutputPath.pid" -Value $process.Id -Encoding ASCII
        if ($script:ShowRawOutput) {
            $paths = @($stdout, $stderr)
            $offsets = [long[]]@(0, 0)
            $encoding = [Console]::OutputEncoding
            $decoders = [Text.Decoder[]]@($encoding.GetDecoder(), $encoding.GetDecoder())
            $watch = [Diagnostics.Stopwatch]::StartNew()
            do {
                $remaining = $TimeoutSeconds * 1000 - [int]$watch.ElapsedMilliseconds
                $finished = $process.WaitForExit([Math]::Min(200, [Math]::Max(1, $remaining)))
                Write-CapturedTail $paths $offsets $decoders
            } while (-not $finished -and $watch.ElapsedMilliseconds -lt $TimeoutSeconds * 1000)
        } else {
            $finished = $process.WaitForExit($TimeoutSeconds * 1000)
        }
        if (-not $finished) {
            try { & taskkill.exe /PID $process.Id /T /F *> $null } catch { }
            if (-not $process.HasExited) { $process.Kill() }
            [void]$process.WaitForExit(5000)
            Write-Warning "$([IO.Path]::GetFileName($FilePath)) exceeded $TimeoutSeconds seconds; preserving partial output."
        }
        if (-not $stdoutTask.Wait(5000) -or -not $stderrTask.Wait(5000)) {
            throw 'Capture streams did not finish after the process exited.'
        }
        if ($script:ShowRawOutput) { Write-CapturedTail $paths $offsets $decoders }
        $exitCode = if ($finished) { $process.ExitCode } else { -1 }
    } finally {
        if ($started -and -not $process.HasExited) { try { $process.Kill() } catch { } }
        if ($stdoutStream) { $stdoutStream.Dispose() }
        if ($stderrStream) { $stderrStream.Dispose() }
        $process.Dispose()
        Remove-Item -LiteralPath "$OutputPath.pid" -Force -ErrorAction SilentlyContinue
    }
    $destination = [IO.File]::Create($OutputPath)
    try {
        foreach ($part in @($stdout, $stderr)) {
            if (Test-Path -LiteralPath $part) {
                $source = [IO.File]::OpenRead($part)
                try { $source.CopyTo($destination) } finally { $source.Dispose() }
            }
        }
    } finally { $destination.Dispose() }
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    if (-not $finished) { return 'timeout' }
    if ($exitCode -ne 0) { return 'partial' }
    return 'checked'
}

function Start-EnumJob([string]$Name, [string]$FilePath, [string]$Arguments, [string]$OutputPath) {
    $definition = ${function:Invoke-CapturedProcess}.ToString()
    $job = Start-Job -ScriptBlock {
        param($command, $arguments, $path, $limit, $source)
        . ([scriptblock]::Create("function Invoke-CapturedProcess { $source }"))
        $script:ShowRawOutput = $false
        Invoke-CapturedProcess $command $arguments $path $limit
    } -ArgumentList $FilePath, $Arguments, $OutputPath, $ToolTimeoutSeconds, $definition
    return @{ Name = $Name; Job = $job; Output = $OutputPath; Offset = [long]0; Stopped = $false }
}

function Stop-EnumJob($Entry) {
    $pidPath = "$($Entry.Output).pid"
    for ($i = 0; $i -lt 20 -and -not (Test-Path -LiteralPath $pidPath) -and
        $Entry.Job.State -in @('NotStarted', 'Running'); $i++) {
        Start-Sleep -Milliseconds 100
    }
    if (Test-Path -LiteralPath $pidPath) {
        $childPid = Get-Content -LiteralPath $pidPath -TotalCount 1
        if ($childPid -match '^[0-9]+$') {
            try {
                if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                    & taskkill.exe /PID $childPid /T /F *> $null
                } else { Stop-Process -Id ([int]$childPid) -Force }
            } catch { }
        }
    } else { Stop-Job -Job $Entry.Job -ErrorAction SilentlyContinue }
    $Entry.Stopped = $true
}

function Complete-EnumJob($Entry) {
    [void](Wait-Job -Job $Entry.Job -Timeout ($ToolTimeoutSeconds + 10))
    if ($Entry.Job.State -notin @('Completed', 'Failed', 'Stopped')) {
        Stop-EnumJob $Entry
        Stop-Job -Job $Entry.Job -ErrorAction SilentlyContinue
    }
    if ($Entry.Job.State -eq 'Failed' -and (Test-Path -LiteralPath "$($Entry.Output).pid")) {
        Stop-EnumJob $Entry
        $Entry.Stopped = $false
    }
    $result = @(Receive-Job -Job $Entry.Job -ErrorAction SilentlyContinue)
    Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $Entry.Output)) {
        $parts = @(@("$($Entry.Output).stdout", "$($Entry.Output).stderr") |
            Where-Object { Test-Path -LiteralPath $_ })
        if ($parts.Count -gt 0) {
            $destination = [IO.File]::Create($Entry.Output)
            try {
                foreach ($part in $parts) {
                    $source = [IO.File]::OpenRead($part)
                    try { $source.CopyTo($destination) } finally { $source.Dispose() }
                }
            } finally { $destination.Dispose() }
            Remove-Item -LiteralPath $parts -Force -ErrorAction SilentlyContinue
        }
    }
    if ($Entry.Stopped) { return 'partial-after-proof' }
    if ($result.Count -eq 0) { return 'partial' }
    return [string]$result[-1]
}

function Watch-EnumOutput($Entry, [hashtable]$SeenCves) {
    foreach ($part in @("$($Entry.Output).stdout", "$($Entry.Output).stderr")) {
        if (-not (Test-Path -LiteralPath $part)) { continue }
        $key = "$($Entry.Name):$part"
        $offset = if ($script:enumOffsets.ContainsKey($key)) { [long]$script:enumOffsets[$key] } else { [long]0 }
        try {
            $reader = [IO.File]::Open($part, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            try {
                if ($reader.Length -le $offset) { continue }
                $reader.Position = [Math]::Max(0, $offset - 64)
                $buffer = New-Object byte[] ([int]($reader.Length - $reader.Position))
                $read = 0
                while ($read -lt $buffer.Length) {
                    $partRead = $reader.Read($buffer, $read, $buffer.Length - $read)
                    if ($partRead -le 0) { break }
                    $read += $partRead
                }
                if ($read -lt $buffer.Length) {
                    $short = New-Object byte[] $read
                    [Array]::Copy($buffer, $short, $read)
                    $buffer = $short
                }
                $text = [Console]::OutputEncoding.GetString($buffer)
                if ($script:ShowRawOutput) {
                    $newStart = [int]([Math]::Min($buffer.Length, $offset - [Math]::Max(0, $offset - 64)))
                    [Console]::Out.Write([Console]::OutputEncoding.GetString($buffer, $newStart, $buffer.Length - $newStart))
                    [Console]::Out.Flush()
                }
                foreach ($match in [regex]::Matches($text, 'CVE-[0-9]{4}-[0-9]{4,}')) {
                    $SeenCves[$match.Value] = $true
                }
                $script:enumOffsets[$key] = $reader.Position
            } finally { $reader.Dispose() }
        } catch [IO.IOException] { }
    }
}

function Expand-VerifiedZip([string]$ArchivePath, [string]$Destination, [string]$ExpectedName) {
    Set-PrivateDirectory $Destination
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        [IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $Destination)
    } catch {
        # Shell.Application is available on Windows PowerShell 3 hosts with
        # .NET 4.0, where ZipFile/Expand-Archive may not exist.
        $shell = New-Object -ComObject Shell.Application
        $archive = $shell.NameSpace($ArchivePath)
        $target = $shell.NameSpace($Destination)
        if (-not $archive -or -not $target) { throw 'ZIP extraction unavailable on this host.' }
        $target.CopyHere($archive.Items(), 0x14)
        for ($i = 0; $i -lt 120; $i++) {
            $member = Get-ChildItem -LiteralPath $Destination -Filter $ExpectedName -Recurse -File -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($member -and $member.Length -gt 0) {
                try {
                    $complete = [IO.File]::Open($member.FullName, [IO.FileMode]::Open,
                        [IO.FileAccess]::Read, [IO.FileShare]::None)
                    $complete.Dispose()
                    return
                } catch [IO.IOException] { }
            }
            Start-Sleep -Milliseconds 250
        }
        throw "Expected ZIP member $ExpectedName was not extracted."
    }
}

function Get-ReleaseAsset([string]$Repo, [string]$Asset, [string]$Destination) {
    $cacheDir = Join-Path $cacheBase ($Repo -replace '/', '_')
    Set-PrivateDirectory $cacheDir
    $cached = Join-Path $cacheDir $Asset
    $expected = $null
    $source = $null
    $release = $null

    if ($ToolDir) {
        $local = Join-Path $ToolDir $Asset
        $digestFile = "$local.sha256"
        if ((Test-Path -LiteralPath $local) -and (Test-Path -LiteralPath $digestFile)) {
            $expected = ((Get-Content -LiteralPath $digestFile -TotalCount 1) -split '\s+')[0]
            if ($expected -match '^[a-fA-F0-9]{64}$' -and
                (Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash -eq $expected) {
                Copy-Item -LiteralPath $local -Destination $Destination
                Add-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value "$Asset`tlocal`t$local`t$expected"
                return $true
            }
        }
        Write-Warning "Local $Asset missing or checksum failed."
    } elseif (-not $Offline) {
        try {
            $latest = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest" -UseBasicParsing -MaximumRedirection 10 -TimeoutSec 20
            $finalUri = $latest.BaseResponse.ResponseUri.AbsoluteUri
            if ($finalUri -notlike "https://github.com/$Repo/releases/tag/*") { throw 'Unexpected release redirect' }
            $release = ($finalUri -split '/')[-1]
            if ($release -notmatch '^[A-Za-z0-9._+-]+$') { throw 'Unexpected release tag' }
            $expanded = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/expanded_assets/$release" -UseBasicParsing -TimeoutSec 25
            $escapedAsset = [regex]::Escape($Asset)
            $pattern = 'clipboard-copy id="clipboard-button-sha256:([a-f0-9]{64})" aria-label="Copy to clipboard digest for ' + $escapedAsset + '"'
            $match = [regex]::Match($expanded.Content, $pattern)
            if (-not $match.Success) { throw 'Release digest missing' }
            $expected = $match.Groups[1].Value
            $source = "https://github.com/$Repo/releases/download/$release/$Asset"
            Invoke-WebRequest -Uri $source -UseBasicParsing -OutFile $Destination -TimeoutSec 180
            $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected) { throw 'Release digest mismatch' }
            Copy-Item -LiteralPath $Destination -Destination $cached -Force
            Set-Content -LiteralPath "$cached.sha256" -Value $expected -Encoding ASCII
            Add-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value "$Asset`t$release`t$source`t$actual"
            return $true
        } catch {
            Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
            Write-Warning "Current $Asset unavailable: $($_.Exception.Message). Checking verified cache."
        }
    } else {
        Write-Host "[OFFLINE] Checking verified cache for $Asset."
    }

    if ((Test-Path -LiteralPath $cached) -and (Test-Path -LiteralPath "$cached.sha256")) {
        $expected = (Get-Content -LiteralPath "$cached.sha256" -TotalCount 1).Trim()
        if ($expected -match '^[a-fA-F0-9]{64}$' -and
            (Get-FileHash -LiteralPath $cached -Algorithm SHA256).Hash -eq $expected) {
            Copy-Item -LiteralPath $cached -Destination $Destination -Force
            Add-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value "$Asset`tcache`t$cached`t$expected"
            return $true
        }
    }
    Add-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value "$Asset`tmissing`t-`t-"
    return $false
}

function Test-PsExecAsset([string]$Path, [string]$ExpectedDigest) {
    try {
        # Reviewed Microsoft Sysinternals PsExec64.exe v2.43. New releases need
        # an explicit digest update and a fresh disposable-guest acceptance run.
        $pinnedDigest = 'edfae1a69522f87b12c6dac3225d930e4848832e3c551ee1e7d31736bf4525ef'
        if ($ExpectedDigest -ne $pinnedDigest) { return $false }
        $file = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($file.PSIsContainer) { return $false }
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        if ($file.VersionInfo.ProductName -ne 'Sysinternals PsExec') { return $false }
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') { return $false }
        if ($ExpectedDigest -notmatch '^[a-fA-F0-9]{64}$') { return $false }
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $ExpectedDigest
    } catch { return $false }
}

function Get-PsExecAsset {
    $destination = Join-Path $capture 'PsExec64.exe'
    $digestPath = "$destination.sha256"
    if ($Resume) {
        if ((Test-Path -LiteralPath $digestPath) -and
            (Test-PsExecAsset $destination (Get-Content -LiteralPath $digestPath -TotalCount 1))) {
            return $destination
        }
        Write-Warning 'Saved PsExec asset is missing or no longer verified.'
        return $null
    }

    $source = 'https://download.sysinternals.com/files/PSTools.zip'
    $release = $null
    try {
        if ($ToolDir) {
            $local = Join-Path $ToolDir 'PsExec64.exe'
            $localDigest = "$local.sha256"
            if (-not (Test-Path -LiteralPath $localDigest) -or
                -not (Test-PsExecAsset $local (Get-Content -LiteralPath $localDigest -TotalCount 1))) {
                throw 'local PsExec signature or SHA-256 verification failed'
            }
            Copy-Item -LiteralPath $local -Destination $destination
            $source = $local
            $release = 'local'
        } elseif (-not $Offline) {
            $archivePath = Join-Path $capture 'PSTools.zip'
            Invoke-WebRequest -Uri $source -UseBasicParsing -OutFile $archivePath -TimeoutSec 180
            $unpack = Join-Path $capture 'psexec-unpack'
            Expand-VerifiedZip $archivePath $unpack 'PsExec64.exe'
            $extracted = Get-ChildItem -LiteralPath $unpack -Filter 'PsExec64.exe' -Recurse -File |
                Select-Object -First 1
            if (-not $extracted) { throw 'PsExec64.exe absent from official archive' }
            Copy-Item -LiteralPath $extracted.FullName -Destination $destination
            Remove-Item -LiteralPath $archivePath -Force
            $release = (Get-Item -LiteralPath $destination).VersionInfo.FileVersion
        } else {
            throw 'offline mode uses only verified local or cached PsExec'
        }
        $digest = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not (Test-PsExecAsset $destination $digest)) { throw 'PsExec Authenticode verification failed' }
        Set-Content -LiteralPath $digestPath -Value $digest -Encoding ASCII
        $cacheDir = Join-Path $cacheBase 'microsoft_sysinternals'
        Set-PrivateDirectory $cacheDir
        Copy-Item -LiteralPath $destination -Destination (Join-Path $cacheDir 'PsExec64.exe') -Force
        Set-Content -LiteralPath (Join-Path $cacheDir 'PsExec64.exe.sha256') -Value $digest -Encoding ASCII
        Add-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value "PsExec64.exe`t$release`t$source`t$digest"
        return $destination
    } catch {
        Remove-Item -LiteralPath $destination, $digestPath -Force -ErrorAction SilentlyContinue
        Write-Warning "Current PsExec unavailable: $($_.Exception.Message). Checking verified cache."
    }

    $cached = Join-Path $cacheBase 'microsoft_sysinternals\PsExec64.exe'
    $cachedDigest = "$cached.sha256"
    if ((Test-Path -LiteralPath $cachedDigest) -and
        (Test-PsExecAsset $cached (Get-Content -LiteralPath $cachedDigest -TotalCount 1))) {
        Copy-Item -LiteralPath $cached -Destination $destination
        $digest = (Get-Content -LiteralPath $cachedDigest -TotalCount 1).Trim()
        Set-Content -LiteralPath $digestPath -Value $digest -Encoding ASCII
        Add-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value "PsExec64.exe`tcache`t$cached`t$digest"
        return $destination
    }
    Add-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value "PsExec64.exe`tmissing`t-`t-"
    return $null
}

function Test-SystemIdentity {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18'
}

function Test-AdminIdentity {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-AdminMembership {
    $whoami = Join-Path ([Environment]::SystemDirectory) 'whoami.exe'
    $groups = (& $whoami /groups 2>&1 | Out-String)
    return $groups -match 'S-1-5-32-544'
}

function Test-TrustedSystemBinary([string]$Path) {
    $systemDir = [Environment]::SystemDirectory
    $allowed = @(
        (Join-Path $systemDir 'sc.exe'),
        (Join-Path $systemDir 'cmd.exe'),
        (Join-Path $systemDir 'WindowsPowerShell\v1.0\powershell.exe')
    )
    try {
        $file = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $file.FullName -notin $allowed) { return $false }
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction Stop
        if ($signature.Status -eq 'Valid' -and $signature.SignerCertificate -and
            $signature.SignerCertificate.Subject -match '^CN=Microsoft (Windows|Corporation),') { return $true }
        # Windows PowerShell 3 on Server 2012 can report catalog-signed OS
        # files as NotSigned. Accept only the exact WRP-protected system files.
        $version = [Environment]::OSVersion.Version
        if ($signature.Status -ne 'NotSigned' -or $version.Major -ne 6 -or $version.Minor -ne 2) { return $false }
        if (-not ('EdamameSystemFileTrust' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EdamameSystemFileTrust {
    [DllImport("sfc.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SfcIsFileProtected(IntPtr rpcHandle, string fileName);
}
'@ -ErrorAction Stop
        }
        if (-not [EdamameSystemFileTrust]::SfcIsFileProtected([IntPtr]::Zero, $file.FullName)) { return $false }
        $installer = New-Object Security.Principal.NTAccount -ArgumentList @('NT SERVICE', 'TrustedInstaller')
        $installerSid = $installer.Translate([Security.Principal.SecurityIdentifier]).Value
        foreach ($item in @($file.FullName, (Split-Path -Parent $file.FullName))) {
            if ((Get-Acl -LiteralPath $item).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $installerSid) {
                return $false
            }
        }
        $writable = $null
        try {
            $writable = [IO.File]::Open($file.FullName, [IO.FileMode]::Open,
                [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
            return $false
        } catch [UnauthorizedAccessException] {
            return $true
        } finally { if ($writable) { $writable.Dispose() } }
    } catch { return $false }
}

function Get-TrustedPowerShell {
    $path = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-TrustedSystemBinary $path)) { throw 'System PowerShell verification failed.' }
    return $path
}

function New-ProofMarker([string]$Name) {
    $marker = Join-Path $capture ("$Name-$([Guid]::NewGuid().ToString('N')).txt")
    if (Test-Path -LiteralPath $marker) { throw 'Proof marker collision.' }
    return $marker
}

function Confirm-SystemService {
    if ($ApproveSystemService) { return $true }
    if (-not [Environment]::UserInteractive) { return $false }
    $choice = Read-Host 'PsExec will accept the Sysinternals EULA and create a temporary local SYSTEM service. Approve? [y/N]'
    return $choice -match '^[Yy]$'
}

function Invoke-SystemViaPsExec {
    if (-not (Test-AdminIdentity)) { return $false }
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($sessionId -lt 1) { Write-Warning 'No interactive desktop session for SYSTEM shell.'; return $false }
    $digest = (Get-Content -LiteralPath "$psExecPath.sha256" -TotalCount 1).Trim()
    if (-not (Test-PsExecAsset $psExecPath $digest)) { Write-Warning 'PsExec verification failed before launch.'; return $false }
    $trustedPowerShell = Get-TrustedPowerShell
    $marker = New-ProofMarker 'system-proof'
    $quotedMarker = $marker.Replace("'", "''")
    $systemChild = @"
`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (`$identity.User.Value -ne 'S-1-5-18') { exit 1 }
Set-Content -LiteralPath '$quotedMarker' -Value `$identity.User.Value -Encoding ASCII
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($systemChild))
    $shellArgs = @('-NoProfile')
    if (-not $NoShell) { $shellArgs += '-NoExit' }
    $shellArgs += @('-EncodedCommand', $encoded)
    try {
        $priorErrorAction = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $psExecPath -accepteula -nobanner -s -i $sessionId -d $trustedPowerShell @shellArgs *> $null
        } finally { $ErrorActionPreference = $priorErrorAction }
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            if ((Test-Path -LiteralPath $marker) -and (Get-Content -LiteralPath $marker -TotalCount 1) -eq 'S-1-5-18') {
                if ($NoShell) { Write-Host '[PROOF] SYSTEM token verified; shell suppressed.' }
                return $true
            }
            Start-Sleep -Milliseconds 500
        }
    } catch { Write-Warning "SYSTEM shell launch failed: $($_.Exception.Message)" }
    return $false
}

function Invoke-Recipe([string]$Recipe) {
    switch ($Recipe) {
        'already-system' {
            if (-not (Test-SystemIdentity)) { return $false }
            if ($NoShell) { Write-Host '[PROOF] SYSTEM token verified; shell suppressed.' }
            else { & (Get-TrustedPowerShell) -NoLogo -NoExit }
            return $true
        }
        'already-admin' {
            if (-not (Test-AdminIdentity)) { return $false }
            if ($NoShell) { Write-Host '[PROOF] Administrator token verified; shell suppressed.' }
            else { & (Get-TrustedPowerShell) -NoLogo -NoExit }
            return $true
        }
        'admin-system' { return (Invoke-SystemViaPsExec) }
        'weak-service-lab' {
            if (-not $EnableWeakServiceLab) { return $false }
            return (Invoke-WeakServiceLabRecipe $expectedWeakFixtureId)
        }
        'uac-admin-system' {
            if (-not (Test-AdminMembership)) { return $false }
            $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
            if ($sessionId -lt 1) { Write-Warning 'No interactive desktop session for SYSTEM shell.'; return $false }
            $digest = (Get-Content -LiteralPath "$psExecPath.sha256" -TotalCount 1).Trim()
            if (-not (Test-PsExecAsset $psExecPath $digest)) { return $false }
            $trustedPowerShell = Get-TrustedPowerShell
            $powerShellDigest = (Get-FileHash -LiteralPath $trustedPowerShell -Algorithm SHA256).Hash
            $marker = New-ProofMarker 'system-proof'
            $quotedMarker = $marker.Replace("'", "''")
            $quotedPsExec = $psExecPath.Replace("'", "''")
            $quotedPowerShell = $trustedPowerShell.Replace("'", "''")
            $openChildShell = if ($NoShell) { '$false' } else { '$true' }
            $systemChild = @"
`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (`$identity.User.Value -ne 'S-1-5-18') { exit 1 }
Set-Content -LiteralPath '$quotedMarker' -Value `$identity.User.Value -Encoding ASCII
"@
            $encodedSystem = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($systemChild))
            $child = @"
`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
`$principal = New-Object Security.Principal.WindowsPrincipal(`$identity)
if (-not `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }
function Get-LocalSha256([string]`$path) {
    `$stream = [IO.File]::OpenRead(`$path)
    `$sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString(`$sha.ComputeHash(`$stream)).Replace('-', '') }
    finally { `$sha.Dispose(); `$stream.Dispose() }
}
if ((Get-LocalSha256 '$quotedPsExec') -ne '$digest') { exit 1 }
`$signature = Get-AuthenticodeSignature -LiteralPath '$quotedPsExec'
if (`$signature.Status -ne 'Valid' -or `$signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') { exit 1 }
if ((Get-LocalSha256 '$quotedPowerShell') -ne '$powerShellDigest') { exit 1 }
`$shellArgs = @('-NoProfile')
if ($openChildShell) { `$shellArgs += '-NoExit' }
`$shellArgs += @('-EncodedCommand', '$encodedSystem')
& '$quotedPsExec' -accepteula -nobanner -s -i $sessionId -d '$quotedPowerShell' @shellArgs *> `$null
"@
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
            try {
                [void](Start-Process -FilePath $trustedPowerShell -ArgumentList "-NoProfile -EncodedCommand $encoded" -Verb RunAs -PassThru)
                for ($attempt = 0; $attempt -lt 30; $attempt++) {
                    if ((Test-Path -LiteralPath $marker) -and (Get-Content -LiteralPath $marker -TotalCount 1) -eq 'S-1-5-18') {
                        if ($NoShell) { Write-Host '[PROOF] UAC to SYSTEM token verified; shell suppressed.' }
                        return $true
                    }
                    Start-Sleep -Milliseconds 500
                }
            } catch { Write-Warning "UAC to SYSTEM elevation failed: $($_.Exception.Message)" }
            return $false
        }
        'uac-admin' {
            if (-not (Test-AdminMembership)) { return $false }
            $trustedPowerShell = Get-TrustedPowerShell
            $marker = New-ProofMarker 'uac-proof'
            $quotedMarker = $marker.Replace("'", "''")
            $child = @"
`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
`$principal = New-Object Security.Principal.WindowsPrincipal(`$identity)
if (-not `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }
Set-Content -LiteralPath '$quotedMarker' -Value `$identity.User.Value -Encoding ASCII
"@
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
            $shellArgs = if ($NoShell) { "-NoProfile -EncodedCommand $encoded" }
                else { "-NoProfile -NoExit -EncodedCommand $encoded" }
            try {
                $process = Start-Process -FilePath $trustedPowerShell -ArgumentList $shellArgs -Verb RunAs -PassThru
                for ($attempt = 0; $attempt -lt 30; $attempt++) {
                    if (Test-Path -LiteralPath $marker) {
                        if ($NoShell) { Write-Host '[PROOF] UAC Administrator token verified; shell suppressed.' }
                        return $true
                    }
                    if ($process.HasExited) { break }
                    Start-Sleep -Milliseconds 500
                }
                return $false
            } catch {
                Write-Warning "UAC elevation failed: $($_.Exception.Message)"
                return $false
            }
        }
        default { return $false }
    }
}

$prior = Get-LatestSuccess
if (-not $Scan -and -not $Resume) {
    if ($prior) {
        if ([Environment]::UserInteractive) {
            $choice = Read-Host 'Prior success found. [R]esume (default) or [S]can?'
            $Resume = $choice -notmatch '^[Ss]'
            $Scan = -not $Resume
        } else {
            $Resume = $true
        }
    } else { $Scan = $true }
}
if ($script:ShowRawOutput -and $Scan) {
    Write-Warning 'Verbose displays raw enumerator output, including possible credentials, on this console.'
}

if ($Resume) {
    if ($RunId) {
        if ($RunId -in @('.', '..') -or $RunId -notmatch '^[A-Za-z0-9._-]+$') { throw 'Invalid run ID' }
        $prior = Join-Path (Join-Path $OutputDir $RunId) 'success.json'
    }
    if (-not $prior -or -not (Test-Path -LiteralPath $prior)) { throw 'No successful run to resume' }
    $runDir = Split-Path -Parent $prior
    Set-PrivateDirectory $OutputDir
    Set-PrivateDirectory $runDir
    $capture = Join-Path $runDir '.capture'
    Set-PrivateDirectory $capture
    $saved = Get-Content -LiteralPath $prior -Raw | ConvertFrom-Json
    if ($saved.host -ne $hostName -or $saved.recipe -notin @('already-system', 'already-admin', 'uac-admin', 'admin-system', 'uac-admin-system', 'weak-service-lab')) {
        throw 'Saved run has an invalid host or recipe'
    }
    if ($saved.recipe -eq 'weak-service-lab') {
        if (-not $EnableWeakServiceLab) {
            Write-Attempt $saved.recipe 'resume-optin-missing'
            throw 'Weak-service lab recipe requires fresh opt-in'
        }
        $expectedWeakFixtureId = [string]$saved.evidence.fixture_id
        if ($expectedWeakFixtureId -cnotmatch '^[0-9a-f]{32}$' -or
            $saved.evidence.service -cne 'EdamameWeakSvc' -or
            $saved.evidence.proof_sid -cne 'S-1-5-18' -or
            $saved.evidence.configuration_restored -cne $true) {
            throw 'Saved weak-service evidence is invalid'
        }
        $currentWeakState = Get-WeakServiceLabState
        if (-not $currentWeakState -or $currentWeakState.FixtureId -cne $expectedWeakFixtureId) {
            Write-Attempt $saved.recipe 'resume-prerequisite-failed'
            throw 'Saved weak-service fixture no longer matches'
        }
        if (-not (Confirm-WeakServiceChange)) {
            Write-Attempt $saved.recipe 'resume-service-change-approval-declined'
            throw 'Weak-service recipe requires fresh approval'
        }
        Write-Attempt $saved.recipe 'resume-service-change-approved'
    }
    if ($saved.recipe -in @('admin-system', 'uac-admin-system')) {
        if (-not (Confirm-SystemService)) {
            Write-Attempt $saved.recipe 'resume-service-approval-declined'
            throw 'SYSTEM service action requires fresh approval'
        }
        Write-Attempt $saved.recipe 'resume-service-approved'
        $psExecPath = Get-PsExecAsset
        if (-not $psExecPath) {
            Write-Attempt $saved.recipe 'resume-psexec-unavailable'
            throw 'Saved PsExec asset is unavailable; use -Scan'
        }
    }
    Write-Host "[RESUME] $($saved.recipe) on $hostName; checking prerequisites again."
    if (Invoke-Recipe $saved.recipe) {
        Write-Attempt $saved.recipe 'resumed-proof'
        exit 0
    }
    if ($saved.recipe -in @('uac-admin', 'uac-admin-system') -and (Test-AdminMembership)) {
        Write-Attempt $saved.recipe 'resume-elevation-not-completed'
        throw 'Elevation did not complete; the saved recipe can be retried'
    }
    if ($saved.recipe -eq 'admin-system' -and (Test-AdminIdentity)) {
        Write-Attempt $saved.recipe 'resume-system-not-completed'
        throw 'SYSTEM elevation did not complete; the saved recipe can be retried'
    }
    Write-Attempt $saved.recipe 'resume-prerequisite-failed'
    throw 'Saved recipe no longer works; use -Scan'
}

Set-PrivateDirectory $OutputDir
Set-PrivateDirectory $cacheBase
$runId = '{0}-{1}-{2}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $hostName, $PID
$runDir = Join-Path $OutputDir $runId
Set-PrivateDirectory $runDir
$capture = Join-Path $runDir '.capture'
Set-PrivateDirectory $capture
foreach ($name in @('tools.tsv', 'findings.tsv', 'attempts.tsv', 'coverage.tsv')) {
    Set-Content -LiteralPath (Join-Path $runDir $name) -Value '' -Encoding UTF8
}
Write-Host "[RUN] $runDir"
if ($ToolDir) { Write-Host '[ENUM] Loading verified local assets.' }
elseif ($Offline) { Write-Host '[OFFLINE] Using verified cached assets; release downloads are disabled.' }
else { Write-Host '[ENUM] Fetching official current release assets.' }

$winpeas = Join-Path $capture 'winPEASany.exe'
$winpeasBat = Join-Path $capture 'winPEAS.bat'
$privescCheck = Join-Path $capture 'PrivescCheck.ps1'
$haveWinpeas = Get-ReleaseAsset 'peass-ng/PEASS-ng' 'winPEASany.exe' $winpeas
$haveBat = Get-ReleaseAsset 'peass-ng/PEASS-ng' 'winPEAS.bat' $winpeasBat
$havePrivescCheck = Get-ReleaseAsset 'itm4n/PrivescCheck' 'PrivescCheck.ps1' $privescCheck
$enumJobs = @()
$script:enumOffsets = @{}
$liveCves = @{}
$sharpJob = $null
$winpeasJob = $null
$privescJob = $null

$domainJoined = $false
$sharpCollectedZip = $null
try {
    $domainJoined = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain
} catch {
    # A standard user can query its computer domain even when WMI denies access.
    if ($Offline) { Write-Warning 'Domain join status unavailable locally in offline mode.' }
    else {
        try {
            $domainJoined = [bool][System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        } catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] {
            $domainJoined = $false
        } catch {
            Write-Warning 'Domain join status unavailable.'
        }
    }
}
if ($domainJoined -and -not $Offline) {
    $sharpRecorded = $false
    $latestSharp = $null
    if ($ToolDir) {
        $sharpLocal = Get-ChildItem -LiteralPath $ToolDir -Filter 'SharpHound_v*_windows_x86.zip' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($sharpLocal -and $sharpLocal.Name -match '^SharpHound_(v[0-9.]+)_windows_x86\.zip$') {
            $latestSharp = $Matches[1]
        }
    } elseif (-not $Offline) {
        try {
            $response = Invoke-WebRequest -Uri 'https://github.com/SpecterOps/SharpHound/releases/latest' -UseBasicParsing -TimeoutSec 20
            $latestSharp = ($response.BaseResponse.ResponseUri.AbsoluteUri -split '/')[-1]
        } catch { Write-Warning 'Could not resolve SharpHound release.' }
    } else {
        $sharpCache = Join-Path $cacheBase 'SpecterOps_SharpHound'
        $cachedSharp = Get-ChildItem -LiteralPath $sharpCache -Filter 'SharpHound_v*_windows_x86.zip' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($cachedSharp -and $cachedSharp.Name -match '^SharpHound_(v[0-9.]+)_windows_x86\.zip$') {
            $latestSharp = $Matches[1]
        }
    }
    if (-not $latestSharp -and $ToolDir) {
        $sharpCache = Join-Path $cacheBase 'SpecterOps_SharpHound'
        $cachedSharp = Get-ChildItem -LiteralPath $sharpCache -Filter 'SharpHound_v*_windows_x86.zip' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($cachedSharp -and $cachedSharp.Name -match '^SharpHound_(v[0-9.]+)_windows_x86\.zip$') {
            $latestSharp = $Matches[1]
        }
    }
    if ($latestSharp -and $latestSharp -match '^v[0-9.]+$') {
        $sharpAsset = "SharpHound_${latestSharp}_windows_x86.zip"
        $sharpZip = Join-Path $capture $sharpAsset
        if (Get-ReleaseAsset 'SpecterOps/SharpHound' $sharpAsset $sharpZip) {
            try {
                $sharpBin = Join-Path $capture 'sharphound-bin'
                Expand-VerifiedZip $sharpZip $sharpBin 'SharpHound.exe'
                $sharpExe = Get-ChildItem -LiteralPath $sharpBin -Filter 'SharpHound.exe' -Recurse -File | Select-Object -First 1
                if (-not $sharpExe) { throw 'SharpHound.exe absent from release ZIP' }
                $sharpOut = Join-Path $capture 'sharphound-data'
                New-Item -ItemType Directory -Path $sharpOut | Out-Null
                Write-Host '[ENUM] SharpHound Default collection.'
                $sharpJob = Start-EnumJob 'sharphound' $sharpExe.FullName `
                    "--CollectionMethods Default --OutputDirectory `"$sharpOut`" --ZipFileName sharphound.zip" `
                    (Join-Path $capture 'sharphound-output.txt')
                $enumJobs += $sharpJob
                $sharpRecorded = $true
            } catch {
                Write-Warning "SharpHound failed: $($_.Exception.Message)"
                Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`tfailed"
                $sharpRecorded = $true
            }
        }
    }
    if (-not $sharpRecorded) {
        Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`tunavailable"
    }
} elseif ($domainJoined) {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`tskipped-offline"
} else {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`tnot-domain-joined"
}

$winpeasOk = $false
if ($haveWinpeas) {
    Write-Host '[ENUM] WinPEAS.'
    try {
        $winpeasJob = Start-EnumJob 'winpeas' $winpeas '' (Join-Path $capture 'winpeas-output.txt')
        $enumJobs += $winpeasJob
    } catch {
        Write-Warning "WinPEAS binary failed: $($_.Exception.Message)"
    }
}

$privescComplete = $false
if ($havePrivescCheck) {
    Write-Host '[ENUM] PrivescCheck.'
    try {
        $quotedCheck = $privescCheck.Replace("'", "''")
        $checkCode = ". '$quotedCheck'; Invoke-PrivescCheck -Extended -Audit"
        $encodedCheck = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($checkCode))
        $privescJob = Start-EnumJob 'privesccheck' 'powershell.exe' "/NoProfile /ExecutionPolicy Bypass /EncodedCommand $encodedCheck" `
            (Join-Path $capture 'privesccheck-output.txt')
        $enumJobs += $privescJob
    } catch {
        Write-Warning "PrivescCheck failed: $($_.Exception.Message)"
        Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "privesccheck`tpartial"
    }
}

# Native prerequisites are independent of enumerator prose, so test them as
# soon as the background collectors start. Enumerator CVEs remain review-only.
$fastRecipe = $null
$fastAttemptedRecipe = $null
$fastSuccessRecipe = $null
$weakLabState = $null
if (Test-SystemIdentity) { $fastRecipe = 'already-system' }
elseif (Test-AdminIdentity) { $fastRecipe = 'already-admin' }
elseif (Test-AdminMembership) { $fastRecipe = 'uac-admin' }
elseif ($EnableWeakServiceLab -and (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Edamame-NG\Lab\WeakService')) {
    $weakLabState = Get-WeakServiceLabState
    if ($weakLabState) { $fastRecipe = 'weak-service-lab' }
}
if ($fastRecipe) {
    Write-Finding 'local-elevation' "$fastRecipe independently verified while enumeration runs"
    if ($fastRecipe -eq 'weak-service-lab') {
        if (-not (Confirm-WeakServiceChange)) {
            Write-Attempt $fastRecipe 'service-change-approval-declined'
            $fastAttemptedRecipe = $fastRecipe
            $fastRecipe = $null
        } else { Write-Attempt $fastRecipe 'service-change-approved' }
    }
    if ($fastRecipe -in @('already-admin', 'uac-admin')) {
        if (Confirm-SystemService) {
            Write-Attempt $fastRecipe 'service-approved'
            $psExecPath = Get-PsExecAsset
            if ($psExecPath) {
                $fastRecipe = if ($fastRecipe -eq 'uac-admin') { 'uac-admin-system' } else { 'admin-system' }
            }
        } else { Write-Attempt $fastRecipe 'service-approval-declined' }
    }
    if ($fastRecipe) {
        $fastAttemptedRecipe = $fastRecipe
        if (-not $FinishBgEnum -and -not $NoShell -and $fastRecipe -in @('already-system', 'already-admin')) {
            foreach ($entry in $enumJobs) { Stop-EnumJob $entry }
        }
        if (Invoke-Recipe $fastRecipe) {
            $fastSuccessRecipe = $fastRecipe
            Write-Attempt $fastRecipe 'proof-success'
            if (-not $FinishBgEnum -and -not $NoShell) {
                foreach ($entry in $enumJobs) { Stop-EnumJob $entry }
            }
        } else { Write-Attempt $fastRecipe 'proof-failed' }
    }
}

$lastLiveCount = 0
while (@($enumJobs | Where-Object { $_.Job.State -in @('NotStarted', 'Running') }).Count -gt 0) {
    foreach ($entry in $enumJobs) { Watch-EnumOutput $entry $liveCves }
    if ($liveCves.Count -gt $lastLiveCount) {
        Write-Finding 'cve-candidates' "$($liveCves.Count) suggested so far; review exact build and patch status"
        $lastLiveCount = $liveCves.Count
    }
    Start-Sleep -Milliseconds 250
}
foreach ($entry in $enumJobs) { Watch-EnumOutput $entry $liveCves }

$sharpStatus = if ($sharpJob) { Complete-EnumJob $sharpJob } else { 'unavailable' }
if ($sharpJob) {
    $sharpCollectedZip = Get-ChildItem -LiteralPath $sharpOut -Filter '*sharphound.zip' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $zipStatus = if (-not $sharpCollectedZip) { 'partial-no-zip' }
        elseif ($sharpStatus -eq 'checked') { 'checked' } else { 'partial-zip' }
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`t$zipStatus"
}
$winpeasStatus = if ($winpeasJob) { Complete-EnumJob $winpeasJob } else { 'unavailable' }
$winpeasOk = $winpeasStatus -eq 'checked'
if ($winpeasJob) { Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "winpeas`t$winpeasStatus" }
if (-not $winpeasOk -and $haveBat -and (-not $fastSuccessRecipe -or $NoShell -or $FinishBgEnum)) {
    Write-Host '[ENUM] WinPEAS batch fallback.'
    $binaryOutput = Join-Path $capture 'winpeas-output.txt'
    if (Test-Path -LiteralPath $binaryOutput) {
        Move-Item -LiteralPath $binaryOutput -Destination (Join-Path $capture 'winpeas-binary-partial.txt')
    }
    try {
        $status = Invoke-CapturedProcess 'cmd.exe' "/d /c `"$winpeasBat`"" $binaryOutput $ToolTimeoutSeconds
        $winpeasOk = $status -eq 'checked'
        $status = if ($winpeasOk) { 'batch-fallback' } else { "batch-$status" }
        Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "winpeas`t$status"
    } catch {
        Write-Warning "WinPEAS batch failed: $($_.Exception.Message)"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $capture 'winpeas-output.txt'))) {
    $status = if (Test-Path -LiteralPath (Join-Path $capture 'winpeas-binary-partial.txt')) { 'partial' } else { 'unavailable' }
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "winpeas`t$status"
}
$privescStatus = if ($privescJob) { Complete-EnumJob $privescJob } else { 'unavailable' }
$privescComplete = $privescStatus -eq 'checked'
Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "privesccheck`t$privescStatus"

foreach ($entry in @(@('winpeas', 'winpeas-output.txt'), @('winpeas-binary-partial', 'winpeas-binary-partial.txt'), @('privesccheck', 'privesccheck-output.txt'))) {
    $raw = Join-Path $capture $entry[1]
    if (Test-Path -LiteralPath $raw) {
        $count = @(Select-String -LiteralPath $raw -Pattern 'writ(e|able)|password|credential|service|impersonate|CVE-' -AllMatches).Count
        Write-Finding "$($entry[0])-screening" "$count candidate lines in raw output; values withheld from console"
    }
}
if ($domainJoined -and -not $Offline) {
    $sharpSummary = if ($sharpCollectedZip) { 'collection ZIP produced; contents withheld from console' }
        else { 'no collection ZIP; see coverage for completion status' }
    Write-Finding 'sharphound-screening' $sharpSummary
}

Write-Host '[ENUM] Verifying local escalation paths.'
$whoamiPriv = (& whoami.exe /priv 2>&1 | Out-String)
if ($whoamiPriv -match 'SeImpersonatePrivilege') {
    Write-Finding 'token-privilege' 'SeImpersonate present; no reviewed recipe is installed'
}
$aieLM = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aieCU = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($aieLM -eq 1 -and $aieCU -eq 1) {
    Write-Finding 'installer-policy' 'AlwaysInstallElevated enabled in both hives; gated recipe needed'
}
try {
    $unquoted = @(Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -match '^\s*[^"\s][^" ]* [^"].*\.exe' -and $_.StartName -match 'LocalSystem|LocalService|NetworkService'
    })
    if ($unquoted.Count -gt 0) {
        Write-Finding 'service-paths' "$($unquoted.Count) privileged unquoted paths; check writable segments before use"
    }
} catch { Write-Warning 'Service path check failed.' }

if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Edamame-NG\Lab\WeakService') {
    if ($EnableWeakServiceLab -and -not (Test-AdminMembership) -and -not (Test-AdminIdentity) -and -not (Test-SystemIdentity)) {
        $weakLabState = Get-WeakServiceLabState
    }
    if ($weakLabState) {
        Write-Finding 'weak-service-lab' 'Exact fixture, stopped LocalSystem service, original path, and effective change/start rights verified'
    } else {
        Write-Finding 'weak-service-lab' 'Fixture marker present; current token or fixture did not pass the gated recipe prerequisites'
    }
}

$suggestedCves = @()
foreach ($file in @('winpeas-output.txt', 'privesccheck-output.txt')) {
    $path = Join-Path $capture $file
    if (Test-Path -LiteralPath $path) {
        $suggestedCves += Select-String -LiteralPath $path -Pattern 'CVE-[0-9]{4}-[0-9]{4,}' -AllMatches |
            ForEach-Object { $_.Matches.Value }
    }
}
$suggestedCves = @($suggestedCves | Sort-Object -Unique)
if ($suggestedCves.Count) { Write-Finding 'cve-candidates' "$($suggestedCves.Count) suggested; review exact build and patch status" }

$recipe = $null
if (Test-SystemIdentity) {
    $recipe = 'already-system'
    Write-Finding 'local-elevation' 'Already running as SYSTEM'
} elseif (Test-AdminIdentity) {
    $recipe = 'already-admin'
    Write-Finding 'local-elevation' 'Already running with Administrator token'
} elseif (Test-AdminMembership) {
    $recipe = 'uac-admin'
    Write-Finding 'local-elevation' 'Administrator membership detected; UAC elevation available'
} elseif ($weakLabState) {
    $recipe = 'weak-service-lab'
    Write-Finding 'local-elevation' 'Standard-user SYSTEM route verified on the exact disposable weak-service fixture'
}
$enumStatus = if ($winpeasOk -and $privescComplete) { 'checked' } else { 'unsupported' }
Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "External local enumerator capture`t$enumStatus`tWinPEAS and PrivescCheck completion only"
foreach ($area in @(
    'Situational Awareness and Initial Enumeration', 'WiFi & Network Enumeration',
    'Processes & Tasks', 'BIOS & Hardware Information', 'Sensitive Information & Passwords',
    'Registry Queries', 'Installed Software', 'Logging/AV enumeration')) {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`t$enumStatus`texternal enumerator output only; individual conditions unverified"
}
foreach ($area in @(
    'Common Privilege Escalation Methods', 'LOW HANGING FRUIT:',
    'UNQUOTED SERVICE PATHS', 'WEAK SERVICE PERMISSIONS:', 'SCHEDULED TASKS:',
    'IMPERSONATION (SeImpersonatePrivilege or SeAssignPrimaryPrivilege):')) {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`tunsupported`tno independent privilege proof for the full checklist area"
}
Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "UAC BYPASS:`tunsupported`tUAC admin consent is the only current recipe"
$domainStatus = if (-not $domainJoined) { 'inapplicable' }
    elseif ($sharpCollectedZip -and $sharpStatus -eq 'checked') { 'checked' }
    else { 'unsupported' }
Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "BloodHound`t$domainStatus`tSharpHound Default collection ZIP"
foreach ($area in @('Active Directory', 'Initial Enumeration')) {
    $status = if ($domainJoined) { 'unsupported' } else { 'inapplicable' }
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`t$status`tSharpHound Default does not verify the full checklist area"
}
foreach ($area in @(
    'Enumerating DACLs with BloodyAD', 'Credential Hunting', 'POISONING Attacks',
    'EXCHANGE', 'SCCM', 'ONCE YOU GET DA', 'Things to check for', 'Other Attacks',
    'GPOs, Domain Auditing', 'Credential validation', 'Local CVE exploitation')) {
    $status = if (-not $domainJoined -and $area -notin @('Local CVE exploitation', 'Standard-user SYSTEM recipe')) { 'inapplicable' } else { 'unsupported' }
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`t$status`tno reviewed automatic recipe"
}
$weakCoverage = if ($weakLabState) { 'checked' } else { 'unsupported' }
Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "Standard-user SYSTEM recipe`t$weakCoverage`texact EdamameWeakSvc fixture only"

# Alerts above precede these final output filenames.
foreach ($name in @('winpeas-output.txt', 'winpeas-binary-partial.txt', 'privesccheck-output.txt', 'sharphound-output.txt')) {
    $from = Join-Path $capture $name
    if (Test-Path -LiteralPath $from) {
        Move-Item -LiteralPath $from -Destination (Join-Path $runDir $name)
        Write-Host "[SAVED] $name"
    }
}
if ($sharpCollectedZip -and (Test-Path -LiteralPath $sharpCollectedZip.FullName)) {
    Move-Item -LiteralPath $sharpCollectedZip.FullName -Destination (Join-Path $runDir 'sharphound.zip')
    Write-Host '[SAVED] sharphound.zip'
}
$suggestedCves | ForEach-Object { "$_`thttps://www.cve.org/CVERecord?id=$_" } |
    Set-Content -LiteralPath (Join-Path $runDir 'cve-candidates.tsv') -Encoding ASCII
Write-CveIndex $CatalogDir $suggestedCves (Join-Path $runDir 'cve-index.tsv')
$detailLines = @("cve`tstate`tdescription`taffected_json`treferences_json`treview_state")
if ((Test-Path -LiteralPath (Join-Path $CatalogDir 'local-eop-details.tsv') -PathType Leaf) -and
    -not (Test-CveDetailsCatalog $CatalogDir)) { Write-Warning 'Offline CVE details failed integrity checks; withholding details.' }
foreach ($id in $suggestedCves) { $detailLines += Get-CveDetailsLine $CatalogDir $id }
$detailLines | Set-Content -LiteralPath (Join-Path $runDir 'cve-details.tsv') -Encoding UTF8
Write-Host '[SAVED] findings.tsv, coverage.tsv, attempts.tsv, tools.tsv'

if ($fastSuccessRecipe) {
    $evidence = if ($fastSuccessRecipe -eq 'weak-service-lab') { $weakServiceEvidence } else { 'verified-local-proof' }
    [pscustomobject]@{ host = $hostName; recipe = $fastSuccessRecipe; evidence = $evidence } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $runDir 'success.json') -Encoding UTF8
    exit 0
}
if ($recipe -eq $fastAttemptedRecipe) { $recipe = $null }

if ($recipe) {
    if ($recipe -eq 'weak-service-lab') {
        if (-not (Confirm-WeakServiceChange)) {
            Write-Attempt $recipe 'service-change-approval-declined'
            $recipe = $null
        } else {
            Write-Attempt $recipe 'service-change-approved'
        }
    }
}
if ($recipe) {
    if ($recipe -in @('already-admin', 'uac-admin')) {
        if (Confirm-SystemService) {
            Write-Attempt $recipe 'service-approved'
            $psExecPath = Get-PsExecAsset
            if ($psExecPath) {
                $recipe = if ($recipe -eq 'uac-admin') { 'uac-admin-system' } else { 'admin-system' }
                Write-Host '[RECIPE] Verified Microsoft PsExec available for local SYSTEM shell.'
            }
        } else {
            Write-Attempt $recipe 'service-approval-declined'
        }
    }
    if (Invoke-Recipe $recipe) {
        $evidence = if ($recipe -eq 'weak-service-lab') { $weakServiceEvidence } else { 'verified-local-proof' }
        [pscustomobject]@{ host = $hostName; recipe = $recipe; evidence = $evidence } |
            ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $runDir 'success.json') -Encoding UTF8
        Write-Attempt $recipe 'proof-success'
        exit 0
    }
    Write-Attempt $recipe 'proof-failed'
}
Write-Host "[RESULT] No supported Windows escalation recipe verified. See $runDir"
