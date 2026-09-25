#requires -Version 5.1
<# Edamame-NG: Windows host enumeration and bounded local elevation. #>
[CmdletBinding(DefaultParameterSetName = 'Auto')]
param(
    [Parameter(ParameterSetName = 'Scan')][switch]$Scan,
    [Parameter(ParameterSetName = 'Resume')][switch]$Resume,
    [Parameter(ParameterSetName = 'Resume')][string]$RunId,
    [string]$OutputDir = (Join-Path $env:LOCALAPPDATA 'Edamame-NG\runs'),
    [string]$ToolDir,
    [ValidateRange(15, 3600)][int]$ToolTimeoutSeconds = 600,
    [switch]$NoShell
)

$ErrorActionPreference = 'Stop'
$hostName = $env:COMPUTERNAME
$cacheBase = Join-Path $env:LOCALAPPDATA 'Edamame-NG\cache'
$runDir = $null

function Set-PrivateDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $Path '/inheritance:r' '/grant:r' "${principal}:(OI)(CI)F" *> $null
    if ($LASTEXITCODE -ne 0) { throw "Could not restrict directory ACL: $Path" }
}

function Get-LatestSuccess {
    if (-not (Test-Path -LiteralPath $OutputDir)) { return $null }
    Get-ChildItem -LiteralPath $OutputDir -Directory |
        Sort-Object Name -Descending |
        ForEach-Object {
            $candidate = Join-Path $_.FullName 'success.json'
            if (Test-Path -LiteralPath $candidate) { return $candidate }
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

function Invoke-CapturedProcess([string]$FilePath, [string]$Arguments, [string]$OutputPath, [int]$TimeoutSeconds) {
    $stdout = "$OutputPath.stdout"
    $stderr = "$OutputPath.stderr"
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments
    $startInfo.WorkingDirectory = Split-Path -Parent $OutputPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($startInfo)
    $outStream = [IO.File]::Create($stdout)
    $errStream = [IO.File]::Create($stderr)
    try {
        $outCopy = $process.StandardOutput.BaseStream.CopyToAsync($outStream)
        $errCopy = $process.StandardError.BaseStream.CopyToAsync($errStream)
        $finished = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $finished) {
            try { & taskkill.exe /PID $process.Id /T /F *> $null } catch { }
            if (-not $process.HasExited) { $process.Kill() }
            [void]$process.WaitForExit(5000)
            Write-Warning "$([IO.Path]::GetFileName($FilePath)) exceeded $TimeoutSeconds seconds; preserving partial output."
        }
        foreach ($copy in @($outCopy, $errCopy)) {
            try { [void]$copy.Wait(5000) } catch { }
        }
        $exitCode = if ($finished) { $process.ExitCode } else { -1 }
    } finally {
        $outStream.Dispose()
        $errStream.Dispose()
        $process.Dispose()
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
    } else {
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

function Test-SystemIdentity {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18'
}

function Test-AdminIdentity {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-AdminMembership {
    $groups = (& whoami.exe /groups 2>&1 | Out-String)
    return $groups -match 'S-1-5-32-544'
}

function Invoke-Recipe([string]$Recipe) {
    switch ($Recipe) {
        'already-system' {
            if (-not (Test-SystemIdentity)) { return $false }
            if ($NoShell) { Write-Host '[PROOF] SYSTEM token verified; shell suppressed.' }
            else { & powershell.exe -NoLogo -NoExit }
            return $true
        }
        'already-admin' {
            if (-not (Test-AdminIdentity)) { return $false }
            if ($NoShell) { Write-Host '[PROOF] Administrator token verified; shell suppressed.' }
            else { & powershell.exe -NoLogo -NoExit }
            return $true
        }
        'uac-admin' {
            if (-not (Test-AdminMembership)) { return $false }
            $marker = Join-Path $runDir '.capture\uac-proof.txt'
            Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
            $quotedMarker = $marker.Replace("'", "''")
            $openChildShell = if ($NoShell) { '$false' } else { '$true' }
            $child = @"
`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
`$principal = New-Object Security.Principal.WindowsPrincipal(`$identity)
if (-not `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }
Set-Content -LiteralPath '$quotedMarker' -Value `$identity.User.Value -Encoding ASCII
if ($openChildShell) { & powershell.exe -NoLogo -NoExit }
"@
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
            try {
                $process = Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -EncodedCommand $encoded" -Verb RunAs -PassThru
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

if ($Resume) {
    if ($RunId) {
        if ($RunId -notmatch '^[A-Za-z0-9._-]+$') { throw 'Invalid run ID' }
        $prior = Join-Path (Join-Path $OutputDir $RunId) 'success.json'
    }
    if (-not $prior -or -not (Test-Path -LiteralPath $prior)) { throw 'No successful run to resume' }
    $runDir = Split-Path -Parent $prior
    $saved = Get-Content -LiteralPath $prior -Raw | ConvertFrom-Json
    if ($saved.host -ne $hostName -or $saved.recipe -notin @('already-system', 'already-admin', 'uac-admin')) {
        throw 'Saved run has an invalid host or recipe'
    }
    Write-Host "[RESUME] $($saved.recipe) on $hostName; checking prerequisites again."
    if (Invoke-Recipe $saved.recipe) {
        Write-Attempt $saved.recipe 'resumed-proof'
        exit 0
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
Write-Host '[ENUM] Fetching official current release assets.'

$winpeas = Join-Path $capture 'winPEASany.exe'
$winpeasBat = Join-Path $capture 'winPEAS.bat'
$privescCheck = Join-Path $capture 'PrivescCheck.ps1'
$haveWinpeas = Get-ReleaseAsset 'peass-ng/PEASS-ng' 'winPEASany.exe' $winpeas
$haveBat = Get-ReleaseAsset 'peass-ng/PEASS-ng' 'winPEAS.bat' $winpeasBat
$havePrivescCheck = Get-ReleaseAsset 'itm4n/PrivescCheck' 'PrivescCheck.ps1' $privescCheck

$domainJoined = $false
try { $domainJoined = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { Write-Warning 'Domain join status unavailable.' }
if ($domainJoined) {
    $sharpRecorded = $false
    $latestSharp = $null
    if ($ToolDir) {
        $sharpLocal = Get-ChildItem -LiteralPath $ToolDir -Filter 'SharpHound_v*_windows_x86.zip' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($sharpLocal -and $sharpLocal.Name -match '^SharpHound_(v[0-9.]+)_windows_x86\.zip$') {
            $latestSharp = $Matches[1]
        }
    } else {
        try {
            $response = Invoke-WebRequest -Uri 'https://github.com/SpecterOps/SharpHound/releases/latest' -UseBasicParsing -TimeoutSec 20
            $latestSharp = ($response.BaseResponse.ResponseUri.AbsoluteUri -split '/')[-1]
        } catch { Write-Warning 'Could not resolve SharpHound release.' }
    }
    if ($latestSharp -and $latestSharp -match '^v[0-9.]+$') {
        $sharpAsset = "SharpHound_${latestSharp}_windows_x86.zip"
        $sharpZip = Join-Path $capture $sharpAsset
        if (Get-ReleaseAsset 'SpecterOps/SharpHound' $sharpAsset $sharpZip) {
            try {
                $sharpBin = Join-Path $capture 'sharphound-bin'
                Expand-Archive -LiteralPath $sharpZip -DestinationPath $sharpBin -Force
                $sharpExe = Get-ChildItem -LiteralPath $sharpBin -Filter 'SharpHound.exe' -Recurse -File | Select-Object -First 1
                if (-not $sharpExe) { throw 'SharpHound.exe absent from release ZIP' }
                $sharpOut = Join-Path $capture 'sharphound-data'
                New-Item -ItemType Directory -Path $sharpOut | Out-Null
                Write-Host '[ENUM] SharpHound Default collection.'
                $sharpStatus = Invoke-CapturedProcess $sharpExe.FullName `
                    "--CollectionMethods Default --OutputDirectory `"$sharpOut`" --ZipFileName sharphound.zip" `
                    (Join-Path $capture 'sharphound-output.txt') $ToolTimeoutSeconds
                $collected = Join-Path $sharpOut 'sharphound.zip'
                if ($sharpStatus -eq 'checked' -and (Test-Path -LiteralPath $collected)) {
                    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`tchecked"
                    $sharpRecorded = $true
                } else {
                    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`tpartial-no-zip"
                    $sharpRecorded = $true
                }
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
} else {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`tnot-domain-joined"
}

$winpeasOk = $false
if ($haveWinpeas) {
    Write-Host '[ENUM] WinPEAS.'
    try {
        $status = Invoke-CapturedProcess $winpeas '' (Join-Path $capture 'winpeas-output.txt') $ToolTimeoutSeconds
        $winpeasOk = $status -eq 'checked'
        Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "winpeas`t$status"
    } catch {
        Write-Warning "WinPEAS binary failed: $($_.Exception.Message)"
    }
}
if (-not $winpeasOk -and $haveBat) {
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

$privescComplete = $false
if ($havePrivescCheck) {
    Write-Host '[ENUM] PrivescCheck.'
    try {
        $quotedCheck = $privescCheck.Replace("'", "''")
        $checkCode = ". '$quotedCheck'; Invoke-PrivescCheck -Extended -Audit"
        $encodedCheck = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($checkCode))
        $status = Invoke-CapturedProcess 'powershell.exe' "/NoProfile /ExecutionPolicy Bypass /EncodedCommand $encodedCheck" `
            (Join-Path $capture 'privesccheck-output.txt') $ToolTimeoutSeconds
        $privescComplete = $status -eq 'checked'
        Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "privesccheck`t$status"
    } catch {
        Write-Warning "PrivescCheck failed: $($_.Exception.Message)"
        Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "privesccheck`tpartial"
    }
} else {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "privesccheck`tunavailable"
}

foreach ($entry in @(@('winpeas', 'winpeas-output.txt'), @('privesccheck', 'privesccheck-output.txt'))) {
    $raw = Join-Path $capture $entry[1]
    if (Test-Path -LiteralPath $raw) {
        $count = @(Select-String -LiteralPath $raw -Pattern 'writ(e|able)|password|credential|service|impersonate|CVE-' -AllMatches).Count
        Write-Finding "$($entry[0])-screening" "$count candidate lines in raw output; values withheld from console"
    }
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
}
$enumStatus = if ($winpeasOk -or $privescComplete) { 'checked' } else { 'unsupported' }
foreach ($area in @(
    'Situational Awareness and Initial Enumeration', 'WiFi & Network Enumeration',
    'Processes & Tasks', 'BIOS & Hardware Information', 'Sensitive Information & Passwords',
    'Registry Queries', 'Installed Software', 'Logging/AV enumeration',
    'Common Privilege Escalation Methods', 'LOW HANGING FRUIT:',
    'UNQUOTED SERVICE PATHS', 'WEAK SERVICE PERMISSIONS:', 'SCHEDULED TASKS:',
    'IMPERSONATION (SeImpersonatePrivilege or SeAssignPrimaryPrivilege):')) {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`t$enumStatus`tenumerator output; only named recipes are attempted"
}
Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "UAC BYPASS:`tunsupported`tUAC admin consent is the only current recipe"
$domainStatus = if (-not $domainJoined) { 'inapplicable' }
    elseif (Test-Path -LiteralPath (Join-Path $capture 'sharphound-data\sharphound.zip')) { 'checked' }
    else { 'unsupported' }
foreach ($area in @('Active Directory', 'Initial Enumeration', 'BloodHound')) {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`t$domainStatus`tSharpHound Default collection"
}
foreach ($area in @(
    'Enumerating DACLs with BloodyAD', 'Credential Hunting', 'POISONING Attacks',
    'BE VERY CAREFUL WHEN LAUNCHING THESE. DO NOT RUN FOR MORE THAN ~5 MINUTES AT A TIME, ALWAYS RUN IN ANALYZE MODE FIRST. CHECK WITH THE TEAM CAPTAIN ON THE COMMAND BEFORE EXECUTION SINCE THESE CAN POTENTIALLY BE DISTRUPTIVE IN SENSITIVE NETWORKS.',
    'EXCHANGE', 'SCCM', 'ONCE YOU GET DA', 'Things to check for', 'Other Attacks',
    'GPOs, Domain Auditing', 'Credential validation', 'Local CVE exploitation',
    'Standard-user SYSTEM recipe')) {
    $status = if (-not $domainJoined -and $area -notin @('Local CVE exploitation', 'Standard-user SYSTEM recipe')) { 'inapplicable' } else { 'unsupported' }
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`t$status`tno reviewed automatic recipe"
}

# Alerts above precede these final output filenames.
foreach ($name in @('winpeas-output.txt', 'winpeas-binary-partial.txt', 'privesccheck-output.txt', 'sharphound-output.txt')) {
    $from = Join-Path $capture $name
    if (Test-Path -LiteralPath $from) {
        Move-Item -LiteralPath $from -Destination (Join-Path $runDir $name)
        Write-Host "[SAVED] $name"
    }
}
$dataZip = Join-Path (Join-Path $capture 'sharphound-data') 'sharphound.zip'
if (Test-Path -LiteralPath $dataZip) {
    Move-Item -LiteralPath $dataZip -Destination (Join-Path $runDir 'sharphound.zip')
    Write-Host '[SAVED] sharphound.zip'
}
$suggestedCves | ForEach-Object { "$_`thttps://www.cve.org/CVERecord?id=$_" } |
    Set-Content -LiteralPath (Join-Path $runDir 'cve-candidates.tsv') -Encoding ASCII
Write-Host '[SAVED] findings.tsv, coverage.tsv, attempts.tsv, tools.tsv'

if ($recipe) {
    if (Invoke-Recipe $recipe) {
        [pscustomobject]@{ host = $hostName; recipe = $recipe; evidence = 'verified-local-proof' } |
            ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $runDir 'success.json') -Encoding UTF8
        Write-Attempt $recipe 'proof-success'
        exit 0
    }
    Write-Attempt $recipe 'proof-failed'
}
Write-Host "[RESULT] No supported Windows escalation recipe verified. See $runDir"
