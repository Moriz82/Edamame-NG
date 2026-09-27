#requires -Version 3.0
<# Edamame-NG: Windows host enumeration and bounded local elevation. #>
[CmdletBinding(DefaultParameterSetName = 'Auto')]
param(
    [Parameter(ParameterSetName = 'Scan')][switch]$Scan,
    [Parameter(ParameterSetName = 'Resume')][switch]$Resume,
    [Parameter(ParameterSetName = 'Resume')][string]$RunId,
    [string]$OutputDir,
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
    [switch]$NoShell,
    [Parameter(ParameterSetName = 'Credential')][switch]$VerifyCredential,
    [Parameter(ParameterSetName = 'Credential')][string]$CredAccount,
    [Parameter(ParameterSetName = 'Credential')][string]$CredEndpoint,
    [Parameter(ParameterSetName = 'Credential')][ValidateSet('smb')][string]$CredService = 'smb',
    [Parameter(ParameterSetName = 'Credential')][switch]$CredSecretStdin,
    [Parameter(ParameterSetName = 'Credential')][string]$CredLockoutFile,
    [Parameter(ParameterSetName = 'Credential')][string]$CredLedger,
    [Parameter(ParameterSetName = 'Credential')][ValidateRange(1, 300)][int]$CredTimeoutSeconds = 20
)

$ErrorActionPreference = 'Stop'
trap {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
if ([string]::IsNullOrWhiteSpace($CatalogDir)) { $CatalogDir = Join-Path $PSScriptRoot 'catalog' }
$hostName = $env:COMPUTERNAME
$localBase = $env:LOCALAPPDATA
if ([string]::IsNullOrWhiteSpace($localBase)) {
    $localBase = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
}
if ([string]::IsNullOrWhiteSpace($localBase)) {
    throw 'Cannot determine the local application data path for private run and cache storage.'
}
if ([string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir = Join-Path $localBase 'Edamame-NG\runs' }
$cacheBase = Join-Path $localBase 'Edamame-NG\cache'
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

function Get-CveDetailsLine([string]$CatalogPath, [string]$Id, $CatalogValid = $null) {
    $index = Join-Path $CatalogPath 'local-eop-details.tsv'
    $reviewState = 'details-not-installed'
    if (Test-Path -LiteralPath $index -PathType Leaf) {
        if ($null -eq $CatalogValid) { $CatalogValid = Test-CveDetailsCatalog $CatalogPath }
        if ($CatalogValid) {
            $member = @(Get-CatalogEntries $CatalogPath | Where-Object cve -eq $Id | Select-Object -First 1)
            if ($member.Count) {
                foreach ($line in [IO.File]::ReadAllLines($index, [Text.Encoding]::UTF8)) {
                    if ($line.StartsWith("$Id`t", [StringComparison]::Ordinal)) { return "$line`t" }
                }
            }
        } else { $reviewState = 'integrity-failed' }
    }
    $state = Get-GeneralCveState $CatalogPath $Id
    if ($state.EndsWith('-general', [StringComparison]::Ordinal)) {
        $state = $state.Substring(0, $state.Length - 8)
    }
    return "$Id`t$state`t`t`t`t$reviewState`t"
}

function Get-AllCveDetailsCatalog([string]$CatalogPath) {
    $result = @{ State = 'absent'; Root = ''; Shards = @{} }
    $marker = Join-Path (Join-Path $CatalogPath 'all-cve-details') 'installed'
    if (-not (Test-Path -LiteralPath $marker)) { return $result }
    $result.State = 'invalid'
    try {
        $sourcePath = Join-Path $CatalogPath 'all-cve-details-source.json'
        $basePath = Join-Path $CatalogPath 'cve-ids-source.json'
        foreach ($path in @($marker, $sourcePath, $basePath, (Split-Path -Parent $marker))) {
            if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $result }
        }
        if ((Get-Item -LiteralPath $marker).Length -ne 65 -or
            (Get-Item -LiteralPath $sourcePath).Length -gt 65536 -or
            (Get-Item -LiteralPath $basePath).Length -gt 65536) { return $result }
        $expected = [IO.File]::ReadAllText($marker).Trim()
        if ($expected -cnotmatch '^[0-9a-f]{64}$' -or
            (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) { return $result }
        $source = [IO.File]::ReadAllText($sourcePath) | ConvertFrom-Json
        $base = [IO.File]::ReadAllText($basePath) | ConvertFrom-Json
        if ($source.format_version -ne 1 -or $source.shards_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $source.baseline_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $source.index_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $source.baseline_sha256 -cne $base.baseline_sha256 -or $source.index_sha256 -cne $base.index_sha256) { return $result }
        $result.Root = Join-Path (Split-Path -Parent $marker) $source.shards_sha256
        $manifest = Join-Path $result.Root 'shards.tsv'
        foreach ($path in @($result.Root, $manifest)) {
            if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $result }
        }
        if ((Get-Item -LiteralPath $manifest).Length -gt 16777216 -or
            (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $source.shards_sha256) { return $result }
        $lines = [IO.File]::ReadAllLines($manifest, [Text.Encoding]::ASCII)
        if (-not $lines.Length -or $lines[0] -cne "path`tsha256`trows`tbytes`tuncompressed_bytes") { return $result }
        [long]$total = 0
        for ($i = 1; $i -lt $lines.Length; $i++) {
            $fields = $lines[$i].Split([char]9)
            if ($fields.Length -ne 5 -or $fields[0] -cnotmatch '^[0-9]{4}/[0-9]{1,16}\.tsv\.gz$' -or
                $fields[1] -cnotmatch '^[0-9a-f]{64}$' -or $result.Shards.ContainsKey($fields[0])) { return $result }
            foreach ($number in $fields[2..4]) { if ($number -cnotmatch '^[0-9]{1,9}$') { return $result } }
            $entry = @{ Hash = $fields[1]; Rows = [int]$fields[2]; Bytes = [int]$fields[3]; Expanded = [int]$fields[4] }
            if ($entry.Rows -lt 1 -or $entry.Rows -gt 1000 -or $entry.Bytes -lt 1 -or $entry.Bytes -gt 269484032 -or
                $entry.Expanded -lt 1 -or $entry.Expanded -gt 268435456) { return $result }
            $result.Shards[$fields[0]] = $entry
            $total += $entry.Rows
        }
        if ($total -ne $source.record_count -or $result.Shards.Count -ne $source.shard_count) { return $result }
        $result.State = 'valid'
    } catch { $result.State = 'invalid' }
    return $result
}

function Get-CveDetailBucket([string]$Id) {
    if ($Id -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,19}$') { throw 'Invalid CVE ID.' }
    $suffix = $Id.Substring(9)
    return $Id.Substring(4, 4) + '/' + $suffix.Substring(0, $suffix.Length - 3) + '.tsv.gz'
}

function Read-CveDetailShard([string]$Root, [string]$Relative, [hashtable]$Entry, [hashtable]$Wanted) {
    $path = Join-Path $Root $Relative
    foreach ($item in @($path, (Split-Path -Parent $path))) {
        if ((Get-Item -LiteralPath $item).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Detail shard is a link.' }
    }
    if ((Get-Item -LiteralPath $path).Length -ne $Entry.Bytes -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Entry.Hash) { throw 'Detail shard digest/size mismatch.' }
    $found = @{}
    $seen = @{}
    $stream = [IO.File]::OpenRead($path)
    $gzip = $null
    try {
        $gzip = New-Object IO.Compression.GZipStream($stream, [IO.Compression.CompressionMode]::Decompress)
        $buffer = New-Object byte[] 8192
        $line = New-Object Text.StringBuilder
        $encoding = [Text.Encoding]::GetEncoding(20127, [Text.EncoderFallback]::ExceptionFallback, [Text.DecoderFallback]::ExceptionFallback)
        [long]$expanded = 0
        $lineNumber = 0
        # StreamReader.ReadLine can allocate an unbounded row before validation.
        # Fixed byte chunks cap row allocation before adding to the builder.
        while (($length = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $expanded += $length
            if ($expanded -gt $Entry.Expanded) { throw 'Detail shard expanded size exceeded.' }
            $chunk = $encoding.GetString($buffer, 0, $length)
            $offset = 0
            while ($offset -lt $chunk.Length) {
                $newline = $chunk.IndexOf("`n", $offset, [StringComparison]::Ordinal)
                $end = if ($newline -lt 0) { $chunk.Length } else { $newline }
                if ($line.Length + $end - $offset -ge 16777216) { throw 'Detail row size exceeded.' }
                [void]$line.Append($chunk, $offset, $end - $offset)
                $offset = $end + 1
                if ($newline -lt 0) { break }
                $value = $line.ToString()
                [void]$line.Clear()
                $lineNumber++
                if ($lineNumber -eq 1) {
                    if ($value -cne "cve`tstate`tdescription`taffected_json`treferences_json`treview_state`tsource_json") { throw 'Invalid detail header.' }
                    continue
                }
                $fields = $value.Split([char]9)
                if ($fields.Length -ne 7 -or $lineNumber -gt 1001 -or
                    $fields[0] -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,19}$' -or
                    $fields[1] -cnotmatch '^(published|rejected|reserved)$' -or
                    $fields[5] -cne 'source-metadata-unreviewed' -or $value -cmatch '[\x00-\x08\x0b-\x1f\x7f]' -or
                    (Get-CveDetailBucket $fields[0]) -cne $Relative -or $seen.ContainsKey($fields[0])) { throw 'Invalid detail row.' }
                $seen[$fields[0]] = $true
                if ($Wanted.ContainsKey($fields[0])) { $found[$fields[0]] = $value }
            }
        }
        if ($line.Length -ne 0 -or $lineNumber - 1 -ne $Entry.Rows -or $expanded -ne $Entry.Expanded) { throw 'Detail shard count/size mismatch.' }
    } finally {
        if ($gzip) { $gzip.Dispose() }
        $stream.Dispose()
    }
    return $found
}

function Get-CveDetailsLines([string]$CatalogPath, [string[]]$Ids) {
    if (-not $Ids.Count) { return }
    $catalog = Get-AllCveDetailsCatalog $CatalogPath
    if ($catalog.State -eq 'absent') {
        $valid = Test-CveDetailsCatalog $CatalogPath
        foreach ($id in $Ids) { Get-CveDetailsLine $CatalogPath $id $valid }
        return
    }
    $groups = @{}
    foreach ($id in $Ids) {
        $key = Get-CveDetailBucket $id
        if (-not $groups.ContainsKey($key)) { $groups[$key] = @{} }
        $groups[$key][$id] = $true
    }
    foreach ($key in @($groups.Keys | Sort-Object)) {
        $found = @{}
        $failed = $catalog.State -ne 'valid'
        if (-not $failed -and $catalog.Shards.ContainsKey($key)) {
            try { $found = Read-CveDetailShard $catalog.Root $key $catalog.Shards[$key] $groups[$key] }
            catch { $failed = $true }
        }
        foreach ($id in @($groups[$key].Keys | Sort-Object)) {
            if (-not $failed -and $found.ContainsKey($id)) { $found[$id]; continue }
            $state = (Get-GeneralCveState $CatalogPath $id) -replace '-general$', ''
            $review = if ($failed -or $state -ne 'unindexed') { 'integrity-failed' } else { 'not-in-dated-baseline' }
            "$id`t$state`t`t`t`t$review`t"
        }
    }
}

function Get-SuggestedCves([string]$CapturePath, [hashtable]$Seen) {
    $ids = @{}
    foreach ($id in $Seen.Keys) {
        $normalized = ([string]$id).ToUpperInvariant()
        if ($normalized -cmatch '^CVE-[0-9]{4}-[0-9]{4,19}$') { $ids[$normalized] = $true }
    }
    foreach ($file in @('winpeas-output.txt', 'winpeas-binary-partial.txt', 'privesccheck-output.txt', 'sharphound-output.txt')) {
        $path = Join-Path $CapturePath $file
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Select-String -LiteralPath $path -Pattern 'CVE-[0-9]{4}-[0-9]{4,19}(?![0-9])' -AllMatches |
                ForEach-Object { foreach ($match in $_.Matches) { $ids[$match.Value.ToUpperInvariant()] = $true } }
        }
    }
    return @($ids.Keys | Sort-Object)
}

function Write-CveIndex([string]$CatalogPath, [string[]]$Suggested, [string]$Destination) {
    $catalog = @{}
    $indexPath = Join-Path $CatalogPath 'local-eop.tsv'
    $curatedPath = Join-Path $CatalogPath 'curated-eop.tsv'
    if ((Test-Path -LiteralPath $indexPath -PathType Leaf) -or
        (Test-Path -LiteralPath $curatedPath -PathType Leaf)) {
        foreach ($item in @(Get-CatalogEntries $CatalogPath)) {
            if (-not $catalog.ContainsKey($item.cve)) { $catalog[$item.cve] = $item }
        }
    } elseif (-not (Test-Path -LiteralPath (Join-Path $CatalogPath 'cve-ids') -PathType Container)) {
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
    if ($Poc -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,19}$') { throw 'Invalid CVE ID.' }
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
    if ($CveDetails -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,19}$') { throw 'Invalid CVE ID.' }
    "cve`tstate`tdescription`taffected_json`treferences_json`treview_state`tsource_json"
    $lines = @(Get-CveDetailsLines $CatalogDir @($CveDetails))
    $lines
    if (@($lines | Where-Object { ($_ -split "`t")[5] -eq 'integrity-failed' }).Count) {
        throw 'Offline CVE details failed integrity checks.'
    }
    return
}

if ($Cve) {
    if ($Cve -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,19}$') { throw 'Invalid CVE ID.' }
    if (-not (Test-Path -LiteralPath (Join-Path $CatalogDir 'local-eop.tsv') -PathType Leaf) -and
        -not (Test-Path -LiteralPath (Join-Path $CatalogDir 'curated-eop.tsv') -PathType Leaf) -and
        -not (Test-Path -LiteralPath (Join-Path $CatalogDir 'cve-ids') -PathType Container)) {
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

# Operator-supplied credential validation. The account, the secret, and the
# discovered endpoint are supplied by the operator for this check only. No
# collector output, cache, or catalog value is ever used as a secret, and no
# secret is written to an artifact or a command line.
function Get-CredMasked([string]$Value) {
    if ($Value.Length -le 2) { return "$($Value.Substring(0, 1))*" }
    return "$($Value.Substring(0, 1))***$($Value.Substring($Value.Length - 1, 1))"
}

function Set-PrivateFile([string]$Path) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    foreach ($sid in @($identity, (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'),
                       (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'))) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $sid, $full, $allow
        $acl.AddAccessRule($rule)
    }
    (Get-Item -LiteralPath $Path -Force).SetAccessControl($acl)
}

function Test-PrivateFileAcl([string]$Path) {
    $permitted = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($sid -notin $permitted) { return $false }
    }
    return $true
}

function Get-CredLedgerPath {
    if ($CredLedger) { return $CredLedger }
    return (Join-Path $cacheBase 'credential-ledger.tsv')
}

function Get-CredLedgerAttempts([string]$Path, [string]$Key) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 0 }
    $header = 'key' + "`t" + 'service' + "`t" + 'endpoint' + "`t" + 'account' + "`t" + 'attempts' + "`t" + 'first_utc' + "`t" + 'last_utc'
    $lines = @(Get-Content -LiteralPath $Path)
    if (-not $lines.Count -or $lines[0] -cne $header) { throw 'Credential ledger has a foreign header.' }
    $found = $false
    $attempts = 0
    for ($i = 1; $i -lt $lines.Count; $i++) {
        if (-not $lines[$i]) { continue }
        $fields = $lines[$i] -split "`t"
        if ($fields[0] -ceq $Key) {
            if ($found -or $fields.Count -lt 7 -or $fields[4] -cnotmatch '^[0-9]{1,6}$') {
                throw 'Credential ledger has a corrupt or duplicate attempt row.'
            }
            $found = $true
            $attempts = [int]$fields[4]
        }
    }
    return $attempts
}

function Set-CredLedgerAttempts([string]$Path, [string]$Key, [int]$Attempts, [string]$First, [string]$Last, $Harden) {
    $header = 'key' + "`t" + 'service' + "`t" + 'endpoint' + "`t" + 'account' + "`t" + 'attempts' + "`t" + 'first_utc' + "`t" + 'last_utc'
    $lines = @(Get-Content -LiteralPath $Path)
    if ($lines[0] -cne $header) { throw 'Credential ledger has a foreign header.' }
    $seen = $false
    $out = New-Object System.Collections.ArrayList
    [void]$out.Add($header)
    for ($i = 1; $i -lt $lines.Count; $i++) {
        if (-not $lines[$i]) { continue }
        $fields = $lines[$i] -split "`t"
        if ($fields[0] -ceq $Key) {
            $fields[4] = [string]$Attempts
            $fields[6] = $Last
            $seen = $true
            [void]$out.Add(($fields -join "`t"))
        } else {
            [void]$out.Add($lines[$i])
        }
    }
    if (-not $seen) {
        [void]$out.Add(($Key, $CredService, "$CredHost`:$CredPort", (Get-CredMasked $CredAccount),
                        [string]$Attempts, $First, $Last) -join "`t")
    }
    Set-Content -LiteralPath $Path -Value $out -Encoding ASCII
    if ($Harden) { & $Harden $Path }
}

function Get-CredPolicy($AclCheck) {
    $basis = 'unverified-single-attempt'
    $allowed = 1
    $digest = ''
    if (-not $CredLockoutFile) { return @($basis, $allowed, $digest) }
    $item = Get-Item -LiteralPath $CredLockoutFile -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Lockout policy file must be a regular file and not a link.'
    }
    if ($AclCheck -and -not (& $AclCheck $CredLockoutFile)) {
        throw 'Lockout policy file is readable or writable by another principal.'
    }
    $threshold = 0
    foreach ($line in (Get-Content -LiteralPath $CredLockoutFile)) {
        if ($line -match '^\s*lockout_threshold\s*=\s*([0-9]{1,3})\s*$') { $threshold = [int]$Matches[1]; break }
    }
    if ($threshold -lt 1) { throw 'Lockout policy file needs an integer lockout_threshold.' }
    $digest = (Get-FileHash -LiteralPath $CredLockoutFile -Algorithm SHA256).Hash
    # A supplied file is useful context, but it does not verify the remote
    # endpoint's effective policy. Keep the per-account check to one attempt.
    return @("operator-policy-threshold-$threshold", 1, $digest)
}

function Test-CredEndpointReachable([string]$HostName, [int]$Port, [int]$TimeoutMs) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch { return $false }
    finally { $client.Close() }
}

if ($VerifyCredential) {
    if ($Cve -or $CveDetails -or $Poc) { throw 'Choose one CVE query or credential mode.' }
    if (-not $CredAccount -or -not $CredEndpoint) {
        throw 'Credential validation needs -CredAccount and -CredEndpoint.'
    }
    if ($CredAccount -cnotmatch '^[A-Za-z0-9._@\\-]+$' -or $CredAccount.Length -gt 256) { throw 'Invalid account name.' }
    if ($CredEndpoint -cnotmatch '^[A-Za-z0-9._-]+(:[0-9]+)?$' -or $CredEndpoint.Length -gt 259) { throw 'Invalid endpoint.' }
    $CredHost = $CredEndpoint
    $CredPort = 445
    if ($CredEndpoint -match ':([0-9]+)$') {
        $CredHost = $CredEndpoint.Substring(0, $CredEndpoint.LastIndexOf(':'))
        $CredPort = [int]$Matches[1]
    }
    if ($CredPort -lt 1 -or $CredPort -gt 65535) { throw 'Invalid endpoint port.' }
    if ($CredPort -ne 445) { throw 'The Windows SMB adapter supports only port 445.' }
    $CredKeySource = "$CredService|$($CredAccount.ToLowerInvariant())|$($CredHost.ToLowerInvariant())`:$CredPort"
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $credKey = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($CredKeySource))).Replace('-', '')
    } finally { $sha.Dispose() }
    $credNow = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $credMasked = Get-CredMasked $CredAccount
    $credLedgerPath = Get-CredLedgerPath
    $credLedgerDir = Split-Path -Parent $credLedgerPath
    if (-not $credLedgerDir) { $credLedgerDir = '.' }
    if (-not (Test-Path -LiteralPath $credLedgerDir)) {
        New-Item -ItemType Directory -Path $credLedgerDir -Force | Out-Null
    }
    $ledgerHeader = 'key' + "`t" + 'service' + "`t" + 'endpoint' + "`t" + 'account' + "`t" + 'attempts' + "`t" + 'first_utc' + "`t" + 'last_utc'
    $ledgerExists = Test-Path -LiteralPath $credLedgerPath
    if ($ledgerExists) {
        $existing = @(Get-Content -LiteralPath $credLedgerPath)
        if (-not $existing.Count -or $existing[0] -cne $ledgerHeader) { throw 'Credential ledger has a foreign header.' }
    } else {
        Set-Content -LiteralPath $credLedgerPath -Value $ledgerHeader -Encoding ASCII
    }
    Set-PrivateFile $credLedgerPath
    $policy = Get-CredPolicy { param($policyPath) Test-PrivateFileAcl $policyPath }
    $policyBasis = $policy[0]
    $policyAllowed = [int]$policy[1]
    $policyDigest = $policy[2]
    $credAttempts = Get-CredLedgerAttempts $credLedgerPath $credKey
    $credFirst = $credNow
    $credDir = Join-Path $OutputDir 'credentials'
    if (-not (Test-Path -LiteralPath $credDir)) { New-Item -ItemType Directory -Path $credDir -Force | Out-Null }
    Set-PrivateDirectory $credDir
    $credRunDir = Join-Path $credDir ("$credNow-$hostName-$PID")
    if (Test-Path -LiteralPath $credRunDir) { throw 'Credential result directory already exists.' }
    New-Item -ItemType Directory -Path $credRunDir | Out-Null
    Set-PrivateDirectory $credRunDir
    $credAttemptsPath = Join-Path $credRunDir 'attempts.tsv'
    $credAttemptsHeader = @('timestamp', 'service', 'endpoint', 'account', 'policy', 'policy_sha256', 'allowed', 'attempt', 'result') -join "`t"
    Set-Content -LiteralPath $credAttemptsPath -Value $credAttemptsHeader -Encoding ASCII
    Set-PrivateFile $credAttemptsPath
    function Write-CredAttempt([int]$Attempt, [string]$Result) {
        Add-Content -LiteralPath $credAttemptsPath -Encoding ASCII -Value (
            @($credNow, $CredService, "$CredHost`:$CredPort", $credMasked, $policyBasis,
              $policyDigest, [string]$policyAllowed, [string]$Attempt, $Result) -join "`t")
    }
    function Stop-Credential([int]$Code, [string]$Result) {
        Write-CredAttempt ($credAttempts + 1) $Result
        Write-Host "[SAVED] $credAttemptsPath"
        exit $Code
    }
    if ($credAttempts -ge $policyAllowed) {
        Write-Warning ("Refused {0} at {1}:{2}: {3} of {4} permitted attempts already recorded (policy {5}). No authentication was attempted." -f $credMasked, $CredHost, $CredPort, $credAttempts, $policyAllowed, $policyBasis)
        Stop-Credential 2 'limit-reached'
    }
    if (-not (Test-CredEndpointReachable $CredHost $CredPort ($CredTimeoutSeconds * 1000))) {
        Write-Warning "Cannot reach ${CredHost}:${CredPort}. No authentication was attempted."
        Stop-Credential 3 'endpoint-unreachable'
    }
    $credSecret = $null
    if ($CredSecretStdin) {
        $credSecret = [Console]::In.ReadLine()
    } else {
        $secure = Read-Host -AsSecureString -Prompt ("Secret for {0} at {1}:{2}" -f $credMasked, $CredHost, $CredPort)
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $credSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    if ([string]::IsNullOrEmpty($credSecret) -or $credSecret.Length -gt 1024) {
        $credSecret = $null
        throw 'Secret missing or longer than 1024 characters.'
    }
    $credName = $CredAccount
    $credDomain = $null
    if ($CredAccount.Contains('\')) { $parts = $CredAccount.Split('\', 2); $credDomain = $parts[0]; $credName = $parts[1] }
    elseif ($CredAccount.Contains('@')) { $parts = $CredAccount.Split('@', 2); $credDomain = $parts[1]; $credName = $parts[0] }
    if (-not ('EdamameWnet' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class EdamameWnet
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NETRESOURCE
    {
        public int dwScope;
        public int dwType;
        public int dwDisplayType;
        public int dwUsage;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpLocalName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpRemoteName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpComment;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpProvider;
    }

    [DllImport("mpr.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WNetAddConnection2W")]
    public static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

    [DllImport("mpr.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WNetCancelConnection2W")]
    public static extern int WNetCancelConnection2(string name, int flags, bool force);
}
'@
    }
    $resource = New-Object EdamameWnet+NETRESOURCE
    $resource.dwScope = 2                                   # CONNECT_TEMPORARY
    $resource.dwType = 1                                    # RESOURCETYPE_DISK
    $resource.dwDisplayType = 3                             # RESOURCEDISPLAYTYPE_SHARED
    $resource.dwUsage = 1                                   # RESOURCEUSAGE_CONNECTABLE
    $resource.lpRemoteName = ('\\{0}\IPC$' -f $CredHost)
    $resource.lpLocalName = $null
    $resource.lpComment = $null
    $resource.lpProvider = $null
    $credUser = if ($credDomain) { "$credDomain\$credName" } else { $credName }
    # Reserve under an OS file lock before authentication. A concurrent run or
    # interrupted process cannot turn an unknown result into a free retry.
    $credLockPath = "$credLedgerPath.lock"
    $credLockStream = $null
    $credLimitReached = $false
    try {
        try {
            $credLockStream = [IO.File]::Open($credLockPath, [IO.FileMode]::OpenOrCreate,
                                              [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        } catch { throw 'Credential ledger is busy; no authentication was attempted.' }
        Set-PrivateFile $credLockPath
        $credAttempts = Get-CredLedgerAttempts $credLedgerPath $credKey
        if ($credAttempts -ge $policyAllowed) {
            $credLimitReached = $true
        } else {
            $credAttempts = $credAttempts + 1
            Set-CredLedgerAttempts $credLedgerPath $credKey $credAttempts $credFirst $credNow { Set-PrivateFile $credLedgerPath }
        }
    } catch {
        $credSecret = $null
        throw
    } finally {
        if ($credLockStream) { $credLockStream.Dispose() }
    }
    if ($credLimitReached) {
        $credSecret = $null
        Write-Warning ("Refused {0} at {1}:{2}: {3} of {4} permitted attempts already recorded. No authentication was attempted." -f $credMasked, $CredHost, $CredPort, $credAttempts, $policyAllowed)
        Stop-Credential 2 'limit-reached'
    }
    $credCode = -1
    $credCancelCode = 0
    try {
        $credCode = [EdamameWnet]::WNetAddConnection2([ref]$resource, $credSecret, $credUser, 4) # CONNECT_TEMPORARY
    } catch {
        $credCode = -1
    } finally {
        $credSecret = $null
        if ($credCode -eq 0) {
            try { $credCancelCode = [EdamameWnet]::WNetCancelConnection2($resource.lpRemoteName, 0, $false) }
            catch { $credCancelCode = -1 }
        }
    }
    # 0 accepted, 1326 logon failure, 1331 disabled, 1327 disabled,
    # 1909 account locked out, 53/67/1219 network or path, 85 unknown share.
    $credResult = switch ($credCode) {
        0 { 'accepted' }
        1326 { 'rejected' }
        1327 { 'rejected' }
        1330 { 'rejected' }
        1331 { 'rejected' }
        1909 { 'rejected' }
        default { 'indeterminate' }
    }
    if ($credCode -eq 0 -and $credCancelCode -ne 0) {
        $credResult = 'indeterminate'
        Write-Warning ("SMB authentication succeeded, but the temporary connection could not be removed (code {0})." -f $credCancelCode)
    }
    $credRecord = if ($credCode -eq 0 -and $credCancelCode -ne 0) { "cleanup-failed-$credCancelCode" } else { [string]$credCode }
    Write-CredAttempt $credAttempts $credRecord
    if ($credResult -eq 'accepted') {
        Write-Host ("[CRED] Accepted: {0} at {1}:{2} over {3}. Attempt {4} of {5} (policy {6})." -f $credMasked, $CredHost, $CredPort, $CredService, $credAttempts, $policyAllowed, $policyBasis)
        Write-Host "[SAVED] $credAttemptsPath"
        exit 0
    }
    if ($credResult -eq 'rejected') {
        Write-Warning ("Rejected: {0} at {1}:{2} over {3}. Attempt {4} of {5} (policy {6})." -f $credMasked, $CredHost, $CredPort, $CredService, $credAttempts, $policyAllowed, $policyBasis)
        Write-Host "[SAVED] $credAttemptsPath"
        exit 1
    }
    Write-Warning ("Inconclusive: {0} at {1}:{2} returned {3}. Attempt {4} of {5} recorded; the authentication result is unknown." -f $credMasked, $CredHost, $CredPort, $credCode, $credAttempts, $policyAllowed)
    Write-Host "[SAVED] $credAttemptsPath"
    exit 3
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

function Ensure-EnumNative {
    if ('EdamameEnumNative' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class EdamameEnumProcess {
    internal IntPtr JobHandle;
    internal IntPtr ProcessHandle;
    internal EdamameEnumProcess(IntPtr job, IntPtr process) {
        JobHandle = job;
        ProcessHandle = process;
    }
    public bool HasExited() {
        uint wait = EdamameEnumNative.WaitForSingleObject(ProcessHandle, 0);
        if (wait == EdamameEnumNative.WAIT_OBJECT_0) return true;
        if (wait == EdamameEnumNative.WAIT_TIMEOUT) return false;
        throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed.");
    }
    public int ExitCode() {
        uint code;
        if (!EdamameEnumNative.GetExitCodeProcess(ProcessHandle, out code)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed.");
        }
        return unchecked((int)code);
    }
    public int ActiveProcesses() {
        return EdamameEnumNative.GetActiveProcesses(JobHandle);
    }
    public void Terminate() {
        if (JobHandle != IntPtr.Zero && !EdamameEnumNative.TerminateJobObject(JobHandle, 1)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed.");
        }
    }
    public void Close() {
        if (ProcessHandle != IntPtr.Zero) {
            EdamameEnumNative.CloseHandle(ProcessHandle);
            ProcessHandle = IntPtr.Zero;
        }
        if (JobHandle != IntPtr.Zero) {
            EdamameEnumNative.CloseHandle(JobHandle);
            JobHandle = IntPtr.Zero;
        }
    }
}

public static class EdamameEnumNative {
    internal const uint WAIT_OBJECT_0 = 0;
    internal const uint WAIT_TIMEOUT = 258;
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint CREATE_ALWAYS = 2;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public uint Flags;
        public short ShowWindow;
        public short Reserved2;
        public IntPtr Reserved2Ptr;
        public IntPtr StdInput;
        public IntPtr StdOutput;
        public IntPtr StdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr AttributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_THREAD_ATTRIBUTE_LIST {
        public IntPtr Reserved;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory,
        ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value,
        IntPtr size, IntPtr previous, IntPtr returnSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length,
        IntPtr returnLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeleteProcThreadAttributeList(IntPtr attributeList);

    private static void ThrowLastError(string operation) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), operation + " failed.");
    }
    private static bool IsInvalidHandle(IntPtr handle) {
        return handle == IntPtr.Zero || handle == new IntPtr(-1);
    }
    private static string Quote(string value) {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    public static EdamameEnumProcess Launch(string filePath, string arguments, string stdoutPath, string stderrPath) {
        IntPtr job = IntPtr.Zero;
        IntPtr stdin = IntPtr.Zero;
        IntPtr stdout = IntPtr.Zero;
        IntPtr stderr = IntPtr.Zero;
        IntPtr attributes = IntPtr.Zero;
        IntPtr process = IntPtr.Zero;
        IntPtr thread = IntPtr.Zero;
        GCHandle handles = new GCHandle();
        bool handlesPinned = false;
        try {
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (IsInvalidHandle(job)) ThrowLastError("CreateJobObjectW");
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            IntPtr limitsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
            try {
                Marshal.StructureToPtr(limits, limitsPtr, false);
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, limitsPtr,
                    (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)))) ThrowLastError("SetInformationJobObject");
            } finally { Marshal.FreeHGlobal(limitsPtr); }

            SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
            security.Length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            security.InheritHandle = 1;
            stdin = CreateFileW("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ref security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (IsInvalidHandle(stdin)) ThrowLastError("CreateFileW stdin");
            stdout = CreateFileW(stdoutPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ref security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (IsInvalidHandle(stdout)) ThrowLastError("CreateFileW stdout");
            stderr = CreateFileW(stderrPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ref security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (IsInvalidHandle(stderr)) ThrowLastError("CreateFileW stderr");

            IntPtr attributeSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeSize);
            if (attributeSize == IntPtr.Zero) ThrowLastError("InitializeProcThreadAttributeList size");
            attributes = Marshal.AllocHGlobal(attributeSize.ToInt32());
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref attributeSize)) ThrowLastError("InitializeProcThreadAttributeList");
            IntPtr[] inherited = new IntPtr[] { stdin, stdout, stderr };
            handles = GCHandle.Alloc(inherited, GCHandleType.Pinned);
            handlesPinned = true;
            IntPtr handleList = handles.AddrOfPinnedObject();
            if (!UpdateProcThreadAttribute(attributes, 0, new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST), handleList,
                new IntPtr(IntPtr.Size * inherited.Length), IntPtr.Zero, IntPtr.Zero)) ThrowLastError("UpdateProcThreadAttribute");

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.Flags = STARTF_USESTDHANDLES;
            startup.StartupInfo.StdInput = stdin;
            startup.StartupInfo.StdOutput = stdout;
            startup.StartupInfo.StdError = stderr;
            startup.AttributeList = attributes;
            StringBuilder commandLine = new StringBuilder(Quote(filePath) + (String.IsNullOrEmpty(arguments) ? "" : " " + arguments));
            PROCESS_INFORMATION info;
            if (!CreateProcessW(filePath, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null,
                ref startup, out info)) ThrowLastError("CreateProcessW");
            process = info.Process;
            thread = info.Thread;
            if (!AssignProcessToJobObject(job, process)) ThrowLastError("AssignProcessToJobObject");
            if (ResumeThread(thread) == 0xffffffff) ThrowLastError("ResumeThread");
            CloseHandle(thread);
            thread = IntPtr.Zero;
            CloseHandle(stdin);
            stdin = IntPtr.Zero;
            CloseHandle(stdout);
            stdout = IntPtr.Zero;
            CloseHandle(stderr);
            stderr = IntPtr.Zero;
            if (handlesPinned) { handles.Free(); handlesPinned = false; }
            if (attributes != IntPtr.Zero) { DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); attributes = IntPtr.Zero; }
            EdamameEnumProcess result = new EdamameEnumProcess(job, process);
            job = IntPtr.Zero;
            process = IntPtr.Zero;
            return result;
        } catch {
            if (process != IntPtr.Zero) {
                TerminateProcess(process, 1);
                CloseHandle(process);
            }
            if (thread != IntPtr.Zero) CloseHandle(thread);
            if (stdin != IntPtr.Zero) CloseHandle(stdin);
            if (stdout != IntPtr.Zero) CloseHandle(stdout);
            if (stderr != IntPtr.Zero) CloseHandle(stderr);
            if (handlesPinned) handles.Free();
            if (attributes != IntPtr.Zero) { DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
            if (job != IntPtr.Zero) CloseHandle(job);
            throw;
        }
    }

    internal static int GetActiveProcesses(IntPtr job) {
        int size = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try {
            if (!QueryInformationJobObject(job, 1, buffer, (uint)size, IntPtr.Zero)) return -1;
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info = (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(buffer,
                typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            return unchecked((int)info.ActiveProcesses);
        } finally { Marshal.FreeHGlobal(buffer); }
    }
}
'@ -Language CSharp -ErrorAction Stop
}

function Clear-EnumCaptureState([string]$OutputPath) {
    $suffix = '.stale.' + [Guid]::NewGuid().ToString('N')
    $paths = @(
        $OutputPath, "$OutputPath.stdout", "$OutputPath.stderr", "$OutputPath.pending",
        "$OutputPath.cancel", "$OutputPath.terminal.json", "$OutputPath.terminal.json.pending"
    )
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $destination = "$path$suffix"
        Move-Item -LiteralPath $path -Destination $destination -ErrorAction Stop
    }
}

function Publish-EnumTerminal([string]$Path, [string]$Status, [int]$ExitCode, [string]$LaunchId) {
    $allowed = @('checked', 'partial', 'timeout', 'partial-after-proof', 'cleanup-failed')
    if ($Status -notin $allowed) { throw "Invalid enumerator terminal status: $Status" }
    if ($LaunchId -notmatch '^[0-9a-f]{32}$') { throw 'Invalid enumerator launch ID.' }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            $existing = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            if ($existing.version -eq 1 -and $existing.status -in $allowed -and
                [string]$existing.exit_code -match '^-?[0-9]+$' -and $existing.launch_id -ceq $LaunchId) { return }
        } catch { }
        throw 'Enumerator terminal marker already exists and is invalid.'
    }
    $pending = "$Path.pending"
    $record = [pscustomobject]@{
        version = 1
        launch_id = $LaunchId
        status = $Status
        exit_code = $ExitCode
        published_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $record | ConvertTo-Json -Compress | Set-Content -LiteralPath $pending -Encoding ASCII
    try {
        [IO.File]::Move($pending, $Path)
    } catch {
        Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw }
    }
}

function Read-EnumTerminal($Entry) {
    if (-not (Test-Path -LiteralPath $Entry.Terminal -PathType Leaf)) { return $null }
    try {
        $marker = Get-Content -LiteralPath $Entry.Terminal -Raw | ConvertFrom-Json
        if ($marker.version -ne 1 -or $marker.launch_id -cne $Entry.LaunchId -or
            $marker.status -notin @('checked', 'partial', 'timeout', 'partial-after-proof', 'cleanup-failed')) { return $null }
        if ([string]$marker.exit_code -notmatch '^-?[0-9]+$') { return $null }
        return $marker
    } catch { return $null }
}

function Invoke-CapturedProcess([string]$FilePath, [string]$Arguments, [string]$OutputPath, [int]$TimeoutSeconds, [string]$LaunchId) {
    $stdout = "$OutputPath.stdout"
    $stderr = "$OutputPath.stderr"
    $cancelPath = "$OutputPath.cancel"
    $terminalPath = "$OutputPath.terminal.json"
    if (-not $LaunchId) { $LaunchId = [Guid]::NewGuid().ToString('N') }
    $windows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    $native = $null
    $process = $null
    $processStarted = $false
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutTask = $null
    $stderrTask = $null
    $finished = $false
    $timedOut = $false
    $cancelled = $false
    $cleanup = $false
    $exitCode = -1
    $errorText = $null
    $paths = @($stdout, $stderr)
    $offsets = [long[]]@(0, 0)
    $decoders = $null
    try {
        if ($windows) {
            if (-not [IO.Path]::IsPathRooted($FilePath)) { throw 'Enumerator executable path must be absolute.' }
            Ensure-EnumNative
            $native = [EdamameEnumNative]::Launch($FilePath, $Arguments, $stdout, $stderr)
        } else {
            $start = New-Object Diagnostics.ProcessStartInfo
            $start.FileName = $FilePath
            $start.Arguments = $Arguments
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            $process = New-Object Diagnostics.Process
            $process.StartInfo = $start
            $stdoutStream = New-Object IO.FileStream -ArgumentList @($stdout, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1)
            $stderrStream = New-Object IO.FileStream -ArgumentList @($stderr, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1)
            [void]$process.Start()
            $processStarted = $true
            $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
            $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        }
        if ($script:ShowRawOutput) {
            $encoding = [Console]::OutputEncoding
            $decoders = [Text.Decoder[]]@($encoding.GetDecoder(), $encoding.GetDecoder())
        }
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        while ($true) {
            if (Test-Path -LiteralPath $cancelPath -PathType Leaf) { $cancelled = $true; break }
            if ($windows) {
                $rootExited = $native.HasExited()
                $active = $native.ActiveProcesses()
                if ($active -lt 0) { throw 'Could not query the enumerator Job Object.' }
                if ($rootExited -and $active -eq 0) { $finished = $true; break }
            } else {
                $finished = $process.HasExited
                if ($finished) { break }
            }
            if ([DateTime]::UtcNow -ge $deadline) { $timedOut = $true; break }
            if ($script:ShowRawOutput) {
                Write-CapturedTail $paths $offsets $decoders
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $finished) {
            if ($windows) {
                $native.Terminate()
                $graceDeadline = [DateTime]::UtcNow.AddSeconds(5)
                do {
                    $active = $native.ActiveProcesses()
                    if ($active -eq 0) { break }
                    if ([DateTime]::UtcNow -ge $graceDeadline) { throw 'Enumerator Job Object did not close its process tree.' }
                    Start-Sleep -Milliseconds 100
                } while ($true)
            } else {
                if (-not $process.HasExited) { $process.Kill() }
                [void]$process.WaitForExit(5000)
                if (-not $process.HasExited) { throw 'Enumerator process did not exit after termination.' }
            }
        }
        if ($windows) {
            $exitCode = $native.ExitCode()
            $native.Close()
            $native = $null
        } else {
            if (-not $stdoutTask.Wait(5000) -or -not $stderrTask.Wait(5000)) {
                throw 'Capture streams did not finish after the process exited.'
            }
            $exitCode = if ($finished) { $process.ExitCode } else { -1 }
        }
        if ($script:ShowRawOutput) { Write-CapturedTail $paths $offsets $decoders }
        $cleanup = $true
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        if ($native) {
            try { $native.Terminate() } catch { }
            try { $native.Close() } catch { }
        }
        if ($process -and $processStarted -and -not $process.HasExited) { try { $process.Kill() } catch { } }
        if ($stdoutStream) { $stdoutStream.Dispose() }
        if ($stderrStream) { $stderrStream.Dispose() }
        if ($process) { $process.Dispose() }
    }
    if (-not $cleanup) {
        Remove-Item -LiteralPath "$OutputPath.pending", $OutputPath -Force -ErrorAction SilentlyContinue
        try { Publish-EnumTerminal $terminalPath 'cleanup-failed' -1 $LaunchId } catch { }
        if ($errorText) { Write-Warning "$([IO.Path]::GetFileName($FilePath)) capture failed: $errorText" }
        return 'cleanup-failed'
    }
    $status = if ($cancelled) { 'partial-after-proof' }
        elseif ($timedOut) { 'timeout' }
        elseif ($exitCode -ne 0) { 'partial' }
        else { 'checked' }
    $pending = "$OutputPath.pending"
    try {
        $destination = [IO.File]::Create($pending)
        try {
            foreach ($part in @($stdout, $stderr)) {
                if (Test-Path -LiteralPath $part) {
                    $source = [IO.File]::OpenRead($part)
                    try { $source.CopyTo($destination) } finally { $source.Dispose() }
                }
            }
        } finally { $destination.Dispose() }
        [IO.File]::Move($pending, $OutputPath)
        Publish-EnumTerminal $terminalPath $status $exitCode $LaunchId
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    } catch {
        Remove-Item -LiteralPath $pending, $OutputPath -Force -ErrorAction SilentlyContinue
        try { Publish-EnumTerminal $terminalPath 'cleanup-failed' -1 $LaunchId } catch { }
        Write-Warning "$([IO.Path]::GetFileName($FilePath)) capture merge failed: $($_.Exception.Message)"
        return 'cleanup-failed'
    }
    if ($timedOut) {
        Write-Warning "$([IO.Path]::GetFileName($FilePath)) exceeded $TimeoutSeconds seconds; preserving partial output."
    }
    return $status
}

function Start-EnumJob([string]$Name, [string]$FilePath, [string]$Arguments, [string]$OutputPath) {
    Clear-EnumCaptureState $OutputPath
    $launchId = [Guid]::NewGuid().ToString('N')
    $definition = ${function:Invoke-CapturedProcess}.ToString()
    $nativeDefinition = ${function:Ensure-EnumNative}.ToString()
    $terminalDefinition = ${function:Publish-EnumTerminal}.ToString()
    $job = Start-Job -ScriptBlock {
        param($command, $arguments, $path, $limit, $launch, $source, $nativeSource, $terminalSource)
        . ([scriptblock]::Create("function Ensure-EnumNative { $nativeSource }"))
        . ([scriptblock]::Create("function Publish-EnumTerminal { $terminalSource }"))
        . ([scriptblock]::Create("function Invoke-CapturedProcess { $source }"))
        $script:ShowRawOutput = $false
        Invoke-CapturedProcess $command $arguments $path $limit $launch
    } -ArgumentList $FilePath, $Arguments, $OutputPath, $ToolTimeoutSeconds, $launchId, $definition, $nativeDefinition, $terminalDefinition
    return @{
        Name = $Name
        Job = $job
        Output = $OutputPath
        Cancel = "$OutputPath.cancel"
        Terminal = "$OutputPath.terminal.json"
        LaunchId = $launchId
        Deadline = [DateTime]::UtcNow.AddSeconds($ToolTimeoutSeconds)
        GraceSeconds = 5
        Offset = [long]0
        Stopped = $false
        Status = $null
    }
}

function Stop-EnumJob($Entry) {
    if (Read-EnumTerminal $Entry) { return }
    if (-not (Test-Path -LiteralPath $Entry.Cancel -PathType Leaf)) {
        try { Set-Content -LiteralPath $Entry.Cancel -Value 'cancel' -Encoding ASCII }
        catch { if (-not (Test-Path -LiteralPath $Entry.Cancel -PathType Leaf)) { throw } }
    }
    if (Read-EnumTerminal $Entry) { return }
    $Entry.Stopped = $true
    $Entry.Status = 'cancel-requested'
}

function Complete-EnumJob($Entry) {
    $limit = $Entry.Deadline.AddSeconds([int]$Entry.GraceSeconds)
    while (-not (Read-EnumTerminal $Entry) -and [DateTime]::UtcNow -lt $limit) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Read-EnumTerminal $Entry)) {
        Stop-EnumJob $Entry
        while (-not (Read-EnumTerminal $Entry) -and [DateTime]::UtcNow -lt $limit) {
            Start-Sleep -Milliseconds 100
        }
    }
    if (-not (Read-EnumTerminal $Entry)) {
        Stop-Job -Job $Entry.Job -ErrorAction SilentlyContinue
    }
    $marker = Read-EnumTerminal $Entry
    if ($marker) {
        $Entry.Status = [string]$marker.status
        Receive-Job -Job $Entry.Job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
        if ($Entry.Status -eq 'cleanup-failed') {
            Remove-Item -LiteralPath $Entry.Output, "$($Entry.Output).pending" -Force -ErrorAction SilentlyContinue
        } elseif (-not (Test-Path -LiteralPath $Entry.Output -PathType Leaf)) {
            $Entry.Status = 'cleanup-failed'
        }
    } else {
        $Entry.Status = 'cleanup-failed'
        Remove-Item -LiteralPath $Entry.Output, "$($Entry.Output).pending" -Force -ErrorAction SilentlyContinue
        Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
    }
    return $Entry.Status
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
        $privescJob = Start-EnumJob 'privesccheck' (Get-TrustedPowerShell) "/NoProfile /ExecutionPolicy Bypass /EncodedCommand $encodedCheck" `
            (Join-Path $capture 'privesccheck-output.txt')
        $enumJobs += $privescJob
    } catch {
        Write-Warning "PrivescCheck failed: $($_.Exception.Message)"
        Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "privesccheck`tpartial"
    }
}

# Native prerequisites are independent of enumerator prose, so test them as
# soon as the background collectors start. Enumerator CVEs remain review-only.
$enumLifecycleComplete = $false
$enumCleanupFailed = $false
try {
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
if ($fastRecipe -eq 'weak-service-lab' -and $enumJobs.Count -gt 0) {
    Write-Host '[RECIPE] Waiting for collectors before the named-pipe service proof.'
    $fastRecipe = $null
}
if ($fastRecipe) {
    Write-Finding 'local-elevation' "$fastRecipe prerequisites independently verified while enumeration runs"
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
$watchDeadline = [DateTime]::UtcNow
foreach ($entry in $enumJobs) {
    if ($entry.Deadline.AddSeconds([int]$entry.GraceSeconds) -gt $watchDeadline) {
        $watchDeadline = $entry.Deadline.AddSeconds([int]$entry.GraceSeconds)
    }
}
while (@($enumJobs | Where-Object { $_.Job.State -in @('NotStarted', 'Running') }).Count -gt 0 -and
    [DateTime]::UtcNow -lt $watchDeadline) {
    foreach ($entry in $enumJobs) { Watch-EnumOutput $entry $liveCves }
    if ($liveCves.Count -gt $lastLiveCount) {
        Write-Finding 'cve-candidates' "$($liveCves.Count) suggested so far; review exact build and patch status"
        $lastLiveCount = $liveCves.Count
    }
    Start-Sleep -Milliseconds 250
}
foreach ($entry in @($enumJobs | Where-Object { $_.Job.State -in @('NotStarted', 'Running') })) {
    Stop-EnumJob $entry
}
foreach ($entry in $enumJobs) { Watch-EnumOutput $entry $liveCves }

$sharpStatus = if ($sharpJob) { Complete-EnumJob $sharpJob } else { 'unavailable' }
if ($sharpJob) {
    $sharpCollectedZip = Get-ChildItem -LiteralPath $sharpOut -Filter '*sharphound.zip' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $zipStatus = if ($sharpStatus -eq 'cleanup-failed') { 'cleanup-failed' }
        elseif (-not $sharpCollectedZip) { 'partial-no-zip' }
        elseif ($sharpStatus -eq 'checked') { 'checked' } else { 'partial-zip' }
    if ($sharpStatus -ne 'checked') { $sharpCollectedZip = $null }
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "sharphound`t$zipStatus"
}
$winpeasStatus = if ($winpeasJob) { Complete-EnumJob $winpeasJob } else { 'unavailable' }
$winpeasOk = $winpeasStatus -eq 'checked'
if ($winpeasJob) { Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "winpeas`t$winpeasStatus" }
if (-not $winpeasOk -and $winpeasStatus -ne 'cleanup-failed' -and $haveBat -and (-not $fastSuccessRecipe -or $NoShell -or $FinishBgEnum)) {
    Write-Host '[ENUM] WinPEAS batch fallback.'
    $binaryOutput = Join-Path $capture 'winpeas-output.txt'
    if (Test-Path -LiteralPath $binaryOutput) {
        Move-Item -LiteralPath $binaryOutput -Destination (Join-Path $capture 'winpeas-binary-partial.txt')
    }
    try {
        Clear-EnumCaptureState $binaryOutput
        $trustedCmd = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
        if (-not (Test-TrustedSystemBinary $trustedCmd)) { throw 'System command interpreter verification failed.' }
        $status = Invoke-CapturedProcess $trustedCmd "/d /c `"$winpeasBat`"" $binaryOutput $ToolTimeoutSeconds
        $winpeasOk = $status -eq 'checked'
        $status = if ($winpeasOk) { 'batch-fallback' } else { "batch-$status" }
        if ($status -eq 'batch-cleanup-failed') { $winpeasStatus = 'cleanup-failed' }
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
$enumCleanupFailed = $sharpStatus -eq 'cleanup-failed' -or $winpeasStatus -eq 'cleanup-failed' -or $privescStatus -eq 'cleanup-failed'
$enumLifecycleComplete = $true
} finally {
    if (-not $enumLifecycleComplete) {
        foreach ($entry in $enumJobs) {
            try {
                $entry.Deadline = [DateTime]::UtcNow
                Stop-EnumJob $entry
            } catch { }
        }
        foreach ($entry in $enumJobs) {
            try {
                if ((Complete-EnumJob $entry) -eq 'cleanup-failed') { $enumCleanupFailed = $true }
            } catch { $enumCleanupFailed = $true }
        }
    }
}

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
    $serviceKeys = @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop)
    $unquotedCount = 0
    $unreadableCount = 0
    foreach ($serviceKey in $serviceKeys) {
        try {
            $service = Get-ItemProperty -LiteralPath $serviceKey.PSPath -ErrorAction Stop
        } catch {
            $unreadableCount++
            continue
        }
        if ([string]$service.ObjectName -match '^(LocalSystem|NT AUTHORITY\\(LocalService|NetworkService))$' -and
            [string]$service.ImagePath -match '^\s*[^"\s][^" ]* [^"].*\.exe') {
            $unquotedCount++
        }
    }
    if ($unquotedCount -gt 0) {
        Write-Finding 'service-paths' "$unquotedCount privileged unquoted paths; check writable segments before use"
    }
    if ($unreadableCount -gt 0) { Write-Warning "$unreadableCount service definitions could not be read." }
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

$suggestedCves = @(Get-SuggestedCves $capture $liveCves)
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
    Write-Finding 'local-elevation' 'Exact weak-service fixture prerequisites verified; SYSTEM proof requires a successful attempt'
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

# Name the individual checklist sub-items, so the record states which specific
# conditions were addressed instead of leaving a reader to infer them from a
# parent row. Each carries its own status; none inherits a parent claim.
$hostSubItems = @(
    'Check OS version, hostname, IP and distribution.',
    'What user are we? User enumeration.',
    'List of files that could potentially contain passwords or other sensitive information:',
    'Search for passwords in the REGISTRY:',
    'Check if any patches or hotfixes are installed:',
    'Installed applications')
foreach ($area in $hostSubItems) {
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`t$enumStatus`texternal enumerator output only; this specific condition is not independently verified"
}
$domainSubItems = @(
    'Machine Account Quota, SMB / LDAP Signing',
    'Enabled Local Guest account on every machine + Enabled domain guest account',
    'GPP Password', 'ASREP Roasting', 'Kerberoasting (every account including computers too)',
    'Pre2k machines', 'Poisoning attacks (always run in ANALYZE mode first)',
    'MITM attacks (last resort for IPv6 poisoning)', 'Coercion attacks (DFSCoerce)',
    'Snaffler (SMB Shares)', 'Pass the password', 'Pass the hash',
    'Local Admin Password reuse / blank password', 'Delegations',
    'Enumerate DACLs + RBCD + Shadow creds', 'Group Policy', 'OUs', 'ADCS', 'IIS', 'WSUS',
    'Exchange CVEs + Open SMTP Relay',
    'MSSQL (impersonation, relay ntlmv2 hash, sql links, xp_cmdshell, external scripts enabled, sql server agent jobs, trustworthy databases, mssql privesc)',
    'Ntlmv1 https://github.com/fox-it/cve-2019-1040-scanner',
    'Easier way, perform an LM downgrade with Responder', 'SMBv1',
    'NTLM Relaying (SMB to SMB, SMB to HTTP, HTTP to LDAP, Reflection)',
    'CVEs: ZeroLogon, PrintNightmare, NoPAC, BadSuccessor, smbghost',
    'Privileged groups', 'Tombstone objects (who has reanimate rights)',
    'StrongCertificateBindingEnforcement reg key not set to 2', 'Defender Exclusions',
    'Forests/Trusts')
foreach ($area in $domainSubItems) {
    $status = if ($domainJoined) { 'unsupported' } else { 'inapplicable' }
    Add-Content -LiteralPath (Join-Path $runDir 'coverage.tsv') -Value "$area`t$status`tdomain sub-item with no reviewed automatic recipe; the parent Active Directory row does not assert it"
}

# A failed collector run cannot publish named raw output, ZIP output, or a
# success marker. The collector rows above remain private run evidence.
if ($enumCleanupFailed) {
    Write-Warning 'Enumerator cleanup failed; no final collector output or success marker was published.'
    exit 1
}

# Alerts above precede these final output filenames.
$confirmedRaw = @{}
if ($winpeasStatus -ne 'cleanup-failed') { $confirmedRaw['winpeas-output.txt'] = $true }
if ($privescStatus -ne 'cleanup-failed') { $confirmedRaw['privesccheck-output.txt'] = $true }
if ($sharpStatus -ne 'cleanup-failed') { $confirmedRaw['sharphound-output.txt'] = $true }
if ($winpeasStatus -ne 'cleanup-failed' -and (Test-Path -LiteralPath (Join-Path $capture 'winpeas-binary-partial.txt'))) {
    $confirmedRaw['winpeas-binary-partial.txt'] = $true
}
foreach ($name in @('winpeas-output.txt', 'winpeas-binary-partial.txt', 'privesccheck-output.txt', 'sharphound-output.txt')) {
    if (-not $confirmedRaw.ContainsKey($name)) { continue }
    $from = Join-Path $capture $name
    if (Test-Path -LiteralPath $from) {
        Move-Item -LiteralPath $from -Destination (Join-Path $runDir $name)
        Write-Host "[SAVED] $name"
    }
}
if ($sharpStatus -eq 'checked' -and $sharpCollectedZip -and (Test-Path -LiteralPath $sharpCollectedZip.FullName)) {
    Move-Item -LiteralPath $sharpCollectedZip.FullName -Destination (Join-Path $runDir 'sharphound.zip')
    Write-Host '[SAVED] sharphound.zip'
}
$suggestedCves | ForEach-Object { "$_`thttps://www.cve.org/CVERecord?id=$_" } |
    Set-Content -LiteralPath (Join-Path $runDir 'cve-candidates.tsv') -Encoding ASCII
Write-CveIndex $CatalogDir $suggestedCves (Join-Path $runDir 'cve-index.tsv')
$detailLines = @("cve`tstate`tdescription`taffected_json`treferences_json`treview_state`tsource_json")
$detailLines += @(Get-CveDetailsLines $CatalogDir $suggestedCves)
if (@($detailLines | Where-Object { ($_ -split "`t")[5] -eq 'integrity-failed' }).Count) {
    Write-Warning 'Offline CVE details failed integrity checks; withholding affected details.'
}
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
