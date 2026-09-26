$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
$originalLocalAppData = $env:LOCALAPPDATA
try {
    Remove-Item Env:LOCALAPPDATA -ErrorAction SilentlyContinue
    $missingEnvQuery = @(& $source -Cve 'CVE-2021-44228')
    if ($missingEnvQuery.Count -lt 2 -or $missingEnvQuery[1] -notmatch 'published-general') {
        throw 'Direct lookup failed without LOCALAPPDATA'
    }
} finally {
    if ($null -eq $originalLocalAppData) { Remove-Item Env:LOCALAPPDATA -ErrorAction SilentlyContinue }
    else { $env:LOCALAPPDATA = $originalLocalAppData }
}
if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = [IO.Path]::GetTempPath() }
$directCve = @(& $source -Cve 'CVE-2021-36934')
if ($directCve.Count -lt 2 -or $directCve[1] -notmatch 'indexed-review-only\twindows') {
    throw 'Direct CVE lookup failed'
}
$directCurated = @(& $source -Cve 'CVE-2023-4911')
if ($directCurated.Count -lt 2 -or $directCurated[1] -notmatch 'indexed-review-only\tlinux\tglibc') {
    throw 'Curated CVE lookup failed'
}
$directGeneral = @(& $source -Cve 'CVE-2021-44228')
if ($directGeneral.Count -lt 2 -or $directGeneral[1] -notmatch 'published-general') {
    throw 'General CVE lookup failed'
}
$directDetails = @(& $source -CveDetails 'CVE-2025-32463')
if ($directDetails.Count -lt 2 -or $directDetails[1] -notmatch 'source-metadata-unreviewed' -or
    $directDetails[1] -notmatch '"lessThan":"1\.9\.17p1"') {
    throw 'Sparse CVE detail lookup failed'
}
$generalDetails = @(& $source -CveDetails 'CVE-2021-44228')
if ($generalDetails.Count -lt 2 -or $generalDetails[1] -notmatch 'details-not-installed') {
    throw 'General CVE detail guard failed'
}
$directPoc = @(& $source -Poc 'CVE-2025-32463')
if ($directPoc.Count -lt 2 -or $directPoc[1] -notmatch 'verified-bundle') {
    throw 'Direct PoC lookup failed'
}
foreach ($name in @('Get-FileHash', 'Get-CatalogEntries', 'Get-GeneralCveState', 'Test-CveDetailsCatalog',
    'Get-CveDetailsLine', 'Get-AllCveDetailsCatalog', 'Get-CveDetailBucket', 'Read-CveDetailShard',
    'Get-CveDetailsLines', 'Get-SuggestedCves', 'Write-CveIndex')) {
    $fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $curatedOnly = Join-Path $testRoot 'curated-only'
    Copy-Item -LiteralPath (Join-Path $root 'catalog') -Destination $curatedOnly -Recurse
    Remove-Item -LiteralPath (Join-Path $curatedOnly 'local-eop.tsv')
    $curatedQuery = @(& $source -Cve 'CVE-2023-4911' -CatalogDir $curatedOnly)
    if ($curatedQuery[1] -notmatch 'indexed-review-only\tlinux\tglibc') {
        throw 'Curated-only direct lookup failed'
    }
    $curatedIndex = Join-Path $testRoot 'curated-index.tsv'
    Write-CveIndex $curatedOnly @('CVE-2023-4911') $curatedIndex
    $curatedRow = @(Import-Csv -LiteralPath $curatedIndex -Delimiter "`t")[0]
    if ($curatedRow.status -ne 'platform-mismatch' -or $curatedRow.product -ne 'glibc') {
        throw 'Curated-only scan index failed'
    }
    Remove-Item -LiteralPath (Join-Path $curatedOnly 'curated-eop.tsv')
    $generalIndex = Join-Path $testRoot 'general-index.tsv'
    Write-CveIndex $curatedOnly @('CVE-2023-4911') $generalIndex
    $generalRow = @(Import-Csv -LiteralPath $generalIndex -Delimiter "`t")[0]
    if ($generalRow.status -ne 'published-general') { throw 'General CVE fallback failed' }
    $tampered = Join-Path $testRoot 'tampered'
    Copy-Item -LiteralPath (Join-Path $root 'catalog') -Destination $tampered -Recurse
    Get-ChildItem -LiteralPath $tampered -Recurse -File | ForEach-Object { $_.IsReadOnly = $false }
    Add-Content -LiteralPath (Join-Path $tampered 'curated-eop.tsv') -Value "CVE-2025-32463`twindows`tincorrect-duplicate`t`thttps://example.invalid/"
    $duplicateIndex = Join-Path $testRoot 'duplicate-index.tsv'
    Write-CveIndex $tampered @('CVE-2025-32463') $duplicateIndex
    $duplicateRow = @(Import-Csv -LiteralPath $duplicateIndex -Delimiter "`t")[0]
    if ($duplicateRow.platform -ne 'linux' -or $duplicateRow.product -ne 'Sudo') { throw 'Base catalog precedence failed' }
    Remove-Item -LiteralPath (Join-Path $tampered 'local-eop-details.tsv')
    $missingDetails = @(& $source -CveDetails 'CVE-2025-32463' -CatalogDir $tampered)
    if ($missingDetails[1] -notmatch 'details-not-installed') { throw 'Missing detail sidecar was inferred' }
    Copy-Item -LiteralPath (Join-Path $root 'catalog/local-eop-details.tsv') -Destination (Join-Path $tampered 'local-eop-details.tsv')
    Add-Content -LiteralPath (Join-Path $tampered 'local-eop-details.tsv') -Value 'tampered'
    $detailRejected = $false
    try { & $source -CveDetails 'CVE-2025-32463' -CatalogDir $tampered | Out-Null }
    catch { $detailRejected = $true }
    if (-not $detailRejected) { throw 'Tampered CVE details were accepted' }
    Set-Content -LiteralPath (Join-Path $tampered 'pocs/CVE-2025-32463/sudo-chwoot.sh') -Value 'tampered'
    $rejected = $false
    try { & $source -Poc 'CVE-2025-32463' -CatalogDir $tampered | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Tampered PoC was accepted' }
    $destination = Join-Path $testRoot 'cve-index.tsv'
    Write-CveIndex (Join-Path $root 'catalog') @('CVE-2021-36934', 'CVE-2025-32463', 'CVE-2023-4911', 'CVE-2099-99999') $destination
    $rows = @(Import-Csv -LiteralPath $destination -Delimiter "`t")
    if ($rows.Count -ne 4) { throw 'Wrong CVE row count' }
    if ($rows[0].status -ne 'indexed-review-only' -or $rows[0].platform -ne 'windows') { throw 'Windows match failed' }
    if ($rows[1].status -ne 'platform-mismatch' -or $rows[1].platform -ne 'linux') { throw 'Platform guard failed' }
    if ($rows[2].status -ne 'platform-mismatch' -or $rows[2].product -ne 'glibc') { throw 'Curated platform guard failed' }
    if ($rows[3].status -ne 'unindexed') { throw 'Unknown CVE state failed' }
    $complete = Join-Path $testRoot 'complete'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures/cve-details/catalog') -Destination $complete -Recurse
    $detailSource = Get-Content -LiteralPath (Join-Path $complete 'all-cve-details-source.json') -Raw | ConvertFrom-Json
    $generation = Join-Path (Join-Path $complete 'all-cve-details') $detailSource.shards_sha256
    $longId = 'CVE-2020-9999999999999999999'
    foreach ($id in @('CVE-2020-0001', 'CVE-2020-01000', 'CVE-2020-1999', $longId)) {
        $query = @(& $source -CveDetails $id -CatalogDir $complete)
        if ($query.Count -ne 2 -or $query[1] -notmatch 'source-metadata-unreviewed') { throw "Complete sidecar query failed: $id" }
        $fields = $query[1].Split([char]9)
        if ($fields.Count -ne 7) { throw 'Complete detail column count failed' }
        $projection = $fields[6] | ConvertFrom-Json
        if ($projection.cveMetadata.cveId -cne $id) { throw 'Source projection ID failed' }
        if ($id -eq 'CVE-2020-0001') {
            if ($fields[2] -notmatch '\\u00e9' -or $fields[2] -notmatch '\\u0000' -or
                $projection.containers.adp[0].affected[0].versions[0].status -ne 'unaffected') { throw 'CNA/ADP projection or escaping failed' }
        }
        if ($id -eq 'CVE-2020-01000' -and $projection.containers.cna.replacedBy[0] -ne 'CVE-2020-0001') { throw 'Rejected replacement lost' }
        if ($id -eq 'CVE-2020-1999' -and ($fields[1] -ne 'reserved' -or $fields[2] -ne '')) { throw 'Reserved details invented' }
    }
    $idOnly = @(& $source -Cve 'CVE-2020-0001' -CatalogDir $complete)
    if ($idOnly[1] -notmatch 'published-general') { throw 'ID-only catalog lookup failed' }
    # A broken unused shard cannot prevent unrelated lookups or startup.
    Remove-Item -LiteralPath (Join-Path $generation '2021/1.tsv.gz')
    $script:detailReads = 0
    $script:originalDetailReader = ${function:Read-CveDetailShard}
    function Read-CveDetailShard([string]$Root, [string]$Relative, [hashtable]$Entry, [hashtable]$Wanted) {
        $script:detailReads++
        & $script:originalDetailReader $Root $Relative $Entry $Wanted
    }
    $batch = @(Get-CveDetailsLines $complete @('CVE-2020-0001', 'CVE-2020-0002'))
    if ($batch.Count -ne 2 -or $script:detailReads -ne 1 -or $batch[0] -notmatch 'source-metadata-unreviewed') { throw 'Batch did not read exactly one touched shard' }
    $missingRejected = $false
    try { & $source -CveDetails 'CVE-2021-1000' -CatalogDir $complete | Out-Null } catch { $missingRejected = $true }
    if (-not $missingRejected) { throw 'Missing installed shard accepted' }
    $touched = Join-Path $generation '2020/0.tsv.gz'
    [IO.File]::WriteAllBytes($touched, [byte[]]@(31, 139, 8))
    $badBatch = @(Get-CveDetailsLines $complete @('CVE-2020-0001', 'CVE-2020-01000'))
    if ($badBatch.Count -ne 2 -or @($badBatch | Where-Object { $_ -match 'integrity-failed' }).Count -ne 1 -or
        @($badBatch | Where-Object { $_ -match 'source-metadata-unreviewed' }).Count -ne 1) { throw 'Batch did not isolate a corrupt shard' }
    $corruptRejected = $false
    try { & $source -CveDetails 'CVE-2020-0001' -CatalogDir $complete | Out-Null } catch { $corruptRejected = $true }
    if (-not $corruptRejected) { throw 'Corrupt installed shard accepted' }
    Remove-Item -LiteralPath (Join-Path $complete 'all-cve-details/installed')
    $absent = @(& $source -CveDetails 'CVE-2020-0001' -CatalogDir $complete)
    if ($absent[1] -notmatch 'details-not-installed') { throw 'Source-clone sidecar fallback failed' }
    $capture = Join-Path $testRoot 'capture'
    New-Item -ItemType Directory -Path $capture | Out-Null
    Set-Content -LiteralPath (Join-Path $capture 'winpeas-output.txt') -Value 'cVe-2020-0001'
    Set-Content -LiteralPath (Join-Path $capture 'winpeas-binary-partial.txt') -Value 'cve-2020-0002 synthetic-private-value'
    Set-Content -LiteralPath (Join-Path $capture 'privesccheck-output.txt') -Value 'cVe-2020-0001'
    Set-Content -LiteralPath (Join-Path $capture 'sharphound-output.txt') -Value 'CvE-2020-01000'
    $suggested = @(Get-SuggestedCves $capture @{ 'cve-2020-1999' = $true; 'CVE-2020-0001' = $true })
    if ($suggested.Count -ne 4 -or $suggested -notcontains 'CVE-2020-0002' -or $suggested -notcontains 'CVE-2020-1999' -or
        ($suggested -join '') -match 'synthetic-private-value') { throw 'Partial/live collector CVE union failed' }
    if (@($suggested | Where-Object { $_ -cnotmatch '^CVE-[0-9]{4}-[0-9]{4,19}$' }).Count) { throw 'Candidate ID casing was not normalized' }
    $caseDetails = @(Get-CveDetailsLines (Join-Path $PSScriptRoot 'fixtures/cve-details/catalog') $suggested)
    if ($caseDetails.Count -ne 4 -or @($caseDetails | Where-Object { $_ -notmatch 'source-metadata-unreviewed' }).Count) {
        throw 'Mixed-case partial/live candidates failed the complete detail batch'
    }
    'PowerShell mixed-case partial/live candidate detail batch passed'
    'PowerShell offline CVE join, complete sidecar, partial-output union and platform guard passed'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
