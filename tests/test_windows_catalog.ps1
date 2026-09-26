$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
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
if ($generalDetails.Count -lt 2 -or $generalDetails[1] -notmatch 'not-in-local-details') {
    throw 'General CVE detail guard failed'
}
$directPoc = @(& $source -Poc 'CVE-2025-32463')
if ($directPoc.Count -lt 2 -or $directPoc[1] -notmatch 'verified-bundle') {
    throw 'Direct PoC lookup failed'
}
foreach ($name in @('Get-CatalogEntries', 'Get-GeneralCveState', 'Write-CveIndex')) {
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
    if ($missingDetails[1] -notmatch 'not-in-local-details') { throw 'Missing detail sidecar was inferred' }
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
    'PowerShell offline CVE join and platform guard passed'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
