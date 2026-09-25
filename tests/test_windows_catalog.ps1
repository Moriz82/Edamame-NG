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
$directPoc = @(& $source -Poc 'CVE-2025-32463')
if ($directPoc.Count -lt 2 -or $directPoc[1] -notmatch 'verified-bundle') {
    throw 'Direct PoC lookup failed'
}
foreach ($name in @('Get-CatalogEntries', 'Write-CveIndex')) {
    $fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $tampered = Join-Path $testRoot 'tampered'
    Copy-Item -LiteralPath (Join-Path $root 'catalog') -Destination $tampered -Recurse
    Add-Content -LiteralPath (Join-Path $tampered 'curated-eop.tsv') -Value "CVE-2025-32463`twindows`tincorrect-duplicate`t`thttps://example.invalid/"
    $duplicateIndex = Join-Path $testRoot 'duplicate-index.tsv'
    Write-CveIndex $tampered @('CVE-2025-32463') $duplicateIndex
    $duplicateRow = @(Import-Csv -LiteralPath $duplicateIndex -Delimiter "`t")[0]
    if ($duplicateRow.platform -ne 'linux' -or $duplicateRow.product -ne 'Sudo') { throw 'Base catalog precedence failed' }
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
