param([Parameter(Mandatory = $true)][string]$ArchivePath)
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
foreach ($name in @('Set-PrivateDirectory', 'Expand-VerifiedZip', 'Test-PsExecAsset', 'Get-PsExecAsset', 'Get-TrustedPowerShell', 'New-ProofMarker')) {
    $fn = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}

$archiveSource = (Get-Item -LiteralPath $ArchivePath -ErrorAction Stop).FullName
$testRoot = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
$runDir = Join-Path $testRoot 'run'
$capture = Join-Path $runDir '.capture'
$cacheBase = Join-Path $testRoot 'cache'
$ToolDir = $null
$Resume = $false
$script:offline = $false
foreach ($dir in @($capture, $cacheBase)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
Set-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value ''
function Invoke-WebRequest {
    param([string]$Uri, [switch]$UseBasicParsing, [string]$OutFile, [int]$TimeoutSec)
    if ($script:offline) { throw 'synthetic offline mode' }
    if ($Uri -ne 'https://download.sysinternals.com/files/PSTools.zip') { throw "Unexpected URL: $Uri" }
    Copy-Item -LiteralPath $archiveSource -Destination $OutFile
}
try {
    $asset = Get-PsExecAsset
    if (-not $asset -or -not (Test-Path -LiteralPath $asset)) { throw 'Official archive extraction failed' }
    $digest = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash
    if (-not (Test-PsExecAsset $asset $digest)) { throw 'Signed asset rejected' }
    if ($digest -ne 'edfae1a69522f87b12c6dac3225d930e4848832e3c551ee1e7d31736bf4525ef') {
        throw 'Official fixture differs from the reviewed PsExec digest'
    }
    if (Test-PsExecAsset $asset ('0' * 64)) { throw 'Unreviewed digest accepted' }
    if (Test-PsExecAsset (Get-TrustedPowerShell) $digest) { throw 'Alternate Microsoft-signed binary accepted as PsExec' }
    $marker1 = New-ProofMarker 'system-proof'
    Set-Content -LiteralPath $marker1 -Value 'S-1-5-18'
    $marker2 = New-ProofMarker 'system-proof'
    if ($marker1 -eq $marker2 -or (Test-Path -LiteralPath $marker2)) { throw 'Proof marker reused' }
    if ((Get-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Raw) -notmatch 'PsExec64.exe\t[0-9.]+\thttps://download.sysinternals.com/files/PSTools.zip') {
        throw 'Official source provenance missing'
    }
    Remove-Item -LiteralPath $asset, "$asset.sha256" -Force
    $script:offline = $true
    $Offline = $true
    if (-not (Get-PsExecAsset)) { throw 'Verified cache fallback failed' }
    if ((Get-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Raw) -notmatch 'PsExec64.exe\tcache') {
        throw 'Cache provenance missing'
    }
    Set-Content -LiteralPath "$asset.sha256" -Value ('0' * 64)
    $Resume = $true
    if (Get-PsExecAsset) { throw 'Mismatched run sidecar accepted on Resume' }
    $Resume = $false
    Remove-Item -LiteralPath $asset, "$asset.sha256" -Force
    Add-Content -LiteralPath (Join-Path $cacheBase 'microsoft_sysinternals\PsExec64.exe') -Value 'tamper' -Encoding ASCII
    if (Get-PsExecAsset) { throw 'Tampered cached asset accepted' }
    'PsExec pinned digest, signature, cache, sidecar, marker, and tamper checks passed'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
