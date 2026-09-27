$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
    $hashFn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-FileHash' }, $true)
    . ([scriptblock]::Create($hashFn.Extent.Text))
}
$fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ReleaseAsset' }, $true)
. ([scriptblock]::Create($fn.Extent.Text))
function Set-PrivateDirectory([string]$Path) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
try {
    $runDir = Join-Path $testRoot 'run'
    $cacheBase = Join-Path $testRoot 'cache'
    $ToolDir = Join-Path $testRoot 'tools'
    foreach ($dir in @($runDir, $cacheBase, $ToolDir)) { Set-PrivateDirectory $dir }
    Set-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Value ''
    $asset = Join-Path $ToolDir 'fixture.ps1'
    Set-Content -LiteralPath $asset -Value 'fixture' -Encoding ASCII
    $hash = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$asset.sha256" -Value $hash
    $dest = Join-Path $runDir 'asset.ps1'
    if (-not (Get-ReleaseAsset 'example/repo' 'fixture.ps1' $dest)) { throw 'verified local asset rejected' }
    if ((Get-FileHash $dest -Algorithm SHA256).Hash -ne $hash) { throw 'local digest changed' }
    Set-Content -LiteralPath "$asset.sha256" -Value ('0' * 64)
    Remove-Item -LiteralPath $dest
    if (Get-ReleaseAsset 'example/repo' 'fixture.ps1' $dest) { throw 'invalid digest accepted' }
    if ((Get-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Raw) -notmatch 'missing') { throw 'missing asset not recorded' }
    $ToolDir = $null
    $script:offline = $false
    $script:fixturePath = $asset
    function Invoke-WebRequest {
        param([string]$Uri, [switch]$UseBasicParsing, [int]$MaximumRedirection,
              [int]$TimeoutSec, [string]$OutFile)
        if ($script:offline) { throw 'synthetic offline mode' }
        if ($Uri -like '*/releases/latest') {
            return [pscustomobject]@{ BaseResponse = [pscustomobject]@{ ResponseUri = [uri]'https://github.com/example/repo/releases/tag/v1' } }
        }
        if ($Uri -like '*/expanded_assets/*') {
            return [pscustomobject]@{ Content = "<clipboard-copy id=`"clipboard-button-sha256:$hash`" aria-label=`"Copy to clipboard digest for fixture.ps1`">" }
        }
        if ($Uri -like '*/download/*') { Copy-Item -LiteralPath $script:fixturePath -Destination $OutFile; return }
        throw "Unexpected synthetic URL: $Uri"
    }
    if (-not (Get-ReleaseAsset 'example/repo' 'fixture.ps1' $dest)) { throw 'verified release asset rejected' }
    if ((Get-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Raw) -notmatch 'fixture.ps1\tv1') { throw 'release provenance missing' }
    $script:offline = $true
    Remove-Item -LiteralPath $dest
    if (-not (Get-ReleaseAsset 'example/repo' 'fixture.ps1' $dest)) { throw 'verified cache fallback failed' }
    if ((Get-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Raw) -notmatch 'fixture.ps1\tcache') { throw 'cache provenance missing' }
    $script:corruptSource = Join-Path (Join-Path $cacheBase 'example_repo') 'fixture.ps1'
    function Copy-Item {
        [CmdletBinding()]
        param([string]$LiteralPath, [string]$Destination, [switch]$Force)
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force -ErrorAction Stop
        if ($LiteralPath -eq $script:corruptSource) { Add-Content -LiteralPath $Destination -Value 'tampered' }
    }
    Remove-Item -LiteralPath $dest
    if (Get-ReleaseAsset 'example/repo' 'fixture.ps1' $dest) { throw 'changed cache copy was accepted' }
    if (Test-Path -LiteralPath $dest) { throw 'changed cache copy was retained' }
    Remove-Item Function:Copy-Item
    $ToolDir = Join-Path $testRoot 'tools'
    $corrupt = Join-Path $ToolDir 'corrupt.ps1'
    Set-Content -LiteralPath $corrupt -Value 'synthetic content' -Encoding ASCII
    Set-Content -LiteralPath "$corrupt.sha256" -Value (Get-FileHash -LiteralPath $corrupt -Algorithm SHA256).Hash
    $script:corruptSource = $corrupt
    function Copy-Item {
        [CmdletBinding()]
        param([string]$LiteralPath, [string]$Destination, [switch]$Force)
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force -ErrorAction Stop
        if ($LiteralPath -eq $script:corruptSource) { Add-Content -LiteralPath $Destination -Value 'tampered' }
    }
    $corruptDest = Join-Path $runDir 'corrupt.ps1'
    if (Get-ReleaseAsset 'example/repo' 'corrupt.ps1' $corruptDest) { throw 'changed copy was accepted' }
    if (Test-Path -LiteralPath $corruptDest) { throw 'changed copy was retained' }
    Remove-Item Function:Copy-Item
    $blocked = Join-Path $ToolDir 'blocked.exe'
    Set-Content -LiteralPath $blocked -Value 'synthetic blocked content' -Encoding ASCII
    $blockedHash = (Get-FileHash -LiteralPath $blocked -Algorithm SHA256).Hash
    Set-Content -LiteralPath "$blocked.sha256" -Value $blockedHash
    function Get-FileHash {
        param([string]$LiteralPath, [string]$Algorithm)
        throw (New-Object System.IO.IOException -ArgumentList 'synthetic asset read block')
    }
    if (Get-ReleaseAsset 'example/repo' 'blocked.exe' (Join-Path $runDir 'blocked.exe')) {
        throw 'unreadable local asset accepted'
    }
    if ((Get-Content -LiteralPath (Join-Path $runDir 'tools.tsv') -Raw) -notmatch 'blocked.exe\tmissing') {
        throw 'unreadable asset was not recorded as missing'
    }
    'PowerShell parse, digest rejection, release digest, cache fallback, changed-copy rejection, and unreadable asset handling passed'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
