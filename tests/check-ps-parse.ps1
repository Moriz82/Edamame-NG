#requires -Version 3.0
<# Parse Edamame-NG.ps1 with the current engine and report the first errors. #>
param([string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1'))

$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $Path).Path, [ref]$null, [ref]$errors)
if ($errors -and $errors.Count) {
    foreach ($item in $errors) {
        Write-Host ("PARSE ERROR line {0}: {1}" -f $item.Extent.StartLineNumber, $item.Message)
    }
    exit 1
}
Write-Host ("PARSE OK: {0}" -f $Path)
