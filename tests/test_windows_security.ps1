$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $errors" }
foreach ($name in @('Set-PrivateDirectory', 'Get-LatestSuccess')) {
    $fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
}

$testRoot = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
$hostName = $env:COMPUTERNAME
$OutputDir = Join-Path $testRoot 'runs'
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
try {
    $acl = Get-Acl -LiteralPath $OutputDir
    $everyone = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-1-0'
    $read = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $everyone, $read, $inherit, $none, $allow))
    Set-Acl -LiteralPath $OutputDir -AclObject $acl
    if (-not ((Get-Acl -LiteralPath $OutputDir).Access.IdentityReference.Value -contains 'Everyone' -or
              (Get-Acl -LiteralPath $OutputDir).Access.IdentityReference.Value -contains 'S-1-1-0')) {
        throw 'Could not create the permissive ACL fixture'
    }
    Set-PrivateDirectory $OutputDir
    $allowed = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18')
    foreach ($rule in (Get-Acl -LiteralPath $OutputDir).Access) {
        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq $allow -and $sid -notin $allowed) {
            throw "Unrelated principal retained access: $sid"
        }
    }

    $mine = Join-Path $OutputDir '20260925T010000Z-own'
    $foreign = Join-Path $OutputDir '20260925T020000Z-other'
    $bad = Join-Path $OutputDir '20260925T030000Z-bad'
    foreach ($folder in @($mine, $foreign, $bad)) { New-Item -ItemType Directory -Path $folder | Out-Null }
    '{"host":"' + $hostName + '","recipe":"already-admin"}' |
        Set-Content -LiteralPath (Join-Path $mine 'success.json')
    '{"host":"different-host","recipe":"already-admin"}' |
        Set-Content -LiteralPath (Join-Path $foreign 'success.json')
    'not json' | Set-Content -LiteralPath (Join-Path $bad 'success.json')
    $selected = Get-LatestSuccess
    $expected = Join-Path $mine 'success.json'
    if ((Get-Item -LiteralPath $selected).FullName -ne (Get-Item -LiteralPath $expected).FullName) {
        throw 'Wrong host Resume selected'
    }
    'Windows ACL reset and same-host Resume selection passed'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
