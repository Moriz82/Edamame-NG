#requires -Version 3.0
<#
    Synthetic Windows credential validation checks.

    The pure decision helpers are lifted out of Edamame-NG.ps1 with the same
    AST extraction the weak-service test uses, so the gating, accounting, and
    binding rules are checked without a Windows authenticator and without any
    authentication attempt against any endpoint. The Windows-only pieces
    (WNetAddConnection2, the private ACLs, the SecureString prompt) are
    asserted structurally rather than executed.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$runner = Join-Path $root 'Edamame-NG.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse failed: $($errors[0].Message)" }

foreach ($name in @('Get-FileHash', 'Get-CredMasked', 'Test-PrivateFileAcl', 'Get-CredLedgerPath',
        'Get-CredLedgerAttempts', 'Set-CredLedgerAttempts', 'Get-CredPolicy',
        'Test-CredEndpointReachable')) {
    $found = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if (-not $found) { throw "Missing credential helper: $name" }
    . ([scriptblock]::Create($found.Extent.Text))
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ("edamame-cred-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
try {
    # ---- masking never reveals the middle of an account -------------------
    if ((Get-CredMasked 'edatest') -cne 'e***t') { throw 'Account masking is wrong' }
    if ((Get-CredMasked 'a') -cne 'a*') { throw 'Single character masking is wrong' }
    if ((Get-CredMasked 'ab') -cne 'a*') { throw 'Two character masking is wrong' }
    $masked = Get-CredMasked 'svc_backup'
    if ($masked -match 'backup') { throw 'Account masking leaked the name' }
    if ((Get-CredMasked 'EDALAB\edatest') -ne 'E***t') { throw 'Qualified account masking is wrong' }

    # ---- binding key covers service, account, host, and port ---------------
    function Get-Key([string]$service, [string]$account, [string]$hostName, [string]$endpoint) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return [BitConverter]::ToString(
                $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$service|$account|$hostName`:$endpoint"))).Replace('-', '')
        } finally { $sha.Dispose() }
    }
    $CredService = 'smb'
    $base = Get-Key 'smb' 'EDALAB\edatest' '192.0.2.10' '445'
    if ($base -notmatch '^[0-9A-F]{64}$') { throw 'Credential key is not a SHA-256' }
    if ($base -ceq (Get-Key 'smb' 'EDALAB\other' '192.0.2.10' '445')) { throw 'Account is not bound' }
    if ($base -ceq (Get-Key 'smb' 'EDALAB\edatest' '192.0.2.11' '445')) { throw 'Host is not bound' }
    if ($base -ceq (Get-Key 'smb' 'EDALAB\edatest' '192.0.2.10' '139')) { throw 'Port is not bound' }
    if ($base -ceq (Get-Key 'rdp' 'EDALAB\edatest' '192.0.2.10' '445')) { throw 'Service is not bound' }

    # ---- ledger: a foreign header is never adopted or overwritten ---------
    $ledger = Join-Path $scratch 'ledger.tsv'
    $CredLedger = $ledger
    $cacheBase = $scratch
    if ((Get-CredLedgerPath) -cne $ledger) { throw 'Explicit ledger path was not honoured' }
    $header = 'key' + "`t" + 'service' + "`t" + 'endpoint' + "`t" + 'account' + "`t" + 'attempts' + "`t" + 'first_utc' + "`t" + 'last_utc'
    Set-Content -LiteralPath $ledger -Value $header -Encoding ASCII
    if ((Get-CredLedgerAttempts $ledger $base) -ne 0) { throw 'A fresh ledger must report zero attempts' }
    $CredAccount = 'EDALAB\edatest'
    $CredHost = '192.0.2.10'
    $CredPort = 445
    Set-CredLedgerAttempts $ledger $base 1 '2026-01-01T00:00:00Z' '2026-01-01T00:00:05Z' $null
    if ((Get-CredLedgerAttempts $ledger $base) -ne 1) { throw 'One attempt was not recorded' }
    Set-CredLedgerAttempts $ledger $base 2 '2026-01-01T00:00:00Z' '2026-01-01T00:01:00Z' $null
    if ((Get-CredLedgerAttempts $ledger $base) -ne 2) { throw 'The attempt count did not accumulate' }
    $rows = @(Get-Content -LiteralPath $ledger)
    if ($rows.Count -ne 2) { throw "The ledger grew a duplicate row: $($rows.Count)" }
    $fields = $rows[1] -split "`t"
    if ($fields[1] -cne 'smb' -or $fields[2] -cne '192.0.2.10:445') { throw 'The ledger row lost its binding' }
    if ($fields[3] -ne (Get-CredMasked 'EDALAB\edatest')) { throw 'The ledger stored an unmasked account' }
    if ($fields[5] -ne '2026-01-01T00:00:00Z') { throw 'The first attempt time was not preserved' }
    if ($fields[6] -ne '2026-01-01T00:01:00Z') { throw 'The last attempt time was not updated' }
    if ((Get-CredLedgerAttempts $ledger (Get-Key 'smb' 'EDALAB\other' '192.0.2.10' '445')) -ne 0) {
        throw 'A different account shared a counter'
    }
    Set-Content -LiteralPath $ledger -Value @($rows[0], ($rows[1] -replace "`t2`t", "`tbad`t")) -Encoding ASCII
    $threw = $false
    try { Get-CredLedgerAttempts $ledger $base } catch { $threw = $true }
    if (-not $threw) { throw 'A corrupt attempt count was treated as unused' }
    Set-Content -LiteralPath $ledger -Value @($rows[0], $rows[1], $rows[1]) -Encoding ASCII
    $threw = $false
    try { Get-CredLedgerAttempts $ledger $base } catch { $threw = $true }
    if (-not $threw) { throw 'Duplicate attempt rows were treated as one' }
    Set-Content -LiteralPath $ledger -Value $rows -Encoding ASCII
    $foreign = Join-Path $scratch 'foreign.tsv'
    Set-Content -LiteralPath $foreign -Value 'someone elses data' -Encoding ASCII
    $threw = $false
    try { Get-CredLedgerAttempts $foreign $base } catch { $threw = $true }
    if (-not $threw) { throw 'A foreign ledger header was adopted' }
    if ((Get-Content -LiteralPath $foreign) -ne 'someone elses data') { throw 'A foreign file was modified' }
    $CredLedger = $null
    $CredLockoutFile = $null
    if ((Get-CredLedgerPath) -cne (Join-Path $cacheBase 'credential-ledger.tsv')) {
        throw 'The default ledger path is wrong'
    }

    # ---- lockout policy ---------------------------------------------------
    $noPolicy = Get-CredPolicy $null
    if ($noPolicy[0] -cne 'unverified-single-attempt' -or [int]$noPolicy[1] -ne 1 -or $noPolicy[2]) {
        throw 'The default policy is not a single permitted attempt'
    }
    $policy = Join-Path $scratch 'policy.txt'
    Set-Content -LiteralPath $policy -Value "lockout_threshold=3`nreset=automatic" -Encoding ASCII
    $CredLockoutFile = $policy
    $parsed = Get-CredPolicy $null
    if ($parsed[0] -cne 'operator-policy-threshold-3' -or [int]$parsed[1] -ne 1) { throw 'The policy must not raise the one-attempt cap' }
    if ($parsed[2] -notmatch '^[0-9A-F]{64}$') { throw 'The policy digest was not recorded' }
    Set-Content -LiteralPath $policy -Value "lockout_threshold=9" -Encoding ASCII
    $capped = Get-CredPolicy $null
    if ([int]$capped[1] -ne 1) { throw 'The policy must not raise the one-attempt cap' }
    Set-Content -LiteralPath $policy -Value 'reset=automatic' -Encoding ASCII
    $threw = $false
    try { Get-CredPolicy $null } catch { $threw = $true }
    if (-not $threw) { throw 'A policy without a threshold was accepted' }
    Set-Content -LiteralPath $policy -Value 'lockout_threshold=0' -Encoding ASCII
    $threw = $false
    try { Get-CredPolicy $null } catch { $threw = $true }
    if (-not $threw) { throw 'A zero threshold was accepted' }
    Set-Content -LiteralPath $policy -Value 'lockout_threshold=abc' -Encoding ASCII
    $threw = $false
    try { Get-CredPolicy $null } catch { $threw = $true }
    if (-not $threw) { throw 'A non-numeric threshold was accepted' }
    $CredLockoutFile = (Join-Path $scratch 'absent.txt')
    $threw = $false
    try { Get-CredPolicy $null } catch { $threw = $true }
    if (-not $threw) { throw 'A missing policy file was accepted' }
    $CredLockoutFile = $null

    # ---- the endpoint precheck is a plain TCP connect, not an attempt ------
    if (Test-CredEndpointReachable '127.0.0.1' 1 200) { throw 'A closed loopback port reported reachable' }
    $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $openPort = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    if (-not (Test-CredEndpointReachable '127.0.0.1' $openPort 2000)) { throw 'A listening loopback port reported unreachable' }
    $listener.Stop()

    # ---- structural guarantees about the credential block -----------------
    $text = Get-Content -LiteralPath $runner -Raw
    if ($text -notmatch 'WNetAddConnection2') { throw 'The SMB authenticator is not WNetAddConnection2' }
    if ($text -notmatch 'WNetCancelConnection2') { throw 'The temporary SMB connection is not removed' }
    # Isolate the credential block, stopping at the startup splash.
    $start = $text.IndexOf('# Operator-supplied credential validation')
    if ($start -lt 0) { throw 'The credential block is missing' }
    $block = $text.Substring($start)
    $end = $block.IndexOf("`n@'")
    if ($end -gt 0) { $block = $block.Substring(0, $end) }
    if ($text -notmatch 'CONNECT_TEMPORARY') { throw 'The SMB connection is not temporary' }
    if ($text -notmatch 'dwUsage = 1') { throw 'The SMB connection is not connectable-only' }
    if ($block -notmatch '\$CredPort -ne 445') { throw 'The WNet adapter accepts a port it cannot address' }
    if ($block -notmatch 'ToLowerInvariant\(\)') { throw 'Case changes could create a new SMB attempt budget' }
    if ($block -notmatch 'WNetAddConnection2\(\[ref\]\$resource, \$credSecret, \$credUser, 4\)') {
        throw 'The SMB connection is not marked temporary'
    }
    if ($block -notmatch 'Set-CredLedgerAttempts[\s\S]*WNetAddConnection2') {
        throw 'The attempt was not reserved before authentication'
    }
    foreach ($forbidden in @('Start-Process', 'Invoke-Expression', 'iex ', 'cmd /c', 'cmd.exe /c')) {
        if ($block -match [regex]::Escape($forbidden)) {
            throw "The credential block can reach a shell: $forbidden"
        }
    }
    # No collector output, capture file, or catalog value feeds the secret.
    foreach ($leak in @('.capture', 'linpeas-output', 'winpeas-output', 'Get-SuggestedCves', 'privesccheck-output')) {
        if ($block -match [regex]::Escape($leak)) { throw "The credential block reads enumerator output: $leak" }
    }
    if ($block -notmatch 'Read-Host -AsSecureString') { throw 'The interactive secret path is not hidden input' }
    if ($block -notmatch 'ZeroFreeBSTR') { throw 'The SecureString is not released' }
    if ($block -notmatch '\$credSecret = \$null') { throw 'The secret is not cleared after use' }

    Write-Host 'Credential validation masking, binding, ledger, policy, and structure passed'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
