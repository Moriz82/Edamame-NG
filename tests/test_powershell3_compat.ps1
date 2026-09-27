#requires -Version 3.0
<#
    Windows PowerShell 3.0 compatibility gate for Edamame-NG.ps1.

    The native 3.0 and 5.1 guest runs prove parsing on a real engine. This check
    proves the opposite direction: that no construct which only exists in a later
    engine has crept in. It is a token scan, so it is cheap enough to run on
    every edit and it fails loudly rather than at run time on a 2012 guest.
#>
param([string]$Runner)

$ErrorActionPreference = 'Stop'
if (-not $Runner) { $Runner = Join-Path (Split-Path -Parent $PSScriptRoot) 'Edamame-NG.ps1' }
$library = Join-Path (Split-Path -Parent $Runner) 'lib\WeakServiceLab.ps1'
$targets = @($Runner)
if (Test-Path -LiteralPath $library -PathType Leaf) { $targets += $library }

# Construct, or command, that a Windows PowerShell 3.0 host does not have.
$forbidden = @(
    @{ Pattern = '::new\s*\('; Name = '::new() (PowerShell 5.0)' },
    @{ Pattern = '^\s*class\s+\w'; Name = 'class keyword (PowerShell 5.0)' },
    @{ Pattern = '^\s*using\s+(namespace|module|assembly)\s'; Name = 'using statement (PowerShell 5.0)' },
    @{ Pattern = '\?\?'; Name = 'null coalescing operator (PowerShell 7.0)' },
    @{ Pattern = '\?\.'; Name = 'null conditional operator (PowerShell 7.0)' },
    @{ Pattern = '-Parallel\b'; Name = 'ForEach-Object -Parallel (PowerShell 7.0)' },
    @{ Pattern = '\bJoin-String\b'; Name = 'Join-String (PowerShell 6.2)' },
    @{ Pattern = '\$PSStyle'; Name = '$PSStyle (PowerShell 7.2)' },
    @{ Pattern = '\bForEach-Object\b[^\n]*\s-Parallel'; Name = 'ForEach-Object -Parallel (PowerShell 7.0)' },
    @{ Pattern = '\bSplit-Path\b[^\n]*-LeafBase'; Name = 'Split-Path -LeafBase (PowerShell 6.0)' },
    @{ Pattern = '\bGet-Content\b[^\n]*-AsByteStream'; Name = 'Get-Content -AsByteStream (PowerShell 6.0)' },
    @{ Pattern = '\bCopy-Item\b[^\n]*-FromSession'; Name = 'Copy-Item -FromSession (PowerShell 5.1)' },
    @{ Pattern = '\bInvoke-RestMethod\b[^\n]*-StatusCodeVariable'; Name = 'Invoke-RestMethod -StatusCodeVariable (PowerShell 7.0)' },
    @{ Pattern = '\bTest-Json\b'; Name = 'Test-Json (PowerShell 6.0)' },
    @{ Pattern = '\bConvertFrom-Json\b[^\n]*-AsHashtable'; Name = 'ConvertFrom-Json -AsHashtable (PowerShell 6.0)' },
    @{ Pattern = '\bGet-Error\b'; Name = 'Get-Error (PowerShell 7.0)' },
    @{ Pattern = '\bMeasure-Object\b[^\n]*-AllStats'; Name = 'Measure-Object -AllStats (PowerShell 7.0)' },
    @{ Pattern = '\bWrite-Output\b[^\n]*-NoEnumerate'; Name = 'Write-Output -NoEnumerate (PowerShell 5.0)' }
)

# Constructs that 3.0 lacks outright. The runner shims Get-FileHash and reads
# the engine version, so those two are expected and are not flagged.
$absent = @('ForEach', 'ConvertFrom-Markdown', 'Get-Uptime')

$failures = 0
foreach ($target in $targets) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Parse failed in $target`: $($errors[0].Message)" }

    # Scan every token, not just command names: a type literal, a member name,
    # and an operator are exactly where a newer-engine construct hides. String
    # and comment tokens are skipped so a message that names a command is not
    # mistaken for a call to it.
    $skip = @('StringLiteral', 'HereStringLiteral', 'Comment', 'NewLine', 'LineContinuation', 'Whitespace')
    foreach ($token in $tokens) {
        if ($skip -contains [string]$token.Kind) { continue }
        $text = [string]$token.Text
        if (-not $text) { continue }
        foreach ($rule in $forbidden) {
            if ($text -match $rule.Pattern) {
                Write-Host ("{0}:{1} forbidden ({2}): {3}" -f (Split-Path -Leaf $target), $token.Extent.StartLineNumber, $rule.Name, $text)
                $failures++
            }
        }
    }

    # Command resolution against the smallest supported engine.
    $commands = $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
    foreach ($name in ($commands | Sort-Object -Unique)) {
        if ($absent -contains $name) {
            Write-Host ("{0}: command absent in Windows PowerShell 3.0: {1}" -f (Split-Path -Leaf $target), $name)
            $failures++
        }
    }

    # ::new() is tokenized as a member name, so it needs an AST check.
    foreach ($node in ($ast.FindAll({
                param($n) $n -is [Management.Automation.Language.InvokeMemberExpressionAst]
            }, $true))) {
        if ($node.Member -and $node.Member.Value -ceq 'new') {
            Write-Host ("{0}:{1} forbidden (::new() (PowerShell 5.0)): {2}" -f (Split-Path -Leaf $target), $node.Extent.StartLineNumber, $node.Extent.Text)
            $failures++
        }
    }

    # A parameter default is evaluated on every run, so a 3.0-only default is fatal.
    foreach ($node in ($ast.FindAll({ param($n) $n -is [Management.Automation.Language.ParameterAst] }, $true))) {
        if ($node.DefaultValue -and $node.DefaultValue.Extent.Text -match '\$PSVersionTable|::new\(') {
            Write-Host ("{0}:{1} parameter default needs a newer engine: {2}" -f (Split-Path -Leaf $target), $node.Extent.StartLineNumber, $node.Name.VariablePath.UserPath)
            $failures++
        }
    }
}

if ($failures) { throw "PowerShell 3.0 compatibility: $failures problem(s)" }
Write-Host 'PowerShell 3.0 compatibility token gate passed'
