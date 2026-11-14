[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$issues = @()
$files = Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
    $_.FullName.Substring($root.Length + 1) -notmatch '(^|[\\/])(artifacts|bin|obj|\.git|__pycache__)([\\/]|$)'
}
foreach ($file in $files) {
    $relative = $file.FullName.Substring($root.Length + 1)
    if ($file.Name -match '^(profiles.*\.json|config\.json|hosts\.yml|\.env.*)$' -or
        $file.Extension -in '.pem','.key','.pfx','.dpapi','.log','.jsonl','.vmx','.vmdk','.vmem','.vmss','.iso','.exe','.dll','.sys') {
        $issues += "Forbidden publication file: $relative"
        continue
    }
    if ($file.Extension -in '.png','.ico') { continue }
    $content = [IO.File]::ReadAllText($file.FullName)
    $patterns = @(
        '-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----',
        '\bgh[pousr]_[A-Za-z0-9]{30,}',
        '\bgithub_pat_[A-Za-z0-9_]{40,}',
        'C:[\\/]Users[\\/](?!Public(?:[\\/]|\b)|<|%|\$)[A-Za-z0-9_.-]+[\\/]',
        'S-1-5-21-\d+-\d+-\d+-\d+'
    )
    foreach ($pattern in $patterns) {
        if ($content -match $pattern) { $issues += "Review sensitive content: $relative"; break }
    }
}
if ($issues.Count) { $issues | Sort-Object -Unique | Write-Output; throw 'Publication audit failed (values omitted).' }
Write-Output "PASS: publication inputs ($($files.Count) files; heuristic check, not a complete security audit)"
