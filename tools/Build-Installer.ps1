[CmdletBinding()]
param([string]$Compiler)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not $Compiler) { $Compiler = Join-Path $root 'artifacts\installer-tools\InnoSetup\ISCC.exe' }
if (-not (Test-Path -LiteralPath $Compiler)) { throw 'Install approved Inno Setup first, or specify -Compiler.' }
$version = ([xml](Get-Content -Raw -LiteralPath (Join-Path $root 'src\NetUlta\NetUlta.csproj'))).Project.PropertyGroup.Version
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid version' }
$runtime = Join-Path $root 'artifacts\dependencies\windowsdesktop-runtime-10.0.15-win-x64.exe'
if ((Get-FileHash -LiteralPath $runtime).Hash -ne 'E61B030C1673EDFA3C0844502EFF83198C46AF9E7DF70DFC6E2EFC5B11EA513A' -or (Get-AuthenticodeSignature -LiteralPath $runtime).Status -ne 'Valid') { throw 'Unverified Desktop Runtime' }
& (Join-Path $PSScriptRoot 'Package.ps1')
$stage = Join-Path $root 'artifacts\installer-stage'
if (Test-Path -LiteralPath $stage) {
    $resolved = (Resolve-Path -LiteralPath $stage).Path
    if ($resolved -ne (Join-Path $root 'artifacts\installer-stage')) { throw 'Invalid staging path' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Expand-Archive -LiteralPath (Join-Path $root "artifacts\VPSLink-$version-win-x64.zip") -DestinationPath $stage
[IO.Directory]::CreateDirectory((Join-Path $stage 'Help')) | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'src\NetUlta\Guide.html') -Destination (Join-Path $stage 'Help\thingsnotfun-link-guide.html')
& $Compiler "/DReleaseVersion=$version" (Join-Path $PSScriptRoot 'installer\Link.iss')
if ($LASTEXITCODE) { throw 'Installer compilation failed' }
$setup = Join-Path $root "artifacts\VPSLink-$version-Setup.exe"
Get-FileHash -LiteralPath $setup | ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), (Split-Path $_.Path -Leaf) } | Add-Content -Encoding Ascii -LiteralPath (Join-Path $root 'artifacts\SHA256SUMS.txt')
Get-Item -LiteralPath $setup | Select-Object FullName,Length
