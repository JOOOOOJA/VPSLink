param([string]$CachedModules, [string]$BaseBundle)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (!$CachedModules) { $CachedModules = Join-Path $root 'artifacts\module-cache' }
if (!$BaseBundle) { $BaseBundle = Join-Path $root 'artifacts\Windows-x64' }
$bundle = Join-Path $root 'artifacts\Windows-x64-quic-auto-test'
& (Join-Path $PSScriptRoot 'Build-QuicBridge.ps1') -Destination (Join-Path $bundle 'quic') -CachedModules $CachedModules
$previousHome = $env:DOTNET_CLI_HOME
$previousTelemetry = $env:DOTNET_CLI_TELEMETRY_OPTOUT
try {
    $env:DOTNET_CLI_HOME = Join-Path $root 'artifacts\dotnet-cache'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    $project = Join-Path $root 'src\NetUlta\NetUlta.csproj'
    dotnet publish $project -c Release --no-restore --self-contained false -o $bundle --nologo -p:Version=0.5.1-quic.1 -p:UseSharedCompilation=false
    if ($LASTEXITCODE) { throw 'VPSLink publish failed.' }
} finally {
    $env:DOTNET_CLI_HOME = $previousHome
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = $previousTelemetry
}
foreach ($name in @('warp-core', 'zapret', 'tfl-awg-keys.exe', 'LICENSE', 'LICENSES', 'THIRD_PARTY_NOTICES.md', 'Go-LICENSE.txt')) {
    Copy-Item -LiteralPath (Join-Path $BaseBundle $name) -Destination $bundle -Recurse -Force
}
Write-Output $bundle
