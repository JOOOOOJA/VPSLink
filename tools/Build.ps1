[CmdletBinding()]
param(
    [string]$Python,
    [string]$LibSsh,
    [string]$WarpCoreDirectory,
    [string]$ZapretDirectory
)
$ErrorActionPreference = 'Stop'
if ([bool]$Python -ne [bool]$LibSsh) { throw 'Specify both -Python and -LibSsh or omit both.' }
if ($ZapretDirectory -and -not $WarpCoreDirectory) { throw 'Bundled winws requires -WarpCoreDirectory.' }
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $root
$priorCliHome = $env:DOTNET_CLI_HOME
$priorTelemetry = $env:DOTNET_CLI_TELEMETRY_OPTOUT
$priorCertificate = $env:DOTNET_GENERATE_ASPNET_CERTIFICATE
$priorGlobalPath = $env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH
$goSettings = @{
    GOENV = 'off'; GOTOOLCHAIN = 'local'; GOPROXY = 'off'; GOSUMDB = 'off';
    CGO_ENABLED = '0'; GOOS = 'windows'; GOARCH = 'amd64'; GOWORK = 'off';
    GOCACHE = (Join-Path $root 'artifacts\go-cache')
}
$priorGo = @{}
try {
    $env:DOTNET_CLI_HOME = Join-Path $root 'artifacts\dotnet-cache'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
    $env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = 'false'
    $app = 'src/NetUlta/NetUlta.csproj'
    $test = 'tests/NetUlta.Tests/NetUlta.Tests.csproj'
    $bundle = 'artifacts/Windows-x64'
    dotnet restore $test --configfile NuGet.Config --packages artifacts/nuget
    if ($LASTEXITCODE) { throw 'Restore failed.' }
    dotnet build $test -c Release --no-restore --nologo -p:UseSharedCompilation=false
    if ($LASTEXITCODE) { throw 'Build failed.' }
    dotnet publish $app -c Release --no-restore --self-contained false -o $bundle --nologo -p:DebugType=None -p:DebugSymbols=false -p:UseSharedCompilation=false
    if ($LASTEXITCODE) { throw 'Publish failed.' }
    if ($WarpCoreDirectory) {
        $core = (Resolve-Path -LiteralPath $WarpCoreDirectory).Path
        $source = Join-Path $core 'usque.exe'
        if ((Get-FileHash -LiteralPath $source).Hash -ne '122F2E40208E81BB814FCB4BE4FBBBDC9246860F1F3784F72AE4512B97667E91') {
            throw 'Unexpected usque.exe SHA-256.'
        }
        $destination = Join-Path $bundle 'warp-core'
        [IO.Directory]::CreateDirectory($destination) | Out-Null
        Copy-Item -LiteralPath $source,(Join-Path $core 'LICENSE.md') -Destination $destination
    }
    if ($ZapretDirectory) {
        $zapret = (Resolve-Path -LiteralPath $ZapretDirectory).Path
        $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'ZapretFiles.psd1')
        $sources = foreach ($name in $manifest.Hashes.Keys) {
            $path = Join-Path $zapret $name
            if ((Get-FileHash -LiteralPath $path).Hash -ne $manifest.Hashes[$name]) {
                throw "Unexpected SHA-256 for $name."
            }
            $path
        }
        $destination = Join-Path $bundle 'zapret'
        [IO.Directory]::CreateDirectory($destination) | Out-Null
        Copy-Item -LiteralPath ($sources + (Join-Path $PSScriptRoot 'Zapret-NOTICES.md')) -Destination $destination
    }
    foreach ($name in $goSettings.Keys) {
        $priorGo[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, $goSettings[$name], 'Process')
    }
    go build -trimpath -ldflags '-s -w' -o "$bundle/tfl-awg-keys.exe" tools/awg-keys/main.go
    if ($LASTEXITCODE) { throw 'AmneziaWG key utility build failed.' }
    $goRoot = go env GOROOT
    if ($LASTEXITCODE) { throw 'Go installation could not be located.' }
    Copy-Item -LiteralPath (Join-Path $goRoot 'LICENSE') -Destination "$bundle/Go-LICENSE.txt"
    $alice = [Convert]::ToBase64String([Convert]::FromHexString('77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A'))
    $derived = ($alice | & "$bundle/tfl-awg-keys.exe" public) | ConvertFrom-Json
    $expected = [Convert]::ToBase64String([Convert]::FromHexString('8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A'))
    if ($LASTEXITCODE -or $derived.PublicKey -cne $expected) { throw 'X25519 fixture failed.' }
    Write-Output 'PASS: AmneziaWG public key derivation'
    $exe = Join-Path $root "$bundle/VPSLink.exe"
    $gui = Start-Process -FilePath $exe -ArgumentList '--smoke-ui' -WindowStyle Hidden -PassThru
    if (-not $gui.WaitForExit(8000)) { $gui.Kill(); throw 'GUI startup test timed out.' }
    if ($gui.ExitCode -ne 0) { throw "GUI startup failed ($($gui.ExitCode))." }
    Write-Output 'PASS: Windows GUI startup'
    if ($Python) {
        & $Python -I 'tests/test_awg_setup.py'
        if ($LASTEXITCODE) { throw 'VPS provisioning tests failed.' }
        & $Python -I 'tests/test_https_relay.py'
        if ($LASTEXITCODE) { throw 'HTTPS/WebSocket relay tests failed.' }
        & $Python -I 'tests/test_gateway_setup.py'
        if ($LASTEXITCODE) { throw 'Persistent gateway tests failed.' }
        & 'tests/NetUlta.Tests/bin/Release/net6.0-windows/NetUlta.Tests.exe' $Python $LibSsh $exe
    } else {
        & 'tests/NetUlta.Tests/bin/Release/net6.0-windows/NetUlta.Tests.exe'
    }
    if ($LASTEXITCODE) { throw 'Tests failed.' }
    Copy-Item -LiteralPath README.md -Destination (Join-Path $bundle 'README.md')
    Copy-Item -LiteralPath LICENSE,THIRD_PARTY_NOTICES.md -Destination $bundle
    Copy-Item -LiteralPath docs,LICENSES -Destination $bundle -Recurse -Force
    Write-Output (Join-Path $root $bundle)
}
finally {
    foreach ($name in $priorGo.Keys) { [Environment]::SetEnvironmentVariable($name, $priorGo[$name], 'Process') }
    $env:DOTNET_CLI_HOME = $priorCliHome
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = $priorTelemetry
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = $priorCertificate
    $env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = $priorGlobalPath
    Pop-Location
}

