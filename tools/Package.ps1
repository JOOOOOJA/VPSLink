[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$artifacts = Join-Path $root 'artifacts'
$build = Join-Path $artifacts 'Windows-x64'
& (Join-Path $PSScriptRoot 'Test-Publication.ps1')
$runtimeFiles = @('README.md','VPSLink.exe','VPSLink.dll','VPSLink.deps.json',
    'VPSLink.runtimeconfig.json','tfl-awg-keys.exe','Go-LICENSE.txt','LICENSE','THIRD_PARTY_NOTICES.md')
foreach ($directory in 'docs','LICENSES') {
    $runtimeFiles += @(Get-ChildItem -LiteralPath (Join-Path $build $directory) -Recurse -File | ForEach-Object { $_.FullName.Substring($build.Length + 1) })
}
$core = Join-Path $build 'warp-core/usque.exe'
if (Test-Path -LiteralPath $core -PathType Leaf) {
    if ((Get-FileHash -LiteralPath $core).Hash -ne '122F2E40208E81BB814FCB4BE4FBBBDC9246860F1F3784F72AE4512B97667E91') {
        throw 'Unexpected bundled usque.exe SHA-256.'
    }
    $runtimeFiles += @('warp-core/usque.exe','warp-core/LICENSE.md')
}
$zapret = Join-Path $build 'zapret'
if (Test-Path -LiteralPath $zapret -PathType Container) {
    if (-not (Test-Path -LiteralPath $core -PathType Leaf)) { throw 'Bundled winws requires bundled usque.' }
    $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'ZapretFiles.psd1')
    foreach ($name in $manifest.Hashes.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $zapret $name)).Hash -ne $manifest.Hashes[$name]) {
            throw "Unexpected SHA-256 for bundled $name."
        }
        $runtimeFiles += "zapret/$name"
    }
    $runtimeFiles += 'zapret/Zapret-NOTICES.md'
}
$version = ([xml](Get-Content -Raw -LiteralPath (Join-Path $root 'src/NetUlta/NetUlta.csproj'))).Project.PropertyGroup.Version
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid release version.' }

function New-Archive([string]$path, [string]$base, [string[]]$files) {
    $tmp = $path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $zip = [IO.Compression.ZipFile]::Open($tmp, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($item in $files | Sort-Object -Unique) {
                $source = Join-Path $base $item
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing file: $source" }
                $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $source,
                    $item.Replace('\','/'), [IO.Compression.CompressionLevel]::Optimal)
            }
        }
        finally { $zip.Dispose() }
        Move-Item -Force -LiteralPath $tmp -Destination $path
    }
    finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp }
    }
}
$winZip = Join-Path $artifacts "VPSLink-$version-win-x64.zip"
$srcZip = Join-Path $artifacts "VPSLink-$version-source.zip"
New-Archive $winZip $build $runtimeFiles
$files = @('README.md','NuGet.Config','.gitignore','LICENSE','THIRD_PARTY_NOTICES.md','CHANGELOG.md','CONTRIBUTING.md','SECURITY.md','tools/https-relay/nginx-location.conf')
foreach ($dir in 'docs','src','tests','tools','LICENSES','assets','.github') {
    $files += @(Get-ChildItem -LiteralPath (Join-Path $root $dir) -Recurse -File | ForEach-Object {
        $relative = $_.FullName.Substring($root.Length + 1)
        if ($relative -notmatch '(^|[\\/])(bin|obj|__pycache__)([\\/]|$)' -and
            $relative -notmatch 'proxy-env-' -and $_.Extension -notin '.conf','.pem','.key','.pyc') { $relative }
    })
}
New-Archive $srcZip $root $files
$archives = @($winZip,$srcZip)
if (Test-Path -LiteralPath $core) {
    $upstream = Join-Path $artifacts 'upstream-sources'
    foreach ($item in (Get-Content -Raw -LiteralPath (Join-Path $upstream 'sources.json') | ConvertFrom-Json)) {
        if ((Get-FileHash -LiteralPath (Join-Path $upstream $item.File)).Hash -ine $item.Sha256) { throw 'Upstream source hash mismatch.' }
    }
    foreach ($item in (Get-Content -Raw -LiteralPath (Join-Path $upstream 'go-modules/modules.json') | ConvertFrom-Json)) {
        if ((Get-FileHash -LiteralPath (Join-Path $upstream ('go-modules/'+$item.Zip))).Hash -ine $item.Sha256) { throw 'Go source hash mismatch.' }
    }
    Copy-Item -LiteralPath (Join-Path $root 'docs/third-party-build.md') -Destination (Join-Path $upstream 'README.md') -Force
    $thirdZip = Join-Path $artifacts "VPSLink-$version-third-party-sources.zip"
    $thirdFiles = @(Get-ChildItem -LiteralPath $upstream -Recurse -File | ForEach-Object { $_.FullName.Substring($upstream.Length + 1) })
    New-Archive $thirdZip $upstream $thirdFiles
    $archives += $thirdZip
}
Get-FileHash -Algorithm SHA256 -LiteralPath $archives |
    ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), (Split-Path $_.Path -Leaf) } |
    Set-Content -Encoding Ascii -LiteralPath (Join-Path $artifacts 'SHA256SUMS.txt')
Get-Item -LiteralPath $archives | Select-Object Name,Length

