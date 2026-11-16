param([Parameter(Mandatory)][string]$Destination, [string]$CachedModules)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$quic = [IO.Path]::GetFullPath($Destination, $root)
$temporaryBinary = Join-Path $quic 'vpslink-quic-linux'
$settings = @{
    GOOS = 'windows'; GOARCH = 'amd64'; GOENV = 'off'; GOFLAGS = ''; GOWORK = 'off'
    GOTOOLCHAIN = 'local'; CGO_ENABLED = '0'; GOCACHE = (Join-Path $root 'artifacts\go-cache')
    GOPROXY = 'https://proxy.golang.org'; GOSUMDB = 'sum.golang.org'; GOPRIVATE = ''; GONOPROXY = ''; GONOSUMDB = ''
}
if ($CachedModules) {
    $settings.GOMODCACHE = (Resolve-Path -LiteralPath $CachedModules).Path
    $settings.GOPROXY = 'off'
    $settings.GOSUMDB = 'off'
}
$previous = @{}
foreach ($name in $settings.Keys) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    [Environment]::SetEnvironmentVariable($name, $settings[$name], 'Process')
}
Push-Location -LiteralPath (Join-Path $PSScriptRoot 'quic-bridge')
try {
    [IO.Directory]::CreateDirectory($quic) | Out-Null
    go test -mod=readonly .
    if ($LASTEXITCODE) { throw 'QUIC bridge tests failed.' }
    go build -mod=readonly -trimpath -ldflags '-s -w' -o (Join-Path $quic 'vpslink-quic.exe') .
    if ($LASTEXITCODE) { throw 'Windows QUIC bridge build failed.' }
    $env:GOOS = 'linux'
    go build -mod=readonly -trimpath -ldflags '-s -w' -o $temporaryBinary .
    if ($LASTEXITCODE) { throw 'Linux QUIC bridge build failed.' }
    $inputFile = [IO.File]::OpenRead($temporaryBinary)
    try {
        $outputFile = [IO.File]::Create((Join-Path $quic 'vpslink-quic-linux.gz'))
        try {
            $compress = [IO.Compression.GZipStream]::new($outputFile, [IO.Compression.CompressionLevel]::Optimal, $true)
            try { $inputFile.CopyTo($compress) } finally { $compress.Dispose() }
        } finally { $outputFile.Dispose() }
    } finally { $inputFile.Dispose() }
    Remove-Item -LiteralPath $temporaryBinary
    $cache = go env GOMODCACHE
    if ($LASTEXITCODE) { throw 'Go module cache could not be located.' }
    $modules = [ordered]@{'quic-go' = 'github.com\quic-go\quic-go@v0.60.0'; 'x-crypto' = 'golang.org\x\crypto@v0.53.0';
        'x-net' = 'golang.org\x\net@v0.56.0'; 'x-sys' = 'golang.org\x\sys@v0.46.0'}
    foreach ($entry in $modules.GetEnumerator()) {
        $license = Join-Path $cache ($entry.Value + '\LICENSE')
        Copy-Item -LiteralPath $license -Destination (Join-Path $quic ($entry.Key + '-LICENSE.txt')) -Force
    }
} finally {
    Pop-Location
    foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
