param([Parameter(Mandatory)][string]$Archive, [Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
$expectedHash = 'B67FF8BECD203502190EC42AC7787C24C2CD3325ED7700485FE7A1C83D2A7957'
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
    throw 'OpenSSH-Win64.zip is required. See docs/build.md for the pinned official download.'
}
$archivePath = (Resolve-Path -LiteralPath $Archive).Path
if ((Get-FileHash -LiteralPath $archivePath).Hash -ne $expectedHash) { throw 'Unexpected Win32 OpenSSH archive SHA-256.' }

$clientFiles = 'ssh.exe', 'ssh-keygen.exe', 'ssh-sk-helper.exe', 'ssh-pkcs11-helper.exe', 'libcrypto.dll', 'LICENSE.txt', 'NOTICE.txt'
[IO.Directory]::CreateDirectory($Destination) | Out-Null
$zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    foreach ($name in $clientFiles) {
        $entry = $zip.GetEntry("OpenSSH-Win64/$name")
        if ($null -eq $entry) { throw "Missing $name in Win32 OpenSSH archive." }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $Destination $name), $true)
    }
}
finally { $zip.Dispose() }
$clientFiles | ForEach-Object { "openssh/$_" }
