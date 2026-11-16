# Building VPSLink

Use Windows 10 x64 (21H2, build 19044 or later) or Windows 11 x64, PowerShell 7, a .NET SDK with the .NET 6 Windows targeting pack, and Go 1.26.2 or newer. The project currently targets `net6.0-windows` for compatibility with the existing prototype. .NET 6 is out of support. Migration of that target is pending. The installer includes Desktop Runtime 10.0.15 and the application uses `RollForward=LatestMajor`.

NuGet sources are disabled in `NuGet.Config`; no third-party NuGet packages are required. If targeting packs are absent, install the matching official .NET SDK before building. The SDK and build tools are not included in the app.

```powershell
./tools/Build-Icon.ps1
./tools/Build.ps1
```

This builds the app, key helper and Windows/Linux x64 QUIC modules. It runs Go and C# checks and a GUI startup check. Go modules are pinned by `tools/quic-bridge/go.sum`; use `-QuicModuleCache <path>` to build from an existing module cache without network access. Without extra directories, usque/winws are not bundled. Existing binaries are verified against fixed SHA-256 values before bundling:

```powershell
./tools/Build.ps1 -WarpCoreDirectory ./artifacts/dependencies/warp-core -ZapretDirectory ./artifacts/dependencies/zapret
```

Prepare those directories from the official sources described in [third-party-build.md](third-party-build.md). `warp-core` needs `usque.exe` and its `LICENSE.md`. `zapret` needs exactly the files listed in `tools/ZapretFiles.psd1`; license copies are in this repository's `LICENSES` directory. Do not copy configuration or registrations from a live installation.

Python tests can be run without a live server:

```powershell
python -I tests/test_awg_setup.py
python -I tests/test_https_relay.py
python -I tests/test_gateway_setup.py
```

Optional local SSH integration tests require an already installed Python and libssh DLL: pass both `-Python` and `-LibSsh` to Build.ps1. No production credentials are needed. The standard CI runs offline C# and Python tests, not a real-provider connectivity test.

For a complete redistributable release, prepare the upstream source archives and manifests described in the build notes. Place the official Microsoft `windowsdesktop-runtime-10.0.15-win-x64.exe` and [Win32 OpenSSH 10.4.0.0p1 `OpenSSH-Win64.zip`](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/10.4.0.0p1-Preview) in `artifacts/dependencies`. `Build-Installer.ps1` validates the .NET installer's pinned checksum and Authenticode signature. `Package.ps1` verifies the SSH archive against the release SHA-256 and copies the client, key generator, helper files and licenses into `openssh/`. Source builds without that directory use the system OpenSSH client (8.5 or later). Install the official Inno Setup 7.1.1 compiler separately:

```powershell
./tools/Build-Installer.ps1 -Compiler 'C:\BuildTools\InnoSetup\ISCC.exe'
```

Outputs go only to ignored `artifacts/`. Packaging uses a source allowlist, excludes build caches/debug symbols and includes licenses. Run `tools/Test-Publication.ps1`, review every staged file and inspect archive contents before publishing. Never package a working application data folder. New releases require updating the project version and release notes; the installer AppId and legacy profile directory must remain stable for upgrades.
