# Third-party source and build notes

Release binaries are unmodified upstream distributions. This project does not claim bit-for-bit reproducibility of the entire installer or upstream binaries. The source archive `sources.json` records URLs and SHA-256 hashes; `go-modules/modules.json` records exact module versions, Go sums and ZIP hashes from the usque executable. `LICENSES/usque-modules.json` in the app source records the same dependency inventory.

## winws, Cygwin, WinDivert

Windows binaries originate from [zapret-win-bundle commit 6b4375fa04f6bd7017eec379e16e462d3ea8df66](https://github.com/bol-van/zapret-win-bundle/tree/6b4375fa04f6bd7017eec379e16e462d3ea8df66/zapret-winws). Required binary hashes are pinned in `tools/ZapretFiles.psd1`.

- winws v72.13 source: commit `87e058624c72863db53bdaf7fb6f16576dddb6ab`; build scripts and Windows instructions are in `docs/compile/build_howto_windows.txt` and the source tree's Makefiles. Build in the documented Cygwin environment.
- Cygwin 3.4.10 source: commit `89a1e4a573d40b233011402f42630b970ff71291`, tag `cygwin-3.4.10`. The supplied source includes `winsup`, configure scripts, Makefiles and installation documentation. Use an out-of-tree build following the [Cygwin contributor build instructions](https://cygwin.com/faq/faq.html#faq.programming.building-cygwin). The licensing texts are those under **winsup**, not the unrelated newlib root COPYING files.
- WinDivert source: tag `v2.2.2`. Follow its included README/build scripts for the DLL and driver. A custom driver requires appropriate signing to load on current Windows; no signing certificate is distributed here.

The libraries remain individual files next to winws. Replace compatible `cygwin1.dll`, `WinDivert.dll` and `WinDivert64.sys` in an isolated test copy to test changes. Build hashes must be deliberately updated if distributing changed versions. No private keys or development environment paths are needed to rebuild these upstream sources.

## usque and Go

usque 4.2.1 source: commit `6aa03fc97d12848dce34eedbd187fb1077b5d1ea`; the official Windows amd64 binary SHA-256 is `122f2e40208e81bb814fcb4be4fbbbdc9246860f1f3784f72ae4512b97667e91`. Obtain it from the [official release](https://github.com/Diniboy1123/usque/releases/tag/v4.2.1).

Follow upstream README/Go build instructions. The official executable records Go 1.26.3 and `vcs.modified=true`; the latter is upstream metadata, and no assertion is made that a pristine checkout reproduces the exact executable. The source bundle includes all 22 exact dependency module ZIPs, with Go sums checked against the binary. The included gVisor module requires at least Go 1.26.3. The smaller VPSLink key helper is built from `tools/awg-keys/main.go` using Go 1.26.2 with `-trimpath -ldflags '-s -w'`.

## Microsoft runtime

The installer embeds the unmodified [Desktop Runtime 10.0.15 x64 installer](https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/10.0.15/windowsdesktop-runtime-10.0.15-win-x64.exe). Build-Installer.ps1 contains the authoritative pinned SHA-256 and checks Microsoft's signature. Microsoft runtime license and third-party notices are supplied in `LICENSES/`. Runtime sources and build instructions are maintained in the official dotnet/runtime and dotnet/windowsdesktop repositories.
