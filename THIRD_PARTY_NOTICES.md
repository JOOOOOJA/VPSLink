# Third-party notices

VPSLink's original source and artwork are MIT licensed. That license does not replace the licenses of bundled components. Original copyright notices and full license texts are in `LICENSES/`; usque dependency licenses are in `LICENSES/usque-modules/`.

| Component | Distribution | License / source |
|---|---|---|
| winws, zapret v72.13 | Unmodified Windows binary | [MIT, bol-van](https://github.com/bol-van/zapret/tree/87e058624c72863db53bdaf7fb6f16576dddb6ab) |
| Cygwin DLL 3.4.10 | Separate, unmodified DLL loaded by winws | [LGPL-3.0-or-later with Cygwin linking exception](https://cygwin.com/licensing.html) |
| WinDivert 2.2.2 | Separate DLL and driver | [LGPLv3 option of upstream dual LGPLv3/GPLv2 license](https://github.com/basil00/WinDivert/blob/v2.2.2/LICENSE) |
| usque 4.2.1 | Unmodified official Windows amd64 executable | [MIT, Diniboy1123](https://github.com/Diniboy1123/usque/tree/6aa03fc97d12848dce34eedbd187fb1077b5d1ea) and dependency notices |
| Go standard library | Compiled into key helper and usque | BSD-style; `LICENSES/Go-BSD.txt` |
| .NET Windows Desktop Runtime 10.0.15 | Official Microsoft redistributable inside Setup | Microsoft .NET Library binary terms and third-party notices in `LICENSES/dotnet-*`; upstream .NET source uses MIT and component-specific licenses |

The release includes `VPSLink-<version>-third-party-sources.zip`: source archives for winws, Cygwin, WinDivert, usque, and the exact Go modules recorded in the official usque binary. Checksums and build pointers accompany that archive. These sources are available from the same release location as the corresponding binaries, without charge. See [build notes](docs/third-party-build.md).

No modification of the bundled LGPL libraries is claimed. Users may replace/relink those separately distributed libraries and reverse engineer the combined work as necessary to debug modifications to them, subject to their applicable licenses. The package hash checks are distribution-build checks; they do not impose a blanket runtime signature requirement on a user's replacement LGPL library. The WinDivert driver still needs a Windows-compatible signature to load.

Cloudflared is not included in the Windows package: the server wizard downloads a pinned official Linux binary. It is [Apache-2.0 licensed](https://github.com/cloudflare/cloudflared); its source and license are available upstream. AmneziaVPN is installed separately and is not redistributed here; its [GPL-3.0 source](https://github.com/amnezia-vpn/amnezia-client) remains upstream. Cloudflare services have separate service terms accepted by the user.

Logos and names of upstream projects are not used as the VPSLink icon. No endorsement or affiliation is implied.

## Imported strategy examples

The optional strategy catalog adapts TLS parameters from the MIT-licensed [bol-van/zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle), `zapret-winws/preset1_example.cmd`. VPSLink stores the source commit and imports only a restricted set of parameters; it does not execute the downloaded script. Existing zapret attribution and license notices apply. See [strategy documentation](docs/strategies.md).
