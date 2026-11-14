# Changelog

## 0.4.0 — sharing and strategy catalogs (Proof of Concept)

- Include the Flowseal/bol-van strategy selection, catalog updates and guarded path testing from 0.3.2–0.3.3.
- Add password-encrypted invitations with a fresh AmneziaWG peer and restricted SSH key per recipient, import and server-side revocation.
- Keep owner SSH/VPN credentials, Cloudflare administration tokens, WARP registrations and local machine settings out of the transfer schema.
- Install a fixed forced-command recipient handler: no shell, forwarding, arbitrary uploaded Python, administration commands or other UDP destinations.
- Expand the technical README, infrastructure requirements, privacy/security boundaries and external tester acceptance steps.
- Preserve manual connection and existing profile storage/installer identity. New sharing is experimental; see the validation report and limitations.

## 0.3.3 — Flowseal catalog (preview)

- Make Flowseal/zapret-discord-youtube the default catalog source and retain bol-van as a selectable alternative.
- Preserve general/ALT/FAKE TLS names, compatible TLS parameters and packet templates, with commit-pinned downloads and per-file integrity checks.
- Explain skipped sections and identical variants. Timestamp-dependent variants are skipped without changing Windows TCP settings.
- Preserve legacy catalogs, saved profiles, active connections and manual connection behavior.

## 0.3.2 — strategy selection (preview)

- Added a Russian-language Strategies page with six built-in WARP TLS strategies, per-server selection and reset to the 0.3.1 default.
- Added manual catalog updates from the official zapret-win-bundle example, commit-pinned downloads, strict parameter validation and previous-catalog rollback. Downloaded CMD files are never executed.
- Added cancellable sequential selection using WARP and the expected VPS SSH host key, with no automatic fallback, VPN activation or profile changes.
- Preserve active connections, saved credentials and manual connection settings when downloading strategy updates. Test guards refuse to run alongside detected active VPN adapters or existing winws/usque processes.
- Added user instructions and technical documentation for source trust, narrow packet filtering and the limits of connectivity checks.

## 0.3.1 — Proof of Concept

First public preview, renamed VPSLink from the private ThingsNotFun Link prototype.

- Windows 11 x64 GUI with manual connect/disconnect, contextual hints and offline guide.
- Local UDP ↔ SSH bridge to an existing AmneziaWG VPS, optional SOCKS5/HTTP CONNECT and HTTPS/WebSocket gateway.
- Bundled WARP MASQUE core and narrowly scoped winws strategy.
- Peer creation/import, preservation of AWG 3.x parameters, loopback profile export and explicit transport route exclusion.
- Persistent Cloudflare Tunnel setup for a user-owned domain and VPS.
- Atomic validated profile storage, backup and rollback on startup-task failure; clearer malformed-profile error.
- In-place installer upgrade preserving existing profiles; automatic connection is not required.
- GitHub PoC update channel, digest validation and user-controlled installation.
- New original icon, MIT license for project code, third-party license and source materials.

Not claimed: universal censorship circumvention, a kill switch, audited anonymity, verified IPv6 coverage, Android support, or unattended setup of a completely unreachable empty VPS.
