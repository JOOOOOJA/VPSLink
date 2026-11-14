# Contributing

Please describe the concrete problem, expected behavior and tested environment. Small focused changes are easier to review. Read [architecture](docs/architecture.md), [build instructions](docs/build.md) and [security model](docs/security-model.md) first.

Run the C# tests and relevant Python tests. Add regression coverage for protocol validation, profile persistence, route handling and privilege-sensitive changes. Do not change third-party binary hashes without checking the upstream release, licenses and corresponding sources.

Use documentation addresses (`example.com`, `192.0.2.0/24`) and generated test fixtures. Never commit real SSH/VPN keys, tokens, `.conf` files, WARP registrations, `profiles.json`, personal diagnostics, VM files or developer paths. Run `tools/Test-Publication.ps1` before proposing a release.

Contributions to original project code are provided under the repository's MIT license. Keep upstream copyright notices and licenses when importing code. Explain new downloads, administrator operations, filesystem changes and rollback behavior in the PR.

No network-affecting tests should run against another person's working connection. Use an isolated lab and retain a separate recovery path.
