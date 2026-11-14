# Security policy

This is a Proof of Concept without an independent security audit. There is no production support or response-time guarantee. Only the latest public PoC is maintained.

Please use [private vulnerability reporting](https://github.com/JOOOOOJA/VPSLink/security/advisories/new) for credential disclosure, arbitrary execution, authentication bypass or unsafe server changes. Do not put secrets or working exploit credentials in public issues. Include a minimal synthetic reproduction and affected version, with personal addresses removed.

Never send your SSH password/private key, Cloudflare token, VPN `.conf`, WARP registration or complete `profiles.json`. A public key or hostname can also identify your server; redact it unless necessary and explicitly intended for disclosure.

The [security model](docs/security-model.md) documents storage and network limits. For bugs in bundled upstream components, identify the exact version and coordinate with their maintainers as appropriate.
