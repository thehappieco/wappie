# Security reports

Do not include tokens, private keys or customer messages in public issues. Report vulnerabilities through this repository's private security advisory feature. Include the affected revision, a minimal reproduction using synthetic data, and the expected authorization boundary.

Workspace roles are distinct from device read permissions. Revocation prevents future authorized delivery but cannot erase keys or content already downloaded by a recipient. The hosted pilot is intended for test numbers.

The hosted remote MCP connector is metadata-only. It is issued a read-only, device-restricted API key with an expiry, never a service account or an archive private key, and cannot return message content. Its OAuth tokens are minted and verified by the reader process, not by the archive server. Report connector token, OAuth, consent or scope-escalation issues through the same private advisory channel; include the connection id, never the token, the API key or the sealed bundle.

See [media security boundaries and pending hardening](docs/media-security.md) for
the current keyless/unhashed attachment limitation, live-server plaintext
exposure, and migration requirements. That source review did not inspect
production objects or establish that any existing object contains plaintext.
