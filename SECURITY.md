# Security reports

Do not include tokens, private keys or customer messages in public issues. Report vulnerabilities through this repository's private security advisory feature. Include the affected revision, a minimal reproduction using synthetic data, and the expected authorization boundary.

Workspace roles are distinct from device read permissions. Revocation prevents future authorized delivery but cannot erase keys or content already downloaded by a recipient. The hosted pilot is intended for test numbers.

There are two hosted remote MCP connectors, and they differ in what they can open:

- The hosted metadata connector (`https://api.wappie.thehappie.co/mcp`, `packages/mcp-http/server.mjs`, and every self-hosted container) is issued a read-only, device-restricted API key with an expiry, never a service account or an archive private key, and cannot return message content.
- The attested reader (`https://mcp.wappie.thehappie.co/mcp`, `packages/mcp-http/enclave/`) runs in an AWS Nitro Enclave whose published image the console verifies before consent. A `content` connection there is given its own read-only service account whose device grants are sealed to a key generated inside the enclave, held only in its memory, and never sent to the archive server, so the reader can open message text, chat and contact names and filenames of the consented numbers. Revoking the connection, its expiry, or removing or disabling the service account or the person who consented removes the account and its grants in one transaction; the enclave drops the key within a minute. Revocation stops future reads; it cannot retract what the assistant already received. [Who can read what](docs/mcp.md#who-can-read-what) states what Wappie's operators, the enclave's parent host, whoever controls DNS and the AI provider can and cannot see; [docs/mcp-enclave.md](docs/mcp-enclave.md) is the contract.

In both, OAuth tokens are minted and verified by the reader process, not by the archive server. Report connector token, OAuth, consent, attestation, key-handling or scope-escalation issues through the same private advisory channel; include the connection id, never the token, the API key, the sealed bundle or any message content.

See [media security boundaries and pending hardening](docs/media-security.md) for
the current keyless/unhashed attachment limitation, live-server plaintext
exposure, and migration requirements. That source review did not inspect
production objects or establish that any existing object contains plaintext.
