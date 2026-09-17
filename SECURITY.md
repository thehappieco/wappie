# Security reports

Do not include tokens, private keys or customer messages in public issues. Report vulnerabilities through this repository's private security advisory feature. Include the affected revision, a minimal reproduction using synthetic data, and the expected authorization boundary.

Workspace roles are distinct from device read permissions. Revocation prevents future authorized delivery but cannot erase keys or content already downloaded by a recipient. The hosted pilot is intended for test numbers.

See [media security boundaries and pending hardening](docs/media-security.md) for
the current keyless/unhashed attachment limitation, live-server plaintext
exposure, and migration requirements. That source review did not inspect
production objects or establish that any existing object contains plaintext.
