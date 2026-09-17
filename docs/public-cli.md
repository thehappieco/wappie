# Public account administration without the private application

The public source distribution includes `packages/cli`, an Apache-2.0 Node 22+ account and administration CLI built on the independent `packages/client` SDK. It covers password login, invited/public signup, password recovery/change, workspace selection, membership and storage administration, encrypted device grants, and generic authenticated public HTTP/WebSocket requests.

See [CLI setup, commands and security model](../packages/cli/README.md). The server, Go operator CLI, TypeScript SDK and this account CLI require no private frontend source or build output.
