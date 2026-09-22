# External Wappie installations

The private app supports compatible Wappie installations reached directly over
HTTPS. The commercial service stores installation origins and number bindings;
it does not proxy the external archive or store remote passwords or sessions.
A binding is identified by installation, remote workspace and device. Its UUIDs
may coincide with UUIDs on another installation without sharing a session/key.

## Discovery and origins

Unauthenticated `GET /v1/discovery` (also `/.well-known/wappie`) returns product,
API version, capabilities and relative HTTP/WebSocket/media paths. Clients must
reject incompatible versions before authenticating. The first version requires
`product: wappie`, `api_version: 1` and `external-client.v1`.

### Remote MCP connector

An installation that serves the hosted MCP connector advertises `mcp.remote.v1`
alongside `external-client.v1`, with `mcp` among its endpoints. Its OAuth
metadata is unauthenticated at `/.well-known/oauth-protected-resource` and
`/.well-known/oauth-authorization-server` (with and without the `/mcp` suffix);
those documents carry no credential and are not covered by
`WS_BROWSER_ORIGINS`, which governs browser origins only. The console approves
a connection against the origin named in the reader's descriptor, not against
its own page origin, so a hosted console can approve connections for a
compatible external installation.

`WS_BROWSER_ORIGINS` lists exact origins allowed for HTTP, WebSocket and call
media. Wildcards, userinfo, paths and query strings are rejected. HTTPS is
required except explicit localhost HTTP origins in development. HTTP preflight
never substitutes for authentication. API clients without Origin still require
credentials. Reverse proxies must preserve Host and upgrade headers.

The private app server enables `WS_WEB_EXTERNAL_SERVERS=true`. A fresh document
with `?server_origin=https://remote.example` restricts its Content Security Policy
to that validated origin plus its WSS counterpart and its own origin. The query
carries no credential. A compatible static host must supply equivalent headers;
a permissive HTML meta policy alone is insufficient.

## Identity and licensing

Central commercial login and each remote login have separate browser state and
keys. Remote servers use their password/recovery flow; central passkeys are
never submitted remotely. Full-document navigation discards archive memory
before changing installation/workspace. Authenticated requests reject redirects.
Remote permission and decryption grants are required in addition to the paid
app binding. The API/CLI does not require a commercial license.

The private registry allocates capacity transactionally from central data. A
remote reported device count is never a billing authority. Reconnection/tabs
reuse the same tuple; a temporarily offline active binding still occupies its
slot. Reserve/activate, explicit replace and release operations manage capacity.
External registration never performs a server-side fetch to the supplied URL.

External archives show “Storage managed by your server”. This means
there is no Wappie commercial storage quota; capacity still depends on the
external installation. Hosted and external numbers can share the commercial
workspace while only hosted archive bytes count toward its storage package.
