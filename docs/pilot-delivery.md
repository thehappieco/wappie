# Wappie pilot delivery — 2026-09-08

## Delivered phases

1. Global identities, workspace memberships and independent sessions per company. Identity-only access supports recovery and accepting an invitation when no active workspace remains.
2. Member management, role changes, invitations, last-owner protection and live revocation of sessions/tokens/grants.
3. Independent device read/send/manage permissions, enforced on HTTP media and WebSocket. Historical content still needs a sealed key grant.
4. Workspace console, member and device permission forms, integration tokens, company selection, and messaging entry point. A company switch loads a fresh document. Logout revokes the current token even after a password change.
5. Private simulated subscriptions, idempotent approved/declined outcomes, capacity enforcement and refusal to reduce capacity below occupied slots. No real payments or prices.
6. Apache-2.0 public core, private cloud repository, homepage, HTTP/WebSocket documentation, isolated EC2 deployment and HTTPS on all four product addresses.

## Published addresses

- https://wappie.thehappie.co — homepage and `/docs/`
- https://console.wappie.thehappie.co — workspace administration
- https://app.wappie.thehappie.co — messages
- https://api.wappie.thehappie.co — HTTP/WebSocket
- https://github.com/thehappieco/wappie — public core
- `thehappieco/wappie-cloud` — private commercial module

Two empty workspaces, Piloto A and Piloto B, have two connection slots each. Owner invites are retained privately outside source control. No password or WhatsApp number was supplied or invented for a real user. Sign up with an owner invite, retain the recovery code, then pair the chosen test phones. Existing identities join the other company by accepting an invite in the console.

## Validation

- Full Go checks with race detection and required PostgreSQL isolation tests.
- Browser client tests, type checking and production builds for OSS and hosted variants.
- Separate private billing tests for approval/decline, idempotency, forbidden capacity reduction and unauthenticated requests.
- Static analysis and reachable-vulnerability scan; secret scan excludes only inspected generated cryptographic fixtures.
- Running API readiness, unauthorized HTTP rejection, private metrics, and HTTPS responses for product and documentation routes.
- Initial database/object-storage snapshot on the EC2; database restored into a temporary verification database and checked, then that temporary database removed.

## Operational boundaries

This remains a free pilot for test numbers on a single EC2. No production-grade high availability or independent off-host backup destination has been configured. The local backup is useful for release recovery but does not protect against loss of the host. Mobile/watch clients and live payment-provider integration remain future product work, as agreed.

The original development checkout and its existing origin/history are preserved. The public repository was initialized from a secret-scanned snapshot instead of publishing the old development history.
