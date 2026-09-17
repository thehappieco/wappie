# Contributing to Wappie

Open an issue describing the behavior before large changes. Keep API compatibility and workspace/key isolation explicit. Use test numbers and synthetic fixtures; never commit production messages, credentials or database snapshots.

Run `WS_TEST_POSTGRES_REQUIRED=1 make check` against a PostgreSQL 18 test database and `make client-check`. The test harness creates isolated schemas and uses a non-superuser role, so row-level security remains active. See README for local database setup. Contributions are accepted under Apache-2.0.

App, console and billing changes belong to the private `wappie-cloud` repository. Public contributions must not depend on its sources or credentials. Run `make public-source` to verify the public snapshot boundary.

## Source and documentation language

Write public documentation, code comments, technical diagnostics and new identifiers in English. Prefer English names when a local identifier can be renamed without changing a public contract. Preserve existing API fields, protocol values and other compatibility-sensitive names unless a separately reviewed migration changes them.

Keep user-facing localization resources in their intended languages. Do not translate cryptographic vectors, byte-exact fixtures or captured protocol values as part of a language cleanup. Documentation and source language do not determine the user's interface locale.
