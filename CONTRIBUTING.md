# Contributing to Wappie

Open an issue describing the behavior before large changes. Keep API compatibility and workspace/key isolation explicit. Use test numbers and synthetic fixtures; never commit production messages, credentials or database snapshots.

Run `WS_TEST_POSTGRES_REQUIRED=1 make check` against a PostgreSQL 18 test database and `make client-check`. The test harness creates isolated schemas and uses a non-superuser role, so row-level security remains active. See README for local database setup. Contributions are accepted under Apache-2.0.

App, console and billing changes belong to the private `wappie-cloud` repository. Public contributions must not depend on its sources or credentials. Run `make public-source` to verify the public snapshot boundary.
