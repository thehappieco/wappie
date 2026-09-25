-- Attested readers (milestone 2a of the hosted assistant connector).
--
-- A connection now names the reader that holds it. Until now there was one,
-- the process on this host (`hosted`); an attested reader runs in a Nitro
-- Enclave elsewhere and reaches this server over HMAC-signed HTTPS. Every
-- route the reader calls acts only on rows whose `reader` is the caller's, so
-- one reader cannot activate, read or revoke another's connections. Existing
-- rows are the hosted reader's, which is what the default says.
--
-- reader_measurement records, for operations, what the enclave declared when
-- the console prepared the consent: "nitro:pcr0=<96 hex>;doc=<64 hex>", the
-- PCR0 it reported and the SHA-256 of the attestation document the browser
-- verified. This server does not verify attestations (the browser does); the
-- value is a pointer back to the release, not a proof. NULL for `hosted`.
--
-- mcp_reader_state holds each attested reader's sealed state: its OAuth
-- clients, connections and token families, and its ACME account. The blobs
-- are sealed inside the enclave under a KMS key only the attested image can
-- use; this server stores bytes it cannot open and hands them back. The
-- generation makes every write a compare-and-swap, so a second writer or a
-- stale copy is a conflict rather than a silent overwrite.
--
-- No RLS on the new table, as with 0040: the reader is not a tenant, and the
-- rows are keyed by reader, not by workspace.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 41, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped and the enclave's health no longer answering, after
-- checking the ledger checksum against `migration41_sha256` in the release's
-- revisions.json:
--
--   1. Copy the state out first: it holds the enclave's ACME account, and CAA
--      names that account. For example
--        \copy (SELECT reader_id, name, generation, encode(blob, 'base64'), updated_at FROM mcp_reader_state) TO 'mcp_reader_state.csv' CSV
--      into the backup directory.
--   2. Then, in one transaction:
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      -- Without these the connector keys would stay live up to 365 days and
--      -- hold places under the per-workspace cap of five.
--      UPDATE api_keys SET revoked_at = now()
--       WHERE revoked_at IS NULL
--         AND id IN (SELECT api_key_id FROM mcp_connections WHERE reader <> 'hosted');
--      UPDATE mcp_connections SET status = 'revoked', revoked_at = now()
--       WHERE reader <> 'hosted' AND status IN ('pending', 'active');
--      DROP TABLE mcp_reader_state;
--      ALTER TABLE mcp_connections DROP COLUMN reader, DROP COLUMN reader_measurement;
--      DELETE FROM schema_migrations WHERE version = 41;
--      COMMIT;
--
-- The revoked rows stay in mcp_connections as history, like any revoked
-- connection.
ALTER TABLE mcp_connections
    ADD COLUMN reader text NOT NULL DEFAULT 'hosted' CHECK (reader ~ '^[a-z][a-z0-9]{0,15}$'),
    ADD COLUMN reader_measurement text;

CREATE TABLE mcp_reader_state (
    reader_id  text        NOT NULL,
    name       text        NOT NULL CHECK (name IN ('as-clients', 'as-connections', 'as-tokens', 'infra')),
    generation bigint      NOT NULL CHECK (generation > 0),
    blob       bytea       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (reader_id, name)
);
