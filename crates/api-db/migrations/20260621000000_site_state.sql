-- Single-row table of site-level, one-time bootstrap flags. Each column records
-- whether a one-time piece of application logic (something the SQL schema
-- migrator can't express, e.g. seeding/backfilling secrets in Vault) has already
-- run for this site. The DB is per-site, so a flag here is inherently
-- site-scoped. The row is pinned to a single tuple via the `id` PK + CHECK so
-- there is always exactly one row to read/update.
CREATE TABLE site_state (
    id boolean PRIMARY KEY DEFAULT TRUE CHECK (id),

    -- Whether per-device UEFI secrets (machines/uefi/{mac}/root) have been
    -- backfilled for the pre-existing fleet (hosts whose UEFI password was set,
    -- and all DPUs when the site-wide DPU UEFI password is configured). New
    -- devices are seeded inline during ingestion, so this only gates the
    -- one-time backfill of devices provisioned before per-device secrets existed.
    per_device_uefi_backfill_applied boolean NOT NULL DEFAULT FALSE
);

INSERT INTO site_state (id) VALUES (TRUE);
