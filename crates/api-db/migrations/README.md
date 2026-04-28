# Postgres Database Migrations

This directory contains `sqlx` migrations for the NICo Postgres database.

## How squashing works

Over time, hundreds of incremental migrations accumulate and slow down fresh
database setup, bloat the compiled binary (the `sqlx::migrate!()` macro embeds
every file), and make it harder to understand the current schema. Squashing
replaces all existing migrations with a single **squash snapshot** that
recreates the full schema from scratch.

### What happens at runtime

The `migrate()` function in `crates/api-db/src/migrations/mod.rs` runs the
following logic before applying migrations:

```text
DELETE FROM _sqlx_migrations WHERE version < LAST_SQUASH_VERSION
```

- **Existing databases:** Old migration tracking rows are removed so sqlx
  doesn't complain about missing files. The squash snapshot then runs; because
  every statement in it is idempotent (`IF NOT EXISTS`, `OR REPLACE`, etc.) it
  completes as a no-op over the already-present schema.
- **Fresh databases:** The `_sqlx_migrations` table doesn't exist yet, so the
  `DELETE` harmlessly fails. The squash snapshot creates the entire schema.

### Generating a new squash

Use the `squash-migrations` tool (in `crates/squash-migrations`):

```
# Preview only (does not delete old migrations):
cargo run -p squash-migrations

# Generate and clean up in one step:
cargo run -p squash-migrations -- --delete-old
```

The tool will:

1. Create a temporary database.
2. Apply every existing migration via sqlx (the same codepath as production).
3. Use `pg_dump` to capture the resulting schema and seed data.
4. Transform the DDL to be idempotent (adds `IF NOT EXISTS`, wraps
   constraints/types in `DO $$ ... EXCEPTION` blocks, etc.).
5. Write a new `<timestamp>_squash_snapshot.sql` migration.
6. Optionally delete all older migration files.

The tool reads database connection settings from environment variables
(see `.envrc`), or you can pass them as CLI flags:

- `--db-user` or `env:TESTDB_USER` (defaults to: `postgres`).
- `--db-password` or `env:TESTDB_PASSWORD` (defaults to: `admin`).
- `--db-host` or `env:TESTDB_HOST` (defaults to: `localhost`).

Run `cargo run -p squash-migrations -- --help` for all options.

### After generating a squash

1. Update `LAST_SQUASH_VERSION` in `crates/api-db/src/migrations/mod.rs` to
   match the timestamp prefix of the new squash file.
2. Delete all migration files older than the squash (or use `--delete-old`).
3. Run the full test suite to verify: `cargo test`.
