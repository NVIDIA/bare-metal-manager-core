/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

mod transform;

use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use clap::Parser;
use sqlx::ConnectOptions;
use sqlx::postgres::PgConnectOptions;

/// Generate a single idempotent "squash snapshot" migration from the
/// current database schema.
///
/// This tool:
///   1. Creates a temporary database.
///   2. Applies every existing migration via sqlx (same codepath as production).
///   3. Uses pg_dump to capture the resulting schema and seed data.
///   4. Transforms the DDL to be idempotent (IF NOT EXISTS, OR REPLACE, etc.).
///   5. Writes the result as a new migration file.
#[derive(Parser)]
#[command(name = "squash-migrations")]
struct Args {
    /// Remove all migration .sql files older than the generated
    /// squash migration file.
    #[arg(long)]
    delete_old: bool,

    /// Postgres user.
    /// Defaults to TESTDB_USER, assuming you're running
    /// this from the repo with a loaded up .envrc.
    #[arg(long, env = "TESTDB_USER", default_value = "postgres")]
    db_user: String,

    /// PostgreSQL password.
    /// Defaults to TESTDB_PASSWORD, assuming you're running
    /// this from the repo with a loaded up .envrc.
    #[arg(long, env = "TESTDB_PASSWORD", default_value = "admin")]
    db_password: String,

    /// PostgreSQL host.
    /// Defaults to TESTDB_HOST, assuming you're running
    /// this from the repo with a loaded up .envrc.
    #[arg(long, env = "TESTDB_HOST", default_value = "localhost")]
    db_host: String,

    /// Path to the migrations directory.
    /// Defaults to our <repo_root>/crates/api-db/migrations.
    #[arg(long)]
    migrations_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let migrations_dir = args.migrations_dir.unwrap_or_else(|| {
        let manifest = env!("CARGO_MANIFEST_DIR");
        Path::new(manifest)
            .join("../api-db/migrations")
            .canonicalize()
            .expect("cannot resolve migrations directory")
    });

    assert!(
        migrations_dir.is_dir(),
        "migrations directory does not exist: {}",
        migrations_dir.display()
    );

    let temp_db = format!("squash_migrations_temp_{}", std::process::id());

    // Create a temp database with our migrations in it.
    eprintln!("Creating temporary database: {temp_db}");
    let root_opts = connect_opts(&args.db_user, &args.db_password, &args.db_host, "postgres");
    let root_pool = sqlx::PgPool::connect_with(root_opts)
        .await
        .expect("cannot connect to postgres");

    sqlx::query(&format!("CREATE DATABASE \"{temp_db}\""))
        .execute(&root_pool)
        .await
        .expect("cannot create temp database");

    // Run migrations via sqlx.
    eprintln!("Running migrations via sqlx...");
    let temp_opts = connect_opts(&args.db_user, &args.db_password, &args.db_host, &temp_db);
    let temp_pool = sqlx::PgPool::connect_with(temp_opts)
        .await
        .expect("cannot connect to temp database");

    db::migrations::MIGRATOR
        .run(&temp_pool)
        .await
        .expect("migrations failed");

    let applied: (i64,) = sqlx::query_as("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&temp_pool)
        .await
        .expect("cannot count migrations");
    eprintln!("Applied {} migrations", applied.0);

    temp_pool.close().await;

    // ...and now dump the schema with pg_dump.
    eprintln!("Dumping schema...");
    let schema_dump = run_pg_dump(
        &[
            "--schema-only",
            "--no-owner",
            "--no-privileges",
            "--no-tablespaces",
            "--no-comments",
            "-U",
            &args.db_user,
            "-h",
            &args.db_host,
            &temp_db,
        ],
        &args.db_password,
    );

    // ..and also dump seed data with pg_dump.
    eprintln!("Dumping seed data...");
    let data_dump = run_pg_dump(
        &[
            "--data-only",
            "--inserts",
            "--on-conflict-do-nothing",
            "--no-owner",
            "--no-privileges",
            "--no-tablespaces",
            "--no-comments",
            "-U",
            &args.db_user,
            "-h",
            &args.db_host,
            &temp_db,
        ],
        &args.db_password,
    );

    // Drop temp database. We're done with it.
    eprintln!("Cleaning up temporary database...");
    sqlx::query(&format!(
        "DROP DATABASE IF EXISTS \"{temp_db}\" WITH (FORCE)"
    ))
    .execute(&root_pool)
    .await
    .ok();
    root_pool.close().await;

    // Now we transform the schema into a CREATE OR UPDATE style
    // migration, so we can lay it over the existing DB schema.
    eprintln!("Applying idempotency transforms...");
    let transformed_schema = transform::transform_schema(&schema_dump);
    let cleaned_data = transform::clean_data_dump(&data_dump);

    // Now generate a timestamp and write the snapshot file.
    let now = Utc::now();
    let timestamp = now.format("%Y%m%d%H%M%S").to_string();
    let today = now.format("%Y-%m-%d").to_string();
    let filename = format!("{timestamp}_squash_snapshot.sql");
    let squash_path = migrations_dir.join(&filename);

    eprintln!("Writing squash migration: {filename}");

    let mut content = format!(
        "-- Squash Snapshot Migration\n\
         --\n\
         -- This migration contains the complete database schema as of {today}.\n\
         -- It was generated by: cargo run -p squash-migrations\n\
         --\n\
         -- On fresh databases: creates the full schema from scratch.\n\
         -- On existing databases: all statements are idempotent (IF NOT EXISTS, OR REPLACE, etc.)\n\
         --   so this migration applies cleanly over the already-present schema.\n\
         --\n\
         -- The LAST_SQUASH_VERSION constant in crates/api-db/src/migrations/mod.rs must match\n\
         -- the timestamp prefix of this file ({timestamp}).\n\n"
    );

    content.push_str(&transformed_schema);

    if !cleaned_data.trim().is_empty() {
        content.push_str(
            "\n\n--\n\
             -- Seed data: rows inserted by original migrations that the schema depends on.\n\
             -- Uses ON CONFLICT DO NOTHING so these are safe to re-run on existing databases.\n\
             --\n\n",
        );
        content.push_str(&cleaned_data);
        content.push('\n');
    }

    std::fs::write(&squash_path, &content).expect("cannot write squash file");

    // If the user opted to optionally delete old migrations.
    if args.delete_old {
        eprintln!("Deleting old migration files...");
        let mut deleted = 0u32;
        for entry in std::fs::read_dir(&migrations_dir).expect("cannot read migrations dir") {
            let entry = entry.expect("cannot read dir entry");
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "sql") && path != squash_path {
                std::fs::remove_file(&path).expect("cannot delete migration file");
                deleted += 1;
            }
        }
        eprintln!("Deleted {deleted} old migration files");
    }

    eprintln!();
    eprintln!("Done!");
    eprintln!("Squash migration: {filename}");
    eprintln!("Timestamp (LAST_SQUASH_VERSION): {timestamp}");
    eprintln!();
    eprintln!("Next steps:");
    eprintln!(
        "  1. Update LAST_SQUASH_VERSION in crates/api-db/src/migrations/mod.rs to: {timestamp}"
    );
    eprintln!("  2. Run tests to verify: cargo test");
}

fn connect_opts(user: &str, password: &str, host: &str, database: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(host)
        .username(user)
        .password(password)
        .database(database)
        .log_statements(tracing::log::LevelFilter::Off)
}

fn run_pg_dump(args: &[&str], password: &str) -> String {
    let output = Command::new("pg_dump")
        .args(args)
        .env("PGPASSWORD", password)
        .output()
        .expect("failed to run pg_dump — is it installed?");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("pg_dump failed: {stderr}");
    }

    String::from_utf8(output.stdout).expect("pg_dump produced non-UTF8 output")
}
