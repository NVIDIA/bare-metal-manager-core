/*

/// admin_cli.rs
///
/// General utility code for working with and displaying data
/// with the admin CLI.

*/

use sqlx::{Pool, Postgres};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};

/// SUMMARY is a global variable that is being used by a few structs which
/// implement serde::Serialize with skip_serialization_if.
///
/// I had wanted the ability to have summarized or extended versions of
/// serialized output, and decided I could use skip_serialization_if along with
/// a function that looks at a global variable.
///
/// You set --extended on the CLI, which controls whether or not to summarized
/// (default is summarized).
static SUMMARY: AtomicBool = AtomicBool::new(false);

pub fn serde_just_print_summary<T>(_: &T) -> bool {
    SUMMARY.load(Ordering::SeqCst)
}

pub fn just_print_summary() -> bool {
    SUMMARY.load(Ordering::SeqCst)
}

pub fn set_summary(val: bool) {
    SUMMARY.store(val, Ordering::SeqCst);
}

/// get_db_url returns the full DB URL to use for connecting (and resetting,
/// if requested).
pub fn get_db_url(db_url: &str, db_name: &str) -> String {
    // Attempt to grab the DATABASE_URL first.
    // If it doesn't exist, fall back to args.db_url.
    let db_base = match env::var("DATABASE_URL") {
        Ok(val) => val,
        Err(_) => db_url.to_string(),
    };
    db_base + "/" + db_name
}

/// connect connects to the database for the provided db_url, which probably
/// comes from get_db_url.
pub async fn connect(db_url: &str) -> eyre::Result<Pool<Postgres>> {
    let pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(db_url).await?;
    Ok(pool)
}
