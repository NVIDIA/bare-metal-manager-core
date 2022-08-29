use sqlx::PgPool;

use crate::CarbideResult;

mod migrator;

pub async fn migrate(pool: &PgPool) -> CarbideResult<()> {
    log::info!("Performing database migrations");

    Ok(sqlx::migrate!().run(pool).await?)
}
