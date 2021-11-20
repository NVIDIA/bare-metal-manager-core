mod migrator;

use crate::CarbideResult;
use log::info;
use sqlx::PgPool;

pub async fn migrate(pool: &PgPool) -> CarbideResult<()> {
    info!("Performing database migrations");

    Ok(sqlx::migrate!().run(pool).await?)
}
