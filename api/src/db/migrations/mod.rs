use crate::CarbideResult;
use sqlx::PgPool;

mod migrator;

#[tracing::instrument(skip(pool))]
pub async fn migrate(pool: &PgPool) -> CarbideResult<()> {
    Ok(sqlx::migrate!().run(pool).await?)
}
