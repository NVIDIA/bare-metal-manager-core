mod migrator;

pub struct Migrator;

use log::info;
use refinery::Report;
use super::Pool;
use crate::CarbideResult;

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("src/db/migrations");
}

impl Migrator {
    pub async fn migrate(db: Pool) -> CarbideResult<Report> {
        let mut client = db.dedicated_connection().await.unwrap();

        info!("Performing database migrations");

        Ok(embedded::migrations::runner()
            .run_async(&mut client)
            .await?)
    }
}
