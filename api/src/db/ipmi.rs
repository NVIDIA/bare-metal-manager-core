use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IpmiIp {
    pub ip: String,
}

impl<'r> sqlx::FromRow<'r, PgRow> for IpmiIp {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(IpmiIp {
            ip: row.try_get("ip")?,
        })
    }
}
impl IpmiIp {
    pub async fn new(id: Uuid, pool: PgPool) -> Result<Self, sqlx::Error> {
        let query =
            r#"SELECT topology->>'ipmi_ip' AS ip FROM machine_topologies where machine_id=$1"#;
        Ok(sqlx::query_as::<_, IpmiIp>(query)
            .bind(id)
            .fetch_one(&pool)
            .await?)
    }
}
