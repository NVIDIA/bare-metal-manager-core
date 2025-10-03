use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    record: IpAddr,
}

impl<'r> FromRow<'r, PgRow> for ResourceRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(ResourceRecord {
            record: row.try_get("resource_record")?,
        })
    }
}

impl From<ResourceRecord> for rpc::forge::dns_message::dns_response::Dnsrr {
    fn from(rr: ResourceRecord) -> Self {
        rpc::forge::dns_message::dns_response::Dnsrr {
            rdata: Some(rr.record.to_string()),
        }
    }
}
