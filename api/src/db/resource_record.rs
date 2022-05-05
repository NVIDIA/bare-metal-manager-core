use crate::CarbideResult;
use ipnetwork::IpNetwork;
use log::info;
use rpc::v0 as rpc;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    record: IpNetwork,
}

#[derive(Default, Debug, Clone, FromRow)]
pub struct Dnsrr {
    rdata: Option<ResourceRecord>,
}

#[derive(Default, Debug, Clone)]
pub struct DnsQuestion {
    pub q_name: Option<String>,
    pub q_type: Option<u32>,
    pub q_class: Option<u32>,
}

#[derive(Default, Debug, Clone)]
pub struct DnsResponse {
    pub rrs: Vec<Dnsrr>,
    pub rcode: Option<u32>,
}

impl DnsResponse {
    pub fn rr(&mut self, rr: Dnsrr) -> &mut DnsResponse {
        self.rrs.push(rr);
        self
    }

    pub fn rcode(&mut self, rcode: u32) -> &mut DnsResponse {
        self.rcode = Some(rcode);
        self
    }
}

impl<'r> FromRow<'r, PgRow> for ResourceRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(ResourceRecord {
            record: row.try_get("resource_record")?,
        })
    }
}

impl From<ResourceRecord> for String {
    fn from(value: ResourceRecord) -> Self {
        value.record.to_string()
    }
}

// Protobuf does not have an IPAddr type, so convert to string
impl From<Dnsrr> for rpc::dns_message::dns_response::Dnsrr {
    fn from(dns: Dnsrr) -> Self {
        rpc::dns_message::dns_response::Dnsrr {
            rdata: dns.rdata.map(|r| r.record.ip().to_string()),
        }
    }
}

impl From<DnsResponse> for rpc::dns_message::DnsResponse {
    fn from(dns: DnsResponse) -> Self {
        rpc::dns_message::DnsResponse {
            rcode: dns.rcode,
            rrs: dns.rrs.into_iter().map(|rr| rr.into()).collect(),
        }
    }
}

impl DnsQuestion {
    pub async fn find_record(
        txn: &mut Transaction<'_, Postgres>,
        question: DnsQuestion,
    ) -> CarbideResult<DnsResponse> {
        let mut response = DnsResponse::default();

        info!("{:?}", question);
        let _record = match question.q_type {
            Some(1) => {
                let result = sqlx::query_as::<_, ResourceRecord>(
                    "SELECT resource_record from dns_records WHERE q_name=$1",
                )
                .bind(Some(question.q_name))
                .fetch_one(&mut *txn)
                .await?;
                info!("{:?}", result);
                let rr = Dnsrr {
                    rdata: Some(result),
                };
                response.rrs.push(rr);
                response.rcode = Some(1);
            }
            None => (),
            _ => (),
        };

        Ok(response)
    }
}
