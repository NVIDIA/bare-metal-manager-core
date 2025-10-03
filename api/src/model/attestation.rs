use chrono::{DateTime, Utc};
use forge_uuid::machine::MachineId;
use sqlx::FromRow;

#[derive(FromRow, Debug)]
pub struct EkCertVerificationStatus {
    pub ek_sha256: Vec<u8>,
    pub serial_num: String,
    pub signing_ca_found: bool,
    pub issuer: Vec<u8>,
    pub issuer_access_info: Option<String>,
    pub machine_id: MachineId,
    // pub ca_id: Option<i32>, // currently unused
}

#[derive(FromRow, Debug, sqlx::Encode)]
pub struct SecretAkPub {
    pub secret: Vec<u8>,
    pub ak_pub: Vec<u8>,
}

#[derive(FromRow, Debug, sqlx::Encode)]
pub struct TpmCaCert {
    pub id: i32,
    pub not_valid_before: DateTime<Utc>,
    pub not_valid_after: DateTime<Utc>,
    #[sqlx(default)]
    pub ca_cert_der: Vec<u8>,
    pub cert_subject: Vec<u8>,
}
