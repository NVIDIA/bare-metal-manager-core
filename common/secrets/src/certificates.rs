use ::rpc::protos::forge::MachineCertificate;
use async_trait::async_trait;

#[derive(Debug, Clone, Default)]
pub struct Certificate {
    pub issuing_ca: Vec<u8>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl From<Certificate> for MachineCertificate {
    fn from(value: Certificate) -> Self {
        MachineCertificate {
            issuing_ca: value.issuing_ca,
            private_key: value.private_key,
            public_key: value.public_key,
        }
    }
}

#[async_trait]
pub trait CertificateProvider: Send + Sync {
    async fn get_certificate(&self, unique_identifier: &str) -> Result<Certificate, eyre::Report>;
}
