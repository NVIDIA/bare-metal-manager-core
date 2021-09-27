//! Carbide gRPC and protobuf module
//!
//! This module contains the gRPC and protocol buffer definitions to generate a client or server to
//! interact with the API Service
//!
pub mod v0 {
    use std::convert::From;
    use std::convert::TryFrom;

    tonic::include_proto!("carbide.v0");

    impl From<uuid::Uuid> for Uuid {
        fn from(uuid: uuid::Uuid) -> Uuid {
            Uuid {
                value: uuid.to_hyphenated().to_string(),
            }
        }
    }

    impl TryFrom<Uuid> for uuid::Uuid {
        type Error = uuid::Error;
        fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
            uuid::Uuid::parse_str(&uuid.value)
        }
    }
}
