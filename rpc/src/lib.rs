use std::convert::From;
use std::convert::TryFrom;

tonic::include_proto!("carbide");

impl From<uuid::Uuid> for Uuid {
    fn from(uuid: uuid::Uuid) -> Uuid {
        Uuid { value: uuid.to_hyphenated().to_string() }
    }
}

impl TryFrom<Uuid> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        uuid::Uuid::parse_str(&uuid.value)
    }
}
