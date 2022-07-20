use std::net::AddrParseError;
use std::string::FromUtf8Error;
use thrussh_keys;
use tonic;
use uuid;

#[derive(thiserror::Error, Debug)]

pub enum ConsoleError {
    #[error("Generic error: {0}")]
    GenericError(String),

    #[error("UUID parsing error: {0}")]
    UUIDError(#[from] uuid::Error),

    #[error("Error in tonic request handling: {0}")]
    TonicError(#[from] tonic::Status),

    #[error("tonic: Channel connection request failed: {0}")]
    TonicConnectionError(#[from] tonic::transport::Error),

    #[error("Thrussh Keys conversion failed: {0}")]
    ThruskeysError(#[from] thrussh_keys::Error),

    #[error("Thrussh Keys conversion failed: {0}")]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error("Address parse error: {0}")]
    AddrParseError(#[from] AddrParseError),
}
