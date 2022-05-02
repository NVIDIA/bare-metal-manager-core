use std::str::Utf8Error;

#[derive(thiserror::Error, Debug)]
pub enum CarbideClientError {
    #[error("Generic error: {0}")]
    GenericError(String),

    #[error("Could not chunk the udev address into 2 length strings {0}")]
    Utf8Error(#[from] Utf8Error),

    #[error("Generic Udev Error {0}")]
    UdevError(#[from] libudev::Error),

    #[error("Generic Tonic transport error {0}")]
    TonicTransportError(#[from] tonic::transport::Error),

    #[error("Generic Tonic status error {0}")]
    TonicStatusError(#[from] tonic::Status),
}

pub type CarbideClientResult<T> = Result<T, CarbideClientError>;
