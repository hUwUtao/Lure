use crate::threat::ClientFail;

#[derive(thiserror::Error, Debug)]
pub enum ReportableError {
    #[error("Request timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Networking error - {0:?}")]
    IoError(#[from] tokio::io::Error),
    #[error("Bad request")]
    ClientError(#[from] ClientFail),
    #[error("Unknown error")]
    Anyhow(#[from] anyhow::Error),
}
