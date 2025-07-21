use crate::threat::ClientFail;

#[derive(thiserror::Error, Debug)]
pub enum ReportableError {
    #[error("Request timeout (re::rt)")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Networking error - {0:?} (re:ne)")]
    IoError(#[from] tokio::io::Error),
    #[error("Bad request (re::br)")]
    ClientError(#[from] ClientFail),
    #[error("Unknown error (re::??)")]
    Anyhow(#[from] anyhow::Error),
}
