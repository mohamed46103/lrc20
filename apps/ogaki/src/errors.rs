#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("No compatible asset found")]
    NoCompatibleAsset,

    #[error("LRC20d binary not found")]
    Lrc20dNotFound,

    #[error("{0}")]
    Other(#[from] eyre::Report),
}
