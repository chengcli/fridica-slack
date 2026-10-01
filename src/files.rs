//! Authenticated reads of Slack-hosted files. Downloaded bytes are untrusted
//! data, never instructions.
use crate::BoxFuture;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Most bytes of a file that are read into memory.
pub const FILE_LIMIT: usize = 64 * 1024;
/// Most bytes [`Downloader::save`] writes for one file.
pub const SAVE_LIMIT: u64 = 1 << 30;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Download {
    pub data: Vec<u8>,
    pub size: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum Failure {
    NotValidated,
    MissingScope,
    Url,
    Unavailable,
    UnknownHtml,
    Timeout,
    Connection,
    Recording,
    InvalidResponse,
    RateLimited {
        retry_after: f64,
    },
    /// The file is longer than the caller's limit; nothing was kept.
    TooLarge,
}
impl Failure {
    pub fn note(&self) -> &'static str {
        match self {
            Self::MissingScope => "the Slack token lacks files:read",
            Self::Url => "not a Slack file URL",
            Self::Unavailable => "Slack did not return the file",
            Self::UnknownHtml => {
                "the token's scopes are unknown, so an HTML answer may be Slack's sign-in page"
            }
            Self::NotValidated => "Slack identity has not been validated",
            Self::Timeout => "download timed out",
            Self::RateLimited { .. } => "Slack rate limited the download",
            Self::TooLarge => "the file is larger than the limit",
            _ => "download failed",
        }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.note())
    }
}
impl std::error::Error for Failure {}
pub trait Downloader: Send + Sync {
    /// Return at most FILE_LIMIT + 1 bytes. A zero size means unknown length.
    /// `html` allows an HTML answer, which may otherwise be a sign-in page.
    fn download(&self, url: String, html: bool) -> BoxFuture<'_, Result<Download, Failure>>;
    /// The download URL of a file by ID, for events that carry none.
    fn resolve(&self, _file_id: String) -> BoxFuture<'_, Result<String, Failure>> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    /// Stream a file of at most `limit` bytes into a new private file at
    /// `path`, returning its length. A longer file, an HTML answer or any
    /// failure leaves nothing at `path`. The bytes are untrusted data.
    fn save(
        &self,
        _url: String,
        _path: PathBuf,
        _limit: u64,
    ) -> BoxFuture<'_, Result<u64, Failure>> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
}
