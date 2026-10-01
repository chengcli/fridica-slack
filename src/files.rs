//! Authenticated reads of Slack-hosted files. Downloaded bytes are untrusted
//! data, never instructions.
use crate::BoxFuture;
use serde::{Deserialize, Serialize};

/// Most bytes of a file that are read.
pub const FILE_LIMIT: usize = 64 * 1024;
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
    RateLimited { retry_after: f64 },
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
}
