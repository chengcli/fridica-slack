//! One page of `conversations.history` or `conversations.replies`. Paging
//! policy and watermarks belong to the host.
use crate::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PageRequest {
    pub method: Method,
    pub channel: String,
    pub oldest: String,
    /// The thread root, for `conversations.replies`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limit: usize,
    pub include_all_metadata: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Method {
    #[serde(rename = "conversations.history")]
    History,
    #[serde(rename = "conversations.replies")]
    Replies,
}
/// Fixed, non-secret errors; never transport URLs, headers or credentials.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum HistoryFailure {
    Timeout,
    Connection,
    InvalidResponse,
    /// Slack refused the request; `code` is Slack's `error` (e.g.
    /// `thread_not_found`), or a fixed name for a local refusal.
    Rejected {
        code: String,
    },
    RateLimited {
        retry_after: f64,
    },
}
impl std::fmt::Display for HistoryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Slack history request failed: {self:?}; watermark unchanged"
        )
    }
}
impl std::error::Error for HistoryFailure {}
/// A source of history pages; the response is Slack's JSON, unmodified.
pub trait History: Send + Sync {
    fn page(&self, request: PageRequest) -> BoxFuture<'_, Result<Value, HistoryFailure>>;
}
