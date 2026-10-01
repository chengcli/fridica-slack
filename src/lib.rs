#![doc = include_str!("../README.md")]
mod connector;
pub mod discovery;
pub mod files;
pub mod history;
pub mod ingress;
pub mod links;
pub mod socket;
pub mod web;

pub use socket::{Acknowledgement, Intake, SocketMode, Status};
pub use web::{Failure, Identity, WebClient};

use serde_json::Value;
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicI64, Ordering},
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The journal could not record a boundary; the operation does not proceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recording;

/// The host's durable record of every Slack boundary: each request is
/// recorded before any I/O, and its outcome afterwards. Payloads never contain
/// credentials or Socket Mode tickets.
pub trait Journal: Send + Sync {
    /// The host's clock, in Unix seconds, for cache expiry.
    fn now(&self) -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(f64::NAN, |d| d.as_secs_f64())
    }
    /// Record a boundary event; returns its sequence number. `complete` is
    /// false when the record alone cannot replay the boundary exactly.
    fn record(
        &self,
        kind: &'static str,
        payload: Value,
        complete: bool,
    ) -> BoxFuture<'_, Result<i64, Recording>>;
    /// Record the outcome of `call` and mark `call` complete or not, atomically.
    fn complete(
        &self,
        call: i64,
        kind: &'static str,
        payload: Value,
        complete: bool,
    ) -> BoxFuture<'_, Result<(), Recording>>;
    /// A successful identity check, recorded before writes are enabled.
    fn identity(&self, _identity: &Identity) -> BoxFuture<'_, Result<(), Recording>> {
        Box::pin(async { Ok(()) })
    }
    /// A Socket Mode status change with its replay record, atomically.
    fn socket_state(
        &self,
        _status: Status,
        _record: Value,
        _complete: bool,
        _failed: bool,
    ) -> BoxFuture<'_, Result<(), Recording>> {
        Box::pin(async { Ok(()) })
    }
    /// Called once before Socket Mode first connects, e.g. to note that a
    /// previous run ended while connected.
    fn socket_recover(&self) -> BoxFuture<'_, Result<(), Recording>> {
        Box::pin(async { Ok(()) })
    }
}
/// Records nothing; for clients without a durable store (e.g. onboarding).
#[derive(Default)]
pub struct DiscardJournal(AtomicI64);
impl Journal for DiscardJournal {
    fn record(&self, _: &'static str, _: Value, _: bool) -> BoxFuture<'_, Result<i64, Recording>> {
        let seq = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        Box::pin(async move { Ok(seq) })
    }
    fn complete(
        &self,
        _: i64,
        _: &'static str,
        _: Value,
        _: bool,
    ) -> BoxFuture<'_, Result<(), Recording>> {
        Box::pin(async { Ok(()) })
    }
}

/// Unique identifiers for connections and pings, e.g. from a replayable source.
pub trait Ids: Send + Sync {
    fn next(&self, namespace: &str) -> String;
}

/// Who the client acts as and which channels it may read and write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    /// The Slack user the user token belongs to.
    pub owner: String,
    pub workspace: String,
    pub channels: Vec<String>,
}
impl Scope {
    pub fn channel(&self, channel: &str) -> bool {
        self.channels.iter().any(|c| c == channel)
    }
}
