//! Slack message permalinks. Permalinks select message IDs, never HTTP
//! destinations; linked text is untrusted data.
use crate::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Most permalinks taken from one text.
pub const LINK_LIMIT: usize = 3;
/// Most messages read for one link (a root and its replies).
pub const REPLY_LIMIT: usize = 51;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub link: String,
    pub channel: String,
    pub ts: String,
    pub root: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub sender: String,
    pub text: String,
    pub ts: String,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    Unavailable,
    Recording,
}
/// Reads the messages a permalink points to.
pub trait Reader: Send + Sync {
    fn fetch(&self, link: Link) -> BoxFuture<'_, Result<Vec<Entry>, Failure>>;
}

pub fn timestamp(text: &str) -> bool {
    text.len() <= 32
        && text.split_once('.').is_some_and(|(a, b)| {
            !a.is_empty() && !b.is_empty() && a.bytes().chain(b.bytes()).all(|v| v.is_ascii_digit())
        })
}

/// Up to [`LINK_LIMIT`] distinct message permalinks in `text`.
pub fn permalinks(text: &str) -> Vec<Link> {
    let mut found: Vec<Link> = vec![];
    for (start, _) in text.match_indices("https://") {
        let rest = &text[start + 8..];
        let host_len = rest
            .bytes()
            .take_while(|v| v.is_ascii_alphanumeric() || *v == b'.' || *v == b'-')
            .count();
        let host = &rest[..host_len];
        if !host
            .strip_suffix(".slack.com")
            .is_some_and(|s| !s.is_empty())
        {
            continue;
        }
        let Some(path) = rest[host_len..].strip_prefix("/archives/") else {
            continue;
        };
        let channel_len = path
            .bytes()
            .take_while(|v| v.is_ascii_uppercase() || v.is_ascii_digit())
            .count();
        let channel = &path[..channel_len];
        if channel.len() < 3 || !matches!(channel.as_bytes()[0], b'C' | b'G') {
            continue;
        }
        let Some(path) = path[channel_len..].strip_prefix("/p") else {
            continue;
        };
        let digits = path.bytes().take_while(u8::is_ascii_digit).count();
        if !(7..=31).contains(&digits) {
            continue;
        }
        let ts = format!("{}.{}", &path[..digits - 6], &path[digits - 6..digits]);
        if found.iter().any(|v| v.channel == channel && v.ts == ts) {
            continue;
        }
        let root = path[digits..].strip_prefix('?').and_then(|query| {
            let query = query
                .split(|v: char| v.is_whitespace() || v == '|' || v == '>')
                .next()
                .unwrap_or("");
            query.split('&').find_map(|part| {
                let value = part.strip_prefix("thread_ts=")?;
                let integer = value.bytes().take_while(u8::is_ascii_digit).count();
                let fraction = value[integer..].strip_prefix('.')?;
                let end = integer + 1 + fraction.bytes().take_while(u8::is_ascii_digit).count();
                timestamp(&value[..end]).then(|| value[..end].to_owned())
            })
        });
        found.push(Link {
            link: format!("https://{host}/archives/{channel}/p{}", &path[..digits]),
            channel: channel.into(),
            ts,
            root,
        });
        if found.len() == LINK_LIMIT {
            break;
        }
    }
    found
}

/// Select the target from one bounded replies page. A root includes subsequent
/// replies; a reply link selects that reply only, matching the frozen adapter.
pub fn select(messages: &[Value], ts: &str) -> Vec<Entry> {
    let valid: Vec<_> = messages
        .iter()
        .take(REPLY_LIMIT)
        .filter(|m| m["text"].is_string())
        .collect();
    let Some(index) = valid.iter().position(|m| m["ts"] == ts) else {
        return vec![];
    };
    let target = valid[index];
    let root = target["thread_ts"].is_null() || target["thread_ts"] == ts;
    valid[index..]
        .iter()
        .take(if root { REPLY_LIMIT } else { 1 })
        .map(|m| Entry {
            sender: m["user"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| m["bot_id"].as_str())
                .unwrap_or("")
                .into(),
            text: m["text"]
                .as_str()
                .unwrap()
                .chars()
                .take(crate::ingress::TEXT_LIMIT)
                .collect(),
            ts: m["ts"].as_str().unwrap_or("").into(),
        })
        .collect()
}
