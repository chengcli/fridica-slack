//! Events API envelopes and message normalization. Only bounded message
//! fields leave this module; raw envelopes are for the host's private journal.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Longest message text kept, in characters.
pub const TEXT_LIMIT: usize = 40_000;
/// Largest envelope, frame or API response accepted, in bytes.
pub const ENVELOPE_LIMIT: usize = 4 * 1024 * 1024;

fn text(value: &Value, key: &str, limit: usize) -> String {
    value[key]
        .as_str()
        .unwrap_or("")
        .chars()
        .take(limit)
        .collect()
}
/// Slack timestamps are ASCII decimal strings; reject nonfinite/Unicode values.
pub fn timestamp(value: &str) -> bool {
    let Some((whole, fraction)) = value.split_once('.') else {
        return false;
    };
    !whole.is_empty()
        && !fraction.is_empty()
        && whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
        && value.parse::<f64>().is_ok_and(f64::is_finite)
}
/// No credentials, port, redirect host or URL parser normalization can change
/// the authority that would receive a token. This is a check, not a downloader.
pub fn file_url(value: &str) -> bool {
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    scheme.eq_ignore_ascii_case("https") && host.eq_ignore_ascii_case("files.slack.com")
}

/// A user message in a channel, normalized from an Events API callback or a
/// history page.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub event_id: String,
    pub workspace: String,
    pub channel: String,
    pub sender: String,
    pub ts: String,
    /// The thread root, when this is a reply.
    pub thread_ts: Option<String>,
    pub text: String,
    /// File names, as Slack sent them.
    pub files: Vec<Value>,
    /// Where the message came from, e.g. `socket` or `catchup`.
    pub source: String,
    /// The message's `metadata`, unparsed (`null` when absent).
    pub metadata: Value,
    /// Readable files: id, name, mimetype, size and a Slack file URL (or "").
    pub attachments: Vec<Value>,
}
/// Normalize an `event_callback` payload carrying a plain message, a file
/// share or a thread broadcast; anything else is `None`.
pub fn normalize(payload: &Value, source: &str) -> Option<Message> {
    if payload["type"] != "event_callback" {
        return None;
    }
    let event = &payload["event"];
    if event["type"] != "message"
        || !matches!(
            event["subtype"].as_str(),
            None | Some("file_share" | "thread_broadcast")
        )
        || (!event["subtype"].is_null() && !event["subtype"].is_string())
    {
        return None;
    }
    let mut fields = Vec::new();
    for value in [
        &payload["event_id"],
        &payload["team_id"],
        &event["channel"],
        &event["user"],
        &event["ts"],
    ] {
        let field = value.as_str()?;
        if field.is_empty() {
            return None;
        }
        fields.push(field.to_string());
    }
    let ts = &fields[4];
    if !timestamp(ts) {
        return None;
    }
    let thread = match &event["thread_ts"] {
        Value::Null => None,
        Value::String(t) if timestamp(t) => (t != ts).then(|| t.clone()),
        _ => return None,
    };
    let mut files = vec![];
    let mut attachments = vec![];
    for item in event["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v.is_object())
    {
        files.push(item.get("name").cloned().unwrap_or(json!("")));
        if item["id"].is_string() && item["name"].is_string() {
            let url = item["url_private"].as_str().unwrap_or("");
            attachments.push(json!({"id":text(item,"id",32),"name":text(item,"name",200),
                "mimetype":text(item,"mimetype",100),"size":item["size"].as_u64().unwrap_or(0),
                "url":if file_url(url) {url} else {""}}));
        }
    }
    let body = text(event, "text", TEXT_LIMIT);
    if body.is_empty() && files.is_empty() {
        return None;
    }
    Some(Message {
        event_id: fields[0].clone(),
        workspace: fields[1].clone(),
        channel: fields[2].clone(),
        sender: fields[3].clone(),
        ts: ts.clone(),
        thread_ts: thread,
        text: body,
        files,
        source: source.into(),
        metadata: event["metadata"].clone(),
        attachments,
    })
}

/// A decoded Socket Mode envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct Envelope {
    /// `events_api`, `hello`, `disconnect`, `interactive`, ...
    pub kind: String,
    /// Empty for `hello` and `disconnect`, which are not acknowledged.
    pub id: String,
    /// The whole envelope, with any legacy verification `token` removed.
    pub value: Value,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    TooLarge,
    InvalidJson,
    MissingType,
    InvalidId,
}
impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "Slack envelope exceeds size limit",
            Self::InvalidJson => "invalid Slack envelope JSON",
            Self::MissingType => "missing Slack envelope type",
            Self::InvalidId => "invalid Slack envelope ID",
        })
    }
}
impl std::error::Error for EnvelopeError {}
pub fn envelope(bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
    if bytes.len() > ENVELOPE_LIMIT {
        return Err(EnvelopeError::TooLarge);
    }
    let mut value: Value = serde_json::from_slice(bytes).map_err(|_| EnvelopeError::InvalidJson)?;
    // Legacy verification tokens are authentication material, not event data.
    if let Some(payload) = value.get_mut("payload").and_then(Value::as_object_mut) {
        payload.remove("token");
    }
    let kind = value["type"]
        .as_str()
        .ok_or(EnvelopeError::MissingType)?
        .to_owned();
    let id = if matches!(kind.as_str(), "hello" | "disconnect") {
        String::new()
    } else {
        value["envelope_id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 256)
            .ok_or(EnvelopeError::InvalidId)?
            .to_owned()
    };
    Ok(Envelope { kind, id, value })
}
