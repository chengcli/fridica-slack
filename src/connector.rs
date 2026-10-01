//! The HTTP transport under `slack-morphism`: every call is journaled before
//! I/O with credentials redacted, has no redirects or retries, reads at most
//! [`ENVELOPE_LIMIT`] bytes, keeps the raw outcome (status, rate-limit and
//! scope headers, body) for the journal, and classifies failures so a send
//! that may have reached Slack is never mistaken for a rejection.
use crate::{ingress::ENVELOPE_LIMIT, web::Failure, Journal};
use reqwest::{
    header::{HeaderValue, AUTHORIZATION},
    Client, RequestBuilder, Url,
};
use serde_json::{json, Value};
use slack_morphism::{
    errors::{SlackClientError, SlackClientSystemError},
    multipart_form::FileMultipartData,
    ClientResult, SlackClientApiCallContext, SlackClientHttpConnector, SlackClientId,
    SlackClientSecret,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

pub(crate) struct Response {
    pub status: u16,
    pub retry_after: Option<String>,
    pub scopes: Option<String>,
    pub body: Vec<u8>,
}
/// Methods Slack reads only from form fields; nested values are JSON strings.
const FORM_METHODS: [&str; 2] = ["files.getUploadURLExternal", "files.completeUploadExternal"];

pub(crate) struct Transport {
    pub client: Client,
    pub journal: Arc<dyn Journal>,
    pub base: Url,
    pub timeout: Duration,
    /// The `x-oauth-scopes` header of the latest `auth.test` response.
    pub scopes: Mutex<Option<String>>,
}
impl Transport {
    /// `loopback` ignores the proxy environment, for test servers; otherwise
    /// the owner's proxy settings apply.
    pub fn new(
        journal: Arc<dyn Journal>,
        timeout: Duration,
        base: Url,
        loopback: bool,
    ) -> Result<Self, Failure> {
        if timeout.is_zero() {
            return Err(Failure::Configuration);
        }
        let builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(10)));
        let builder = if loopback {
            builder.no_proxy()
        } else {
            builder
        };
        Ok(Self {
            client: builder.build().map_err(|_| Failure::Configuration)?,
            journal,
            base,
            timeout,
            scopes: Mutex::new(None),
        })
    }
    pub fn url(&self, method: &str) -> Result<Url, Failure> {
        self.base.join(method).map_err(|_| Failure::Configuration)
    }
    /// Journal the call, send it, and journal the outcome.
    pub async fn call(
        &self,
        method: &str,
        arguments: Value,
        context: Option<Value>,
        token: &str,
        request: RequestBuilder,
    ) -> Result<Response, Failure> {
        let mut record = json!({"method":method,"arguments":arguments,"context":context});
        redact(&mut record, token);
        let call = self
            .journal
            .record("slack_http_call", record, false)
            .await
            .map_err(|_| Failure::Recording)?;
        let result = read(request).await;
        let mut complete = !matches!(result, Err(Failure::ResponseLimit));
        let record = match &result {
            Ok(response) => {
                let body = match serde_json::from_slice::<Value>(&response.body) {
                    Ok(mut value) => {
                        redact(&mut value, token);
                        if method == "apps.connections.open" {
                            value
                                .as_object_mut()
                                .map(|v| v.insert("url".into(), json!("[socket credential]")));
                        }
                        json!({"json":value})
                    }
                    Err(_) if method == "apps.connections.open" => {
                        complete = false;
                        json!({"omitted":"invalid connection response may contain credentials"})
                    }
                    Err(_) => {
                        let mut bytes = response.body.clone();
                        // Keep malformed/binary responses, without a reflected credential.
                        scrub_bytes(&mut bytes, token.as_bytes());
                        json!({"bytes":bytes})
                    }
                };
                json!({"call":call,"status":response.status,"retry_after":safe_header(&response.retry_after,token),"scopes":safe_header(&response.scopes,token),"body":body})
            }
            Err(failure) => json!({"call":call,"failure":failure}),
        };
        // Timeouts and body failures may have lost a prefix of the response.
        if matches!(result, Err(Failure::Timeout | Failure::Connection)) {
            complete = false;
        }
        self.journal
            .complete(call, "slack_http_result", record, complete)
            .await
            .map_err(|_| Failure::Recording)?;
        if method == "auth.test" {
            if let Ok(response) = &result {
                *self.scopes.lock().map_err(|_| Failure::Recording)? = response.scopes.clone();
            }
        }
        result
    }
}
pub(crate) fn bearer(token: &str) -> Result<HeaderValue, Failure> {
    let mut value =
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| Failure::Configuration)?;
    value.set_sensitive(true);
    Ok(value)
}
pub(crate) fn safe_header(value: &Option<String>, token: &str) -> Option<String> {
    value
        .as_ref()
        .filter(|v| v.len() <= 4096 && v.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
        .map(|v| v.replace(token, "[credential]"))
}
pub(crate) fn scrub_bytes(value: &mut Vec<u8>, token: &[u8]) {
    if token.is_empty() {
        return;
    }
    let mut clean = Vec::with_capacity(value.len());
    let mut offset = 0;
    while offset < value.len() {
        if value[offset..].starts_with(token) {
            clean.extend_from_slice(b"[credential]");
            offset += token.len();
        } else {
            clean.push(value[offset]);
            offset += 1;
        }
    }
    *value = clean;
}
pub(crate) fn redact(value: &mut Value, token: &str) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "token" | "access_token" | "refresh_token" | "upload_url"
                ) {
                    *value = json!("[credential]");
                } else {
                    redact(value, token);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact(item, token);
            }
        }
        Value::String(text) if !token.is_empty() => *text = text.replace(token, "[credential]"),
        _ => (),
    }
}
pub(crate) async fn read(request: RequestBuilder) -> Result<Response, Failure> {
    let failure = |e: reqwest::Error| {
        if e.is_timeout() {
            Failure::Timeout
        } else {
            Failure::Connection
        }
    };
    let mut response = request.send().await.map_err(failure)?;
    let status = response.status().as_u16();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let retry_after = header("retry-after");
    let scopes = header("x-oauth-scopes");
    if response
        .content_length()
        .is_some_and(|n| n > ENVELOPE_LIMIT as u64)
    {
        return Err(Failure::ResponseLimit);
    }
    let mut body = vec![];
    while let Some(chunk) = response.chunk().await.map_err(failure)? {
        if body.len() + chunk.len() > ENVELOPE_LIMIT {
            return Err(Failure::ResponseLimit);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Response {
        status,
        retry_after,
        scopes,
        body,
    })
}
fn code(body: &Value) -> String {
    const KNOWN: &[&str] = &[
        "internal_error",
        "fatal_error",
        "request_timeout",
        "service_unavailable",
        "invalid_auth",
        "not_authed",
        "token_revoked",
        "token_expired",
        "missing_scope",
        "channel_not_found",
        "not_in_channel",
        "is_archived",
        "no_permission",
        "restricted_action",
        "invalid_arguments",
        "file_not_found",
        "file_uploads_disabled",
        "invalid_metadata_format",
        "msg_too_long",
        "ratelimited",
    ];
    body["error"]
        .as_str()
        .filter(|s| KNOWN.contains(s))
        .unwrap_or("slack_api_error")
        .into()
}
/// Server errors may have taken effect, so they are ambiguous, not rejected.
pub(crate) fn http_failure(response: &Response) -> Failure {
    if response.status == 429 {
        return Failure::RateLimited {
            retry_after: response
                .retry_after
                .as_ref()
                .and_then(|s| s.parse::<f64>().ok())
                .filter(|n| n.is_finite())
                .unwrap_or(30.),
        };
    }
    let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    let code = code(&body);
    if response.status >= 500
        || matches!(
            code.as_str(),
            "internal_error" | "fatal_error" | "request_timeout" | "service_unavailable"
        )
    {
        Failure::Ambiguous { code }
    } else if body["ok"] == false || (400..500).contains(&response.status) {
        Failure::Rejected { code }
    } else {
        Failure::InvalidResponse
    }
}
/// The body of a successful (`ok: true`) Slack response.
pub(crate) fn decode(response: &Response) -> Result<Value, Failure> {
    if response.status != 200 {
        return Err(http_failure(response));
    }
    let body: Value =
        serde_json::from_slice(&response.body).map_err(|_| Failure::InvalidResponse)?;
    if body["ok"] != true {
        return Err(http_failure(response));
    }
    Ok(body)
}

/// `slack-morphism`'s connector over a [`Transport`]. `context` is journaled
/// with every call made through this connector.
#[derive(Clone)]
pub(crate) struct Connector {
    pub transport: Arc<Transport>,
    pub context: Option<Value>,
}
/// Carries a [`Failure`] through `slack-morphism`'s error type.
fn carry(failure: Failure) -> SlackClientError {
    SlackClientError::SystemError(SlackClientSystemError {
        message: None,
        cause: Some(Box::new(failure)),
    })
}
/// The [`Failure`] behind a `slack-morphism` error.
pub(crate) fn failure(error: SlackClientError) -> Failure {
    match error {
        SlackClientError::SystemError(SlackClientSystemError {
            cause: Some(cause), ..
        }) => cause
            .downcast::<Failure>()
            .map(|f| *f)
            .unwrap_or(Failure::InvalidResponse),
        _ => Failure::InvalidResponse,
    }
}
impl Connector {
    fn method(&self, uri: &Url) -> String {
        uri.path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("")
            .to_string()
    }
    async fn typed<RS>(
        &self,
        uri: Url,
        arguments: Value,
        context: SlackClientApiCallContext<'_>,
        build: impl FnOnce(&Client, Url) -> RequestBuilder,
    ) -> ClientResult<RS>
    where
        RS: for<'de> serde::de::Deserialize<'de>,
    {
        let token = context
            .token
            .map(|t| t.token_value.0.clone())
            .unwrap_or_default();
        let method = self.method(&uri);
        let request = build(&self.transport.client, uri)
            .header(AUTHORIZATION, bearer(&token).map_err(carry)?);
        let response = self
            .transport
            .call(&method, arguments, self.context.clone(), &token, request)
            .await
            .map_err(carry)?;
        let body = decode(&response).map_err(carry)?;
        serde_json::from_value(body).map_err(|_| carry(Failure::InvalidResponse))
    }
}
impl SlackClientHttpConnector for Connector {
    fn create_method_uri_path(&self, method_relative_uri: &str) -> ClientResult<Url> {
        self.transport.url(method_relative_uri).map_err(carry)
    }
    fn http_get_uri<'a, RS>(
        &'a self,
        mut full_uri: Url,
        context: SlackClientApiCallContext<'a>,
    ) -> futures_util::future::BoxFuture<'a, ClientResult<RS>>
    where
        RS: for<'de> serde::de::Deserialize<'de> + Send + 'a,
    {
        // Calls without arguments arrive with an empty query (`?`).
        if full_uri.query() == Some("") {
            full_uri.set_query(None);
        }
        let pairs: Vec<(String, String)> = full_uri.query_pairs().into_owned().collect();
        let arguments: serde_json::Map<String, Value> =
            pairs.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        if FORM_METHODS.contains(&self.method(&full_uri).as_str()) {
            full_uri.set_query(None);
            return Box::pin(self.typed(
                full_uri,
                Value::Object(arguments),
                context,
                move |c, u| c.post(u).form(&pairs),
            ));
        }
        Box::pin(self.typed(full_uri, Value::Object(arguments), context, |c, u| c.get(u)))
    }
    fn http_post_uri<'a, RQ, RS>(
        &'a self,
        full_uri: Url,
        request_body: &'a RQ,
        context: SlackClientApiCallContext<'a>,
    ) -> futures_util::future::BoxFuture<'a, ClientResult<RS>>
    where
        RQ: serde::ser::Serialize + Send + Sync,
        RS: for<'de> serde::de::Deserialize<'de> + Send + 'a,
    {
        Box::pin(async move {
            let body =
                serde_json::to_value(request_body).map_err(|_| carry(Failure::Configuration))?;
            let form = FORM_METHODS.contains(&self.method(&full_uri).as_str());
            let fields: Vec<(String, String)> = body
                .as_object()
                .into_iter()
                .flatten()
                .map(|(key, value)| {
                    let value = match value {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    (key.clone(), value)
                })
                .collect();
            let arguments = body.clone();
            self.typed(full_uri, arguments, context, move |c, u| {
                if form {
                    c.post(u).form(&fields)
                } else {
                    c.post(u).json(&body)
                }
            })
            .await
        })
    }
    fn http_get_with_client_secret<'a, RS>(
        &'a self,
        _full_uri: Url,
        _client_id: &'a SlackClientId,
        _client_secret: &'a SlackClientSecret,
    ) -> futures_util::future::BoxFuture<'a, ClientResult<RS>>
    where
        RS: for<'de> serde::de::Deserialize<'de> + Send + 'a,
    {
        Box::pin(async { Err(carry(Failure::Configuration)) })
    }
    fn http_post_uri_multipart_form<'a, 'p, RS, PT, TS>(
        &'a self,
        _full_uri: Url,
        _file: Option<FileMultipartData<'p>>,
        _params: &'p PT,
        _context: SlackClientApiCallContext<'a>,
    ) -> futures_util::future::BoxFuture<'a, ClientResult<RS>>
    where
        RS: for<'de> serde::de::Deserialize<'de> + Send + 'a,
        PT: std::iter::IntoIterator<Item = (&'p str, Option<TS>)> + Clone,
        TS: AsRef<str> + 'p + Send,
    {
        Box::pin(async { Err(carry(Failure::Configuration)) })
    }
    fn http_post_uri_binary<'a, 'p, RS>(
        &'a self,
        _full_uri: Url,
        _content_type: String,
        _data: &'a [u8],
        _context: SlackClientApiCallContext<'a>,
    ) -> futures_util::future::BoxFuture<'a, ClientResult<RS>>
    where
        RS: for<'de> serde::de::Deserialize<'de> + Send + 'a,
    {
        Box::pin(async { Err(carry(Failure::Configuration)) })
    }
}
