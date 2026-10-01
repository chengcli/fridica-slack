//! The owner-authenticated Slack Web API: fixed endpoints, no transport retries
//! or redirects, and journal records before I/O. Constructors do no I/O.
mod download;
use crate::{
    connector::{self, bearer, decode, Connector, Transport},
    history::{History, HistoryFailure, Method, PageRequest},
    ingress::{file_url, timestamp},
    links, BoxFuture, Journal, Scope,
};
use reqwest::{header::AUTHORIZATION, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use slack_morphism::{
    api::{
        SlackApiAppsConnectionOpenRequest, SlackApiConversationsInfoRequest, SlackApiFilesComplete,
        SlackApiFilesCompleteUploadExternalRequest, SlackApiFilesGetUploadUrlExternalRequest,
        SlackApiFilesInfoRequest,
    },
    SlackApiToken, SlackApiTokenValue, SlackChannelId, SlackClient, SlackFileId, SlackTs,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

/// What went wrong, as facts. `Ambiguous` means the request may have taken
/// effect; whether to retry is the host's decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum Failure {
    Configuration,
    NotValidated,
    Scope,
    Identity,
    Membership,
    Recording,
    Connection,
    Timeout,
    ResponseLimit,
    InvalidResponse,
    RateLimited { retry_after: f64 },
    Rejected { code: String },
    Ambiguous { code: String },
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Slack request failed: {self:?}")
    }
}
impl std::error::Error for Failure {}
type Result<T> = std::result::Result<T, Failure>;

/// The validated identity behind the user token.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Identity {
    pub owner: String,
    pub workspace: String,
    /// The token's scopes, when Slack reported them.
    pub scopes: Option<BTreeSet<String>>,
    /// Names of the scoped channels, by ID.
    pub channel_names: BTreeMap<String, String>,
    pub workspace_name: String,
}
/// A message to post, as the owner.
#[derive(Clone, Debug, PartialEq)]
pub struct Post {
    pub channel: String,
    /// Reply in this thread.
    pub thread_ts: Option<String>,
    pub text: String,
    /// Message metadata (`event_type`, `event_payload`), sent as is.
    pub metadata: Option<Value>,
}
/// A file to share in a channel or thread, as the owner.
#[derive(Clone, Debug, PartialEq)]
pub struct Upload {
    pub channel: String,
    pub thread_ts: Option<String>,
    pub filename: String,
    pub data: Vec<u8>,
}

/// A Slack Web API client for one user token. No `Debug`: it holds the token.
#[derive(Clone)]
pub struct WebClient {
    transport: Arc<Transport>,
    token: String,
    scope: Scope,
    validated: Arc<AtomicBool>,
    file_scopes: Arc<RwLock<Option<BTreeSet<String>>>>,
    downloads: Arc<tokio::sync::Mutex<download::Cache>>,
    #[cfg(feature = "testing")]
    upload_origin: Option<Url>,
    #[cfg(feature = "testing")]
    file_origin: Option<Url>,
}
impl WebClient {
    /// `token` must be a user token (`xoxp-`). Nothing is sent until
    /// [`validate`](Self::validate) succeeds.
    pub fn new(
        scope: Scope,
        journal: Arc<dyn Journal>,
        token: String,
        timeout: Duration,
    ) -> Result<Self> {
        if !token.starts_with("xoxp-")
            || token.len() < 6
            || token.bytes().any(|b| !b.is_ascii_graphic())
        {
            return Err(Failure::Configuration);
        }
        let base = Url::parse("https://slack.com/api/").map_err(|_| Failure::Configuration)?;
        Ok(Self {
            transport: Arc::new(Transport::new(journal, timeout, base, false)?),
            token,
            scope,
            validated: Arc::new(AtomicBool::new(false)),
            file_scopes: Arc::new(RwLock::new(None)),
            downloads: Arc::new(tokio::sync::Mutex::new(download::Cache::default())),
            #[cfg(feature = "testing")]
            upload_origin: None,
            #[cfg(feature = "testing")]
            file_origin: None,
        })
    }
    /// Send API calls, uploads and file reads to loopback test servers.
    #[cfg(feature = "testing")]
    pub fn with_test_endpoints(mut self, api: Url, upload: Url, files: Url) -> Self {
        let current = &self.transport;
        let transport = Transport::new(current.journal.clone(), current.timeout, api, true)
            .expect("the client was built with the same settings");
        self.transport = Arc::new(transport);
        self.upload_origin = Some(upload);
        self.file_origin = Some(files);
        self
    }
    /// Replace the file scopes a validation recorded.
    #[cfg(feature = "testing")]
    pub fn set_file_scopes(&self, scopes: Option<BTreeSet<String>>) {
        *self.file_scopes.write().unwrap() = scopes;
    }
    pub(crate) fn journal(&self) -> &dyn Journal {
        self.transport.journal.as_ref()
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn is_validated(&self) -> bool {
        self.validated.load(Ordering::Acquire)
    }
    fn client(&self, context: Option<Value>) -> SlackClient<Connector> {
        SlackClient::new(Connector {
            transport: self.transport.clone(),
            context,
        })
    }
    fn api_token(token: &str) -> SlackApiToken {
        SlackApiToken::new(SlackApiTokenValue(token.into()))
    }
    /// The Socket Mode URL for `connection`. The URL is a credential: it is
    /// never journaled.
    pub async fn socket_url(&self, app_token: &str, connection: &str) -> Result<String> {
        if !self.is_validated() {
            return Err(Failure::NotValidated);
        }
        if !app_token.starts_with("xapp-")
            || app_token.len() < 6
            || app_token.bytes().any(|b| !b.is_ascii_graphic())
        {
            return Err(Failure::Configuration);
        }
        let client = self.client(Some(json!({"connection":connection})));
        let token = Self::api_token(app_token);
        let response = client
            .open_session(&token)
            .apps_connections_open(&SlackApiAppsConnectionOpenRequest::new())
            .await
            .map_err(connector::failure)?;
        Ok(response.url.0.to_string())
    }
    /// Check that the token is the owner's user token in the expected
    /// workspace and that every scoped channel is joined. Only a check the
    /// journal recorded enables writes.
    pub async fn validate(&self) -> Result<Identity> {
        self.validated.store(false, Ordering::Release);
        let client = self.client(None);
        let token = Self::api_token(&self.token);
        let session = client.open_session(&token);
        let auth = session.auth_test().await.map_err(connector::failure)?;
        if auth.user_id.0 != self.scope.owner
            || auth.team_id.0 != self.scope.workspace
            || auth.bot_id.as_ref().is_some_and(|v| !v.0.is_empty())
        {
            return Err(Failure::Identity);
        }
        let header = self
            .transport
            .scopes
            .lock()
            .map_err(|_| Failure::Recording)?
            .clone();
        let scopes = connector::safe_header(&header, &self.token).map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<BTreeSet<_>>()
        });
        let mut channel_names = BTreeMap::new();
        for channel in &self.scope.channels {
            let info = session
                .conversations_info(&SlackApiConversationsInfoRequest::new(SlackChannelId(
                    channel.clone(),
                )))
                .await
                .map_err(connector::failure)?;
            if info.channel.id.0 != *channel || info.channel.flags.is_member != Some(true) {
                return Err(Failure::Membership);
            }
            // Names let owners address a channel as `#name`.
            if let Some(name) = info.channel.name.filter(|n| n.len() <= 80) {
                channel_names.insert(channel.clone(), name);
            }
        }
        let identity = Identity {
            owner: self.scope.owner.clone(),
            workspace: self.scope.workspace.clone(),
            scopes,
            channel_names,
            workspace_name: Some(auth.team)
                .filter(|n| n.len() <= 80)
                .unwrap_or_default(),
        };
        self.transport
            .journal
            .identity(&identity)
            .await
            .map_err(|_| Failure::Recording)?;
        *self.file_scopes.write().map_err(|_| Failure::Recording)? = identity.scopes.clone();
        self.validated.store(true, Ordering::Release);
        Ok(identity)
    }
    fn check(&self, channel: &str) -> Result<()> {
        if !self.is_validated() {
            return Err(Failure::NotValidated);
        }
        if !self.scope.channel(channel) {
            return Err(Failure::Scope);
        }
        Ok(())
    }
    async fn raw(
        &self,
        method: &str,
        request: reqwest::RequestBuilder,
        arguments: Value,
        context: Option<Value>,
    ) -> Result<connector::Response> {
        let request = request.header(AUTHORIZATION, bearer(&self.token)?);
        self.transport
            .call(method, arguments, context, &self.token, request)
            .await
    }
    /// Post a message; returns its timestamp. `context` is journaled with the
    /// call (e.g. an outbox ID).
    pub async fn post(&self, post: Post, context: Option<Value>) -> Result<String> {
        self.check(&post.channel)?;
        if post.thread_ts.as_deref().is_some_and(|s| !timestamp(s)) {
            return Err(Failure::Scope);
        }
        // Sent as raw JSON: metadata payloads keep their numeric fields.
        let mut body = json!({"channel":post.channel,"text":post.text,"unfurl_links":false,"unfurl_media":false});
        if let Some(ts) = post.thread_ts {
            body["thread_ts"] = json!(ts);
        }
        if let Some(meta) = post.metadata {
            body["metadata"] = meta;
        }
        let url = self.transport.url("chat.postMessage")?;
        let request = self.transport.client.post(url).json(&body);
        let response = decode(&self.raw("chat.postMessage", request, body, context).await?)?;
        let ts = response["ts"]
            .as_str()
            .filter(|s| timestamp(s))
            .ok_or(Failure::Ambiguous {
                code: "unconfirmed_timestamp".into(),
            })?;
        if response
            .get("channel")
            .is_some_and(|channel| channel != &post.channel)
        {
            return Err(Failure::Ambiguous {
                code: "unexpected_channel".into(),
            });
        }
        Ok(ts.into())
    }
    /// Upload and share a file; returns its file ID.
    pub async fn upload(&self, upload: Upload, context: Option<Value>) -> Result<String> {
        self.check(&upload.channel)?;
        if upload.filename.is_empty() || upload.thread_ts.as_deref().is_some_and(|s| !timestamp(s))
        {
            return Err(Failure::Configuration);
        }
        let client = self.client(context.clone());
        let token = Self::api_token(&self.token);
        let session = client.open_session(&token);
        let ticket = session
            .get_upload_url_external(&SlackApiFilesGetUploadUrlExternalRequest::new(
                upload.filename.clone(),
                upload.data.len(),
            ))
            .await
            .map_err(connector::failure)?;
        let id = ticket.file_id.0.clone();
        if !valid_file_id(&id) {
            return Err(Failure::InvalidResponse);
        }
        let target = self.upload_url(ticket.upload_url.0.as_str())?;
        let record = json!({"file_id":id,"length":upload.data.len(),"sha256":format!("{:x}",<sha2::Sha256 as sha2::Digest>::digest(&upload.data))});
        // The upload URL is itself a credential and carries no bearer token.
        let request = self
            .transport
            .client
            .post(target)
            .header("Content-Type", "application/octet-stream")
            .body(upload.data);
        let uploaded = self
            .transport
            .call("file_bytes", record, context.clone(), &self.token, request)
            .await?;
        if uploaded.status != 200 {
            return Err(connector::http_failure(&uploaded));
        }
        let mut complete =
            SlackApiFilesCompleteUploadExternalRequest::new(vec![SlackApiFilesComplete::new(
                SlackFileId(id.clone()),
            )
            .with_title(upload.filename)])
            .with_channel_id(SlackChannelId(upload.channel));
        if let Some(ts) = upload.thread_ts {
            complete = complete.with_thread_ts(SlackTs(ts));
        }
        // The bytes are uploaded: a completion that cannot be read may still
        // have shared the file.
        let confirmed = session
            .files_complete_upload_external(&complete)
            .await
            .map_err(|e| match connector::failure(e) {
                Failure::InvalidResponse => Failure::Ambiguous {
                    code: "unconfirmed_file".into(),
                },
                other => other,
            })?;
        if confirmed.files.len() != 1 || confirmed.files[0].id.0 != id {
            return Err(Failure::Ambiguous {
                code: "unconfirmed_file".into(),
            });
        }
        Ok(id)
    }
    /// A file's `url_private`, from `files.info`.
    pub(crate) async fn files_info(&self, file_id: String) -> Result<Option<String>> {
        let client = self.client(None);
        let token = Self::api_token(&self.token);
        let info = client
            .open_session(&token)
            .files_info(&SlackApiFilesInfoRequest::new(SlackFileId(file_id)))
            .await
            .map_err(connector::failure)?;
        Ok(info.file.url_private.map(|url| url.to_string()))
    }
    fn upload_url(&self, value: &str) -> Result<Url> {
        let url = Url::parse(value).map_err(|_| Failure::InvalidResponse)?;
        #[cfg(feature = "testing")]
        if let Some(origin) = &self.upload_origin {
            if url.origin() == origin.origin()
                && url.path().starts_with("/upload/")
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
            {
                return Ok(url);
            }
        }
        if !file_url(value) || !url.path().starts_with("/upload/") || url.fragment().is_some() {
            return Err(Failure::InvalidResponse);
        }
        Ok(url)
    }
    /// A GET of a read API method, decoded as Slack's raw JSON.
    async fn read(&self, method: &str, arguments: Value, context: Option<Value>) -> Result<Value> {
        let url = self.transport.url(method)?;
        let request = self.transport.client.get(url).query(&arguments);
        decode(&self.raw(method, request, arguments, context).await?)
    }
}
fn valid_file_id(id: &str) -> bool {
    id.len() > 1
        && id.len() <= 64
        && id.starts_with('F')
        && id.bytes().all(|b| b.is_ascii_alphanumeric())
}
impl History for WebClient {
    fn page(
        &self,
        request: PageRequest,
    ) -> BoxFuture<'_, std::result::Result<Value, HistoryFailure>> {
        Box::pin(async move {
            let operation = async {
                self.check(&request.channel)?;
                if request.limit == 0
                    || request.limit > 200
                    || !timestamp(&request.oldest)
                    || request.ts.as_deref().is_some_and(|s| !timestamp(s))
                    || matches!(request.method, Method::Replies) != request.ts.is_some()
                {
                    return Err(Failure::Configuration);
                }
                let method = match request.method {
                    Method::History => "conversations.history",
                    Method::Replies => "conversations.replies",
                };
                let mut body = serde_json::to_value(request).map_err(|_| Failure::Configuration)?;
                body.as_object_mut()
                    .ok_or(Failure::Configuration)?
                    .remove("method");
                self.read(method, body, None).await
            }
            .await;
            operation.map_err(|error| match error {
                Failure::Timeout => HistoryFailure::Timeout,
                Failure::Connection => HistoryFailure::Connection,
                Failure::RateLimited { retry_after } => HistoryFailure::RateLimited { retry_after },
                Failure::InvalidResponse | Failure::ResponseLimit => {
                    HistoryFailure::InvalidResponse
                }
                Failure::Rejected { code } | Failure::Ambiguous { code } => {
                    HistoryFailure::Rejected { code }
                }
                other => HistoryFailure::Rejected {
                    code: serde_json::to_value(&other)
                        .ok()
                        .and_then(|v| v["error"].as_str().map(str::to_owned))
                        .unwrap_or_else(|| "rejected".into()),
                },
            })
        })
    }
}
impl links::Reader for WebClient {
    fn fetch(
        &self,
        link: links::Link,
    ) -> BoxFuture<'_, std::result::Result<Vec<links::Entry>, links::Failure>> {
        Box::pin(async move {
            let operation = async {
                self.check(&link.channel)?;
                if !links::timestamp(&link.ts)
                    || link.root.as_deref().is_some_and(|s| !links::timestamp(s))
                {
                    return Err(Failure::Configuration);
                }
                let body = json!({
                    "channel":link.channel,
                    "ts":link.root.as_deref().unwrap_or(&link.ts),
                    "limit":links::REPLY_LIMIT,
                });
                let context = json!({"operation":"linked_message","target":link.ts});
                let response = self
                    .read("conversations.replies", body, Some(context))
                    .await?;
                let messages = response["messages"]
                    .as_array()
                    .ok_or(Failure::InvalidResponse)?;
                Ok(links::select(messages, &link.ts))
            }
            .await;
            operation.map_err(|error| {
                if matches!(error, Failure::Recording) {
                    links::Failure::Recording
                } else {
                    links::Failure::Unavailable
                }
            })
        })
    }
}
