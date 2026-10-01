//! Read-only onboarding calls, before any store exists: the token's identity
//! and the channels it can list. Deciding what to configure is the host's job.
use crate::{
    connector::{self, redact, Connector, Transport},
    web::Failure,
    BoxFuture, DiscardJournal,
};
use reqwest::Url;
use serde_json::Value;
use slack_morphism::{
    api::SlackApiConversationsListRequest, SlackApiToken, SlackApiTokenValue, SlackClient,
    SlackConversationType, SlackCursorId,
};
use std::{sync::Arc, time::Duration};

#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    /// `auth.test`.
    Identity,
    /// One `conversations.list` page of public or private channels.
    Channels { private: bool, cursor: String },
}
/// Slack's JSON for an onboarding request, with credential echoes redacted.
pub trait Api: Send + Sync {
    fn get(&self, request: Request) -> BoxFuture<'_, Result<Value, Failure>>;
}
/// No `Debug`: it holds the user's credential.
pub struct Web {
    client: SlackClient<Connector>,
    token: SlackApiToken,
}
impl Web {
    pub fn new(token: &str) -> Result<Self, Failure> {
        if !token.starts_with("xoxp-")
            || token.len() < 6
            || token.bytes().any(|b| !b.is_ascii_graphic())
        {
            return Err(Failure::Configuration);
        }
        let base = Url::parse("https://slack.com/api/").map_err(|_| Failure::Configuration)?;
        Self::with_base(token, base, false)
    }
    fn with_base(token: &str, base: Url, loopback: bool) -> Result<Self, Failure> {
        let transport = Transport::new(
            Arc::new(DiscardJournal::default()),
            Duration::from_secs(15),
            base,
            loopback,
        )?;
        Ok(Self {
            client: SlackClient::new(Connector {
                transport: Arc::new(transport),
                context: None,
            }),
            token: SlackApiToken::new(SlackApiTokenValue(token.into())),
        })
    }
    /// Send calls to a loopback test server.
    #[cfg(feature = "testing")]
    pub fn with_test_endpoint(token: &str, base: Url) -> Result<Self, Failure> {
        Self::with_base(token, base, true)
    }
}
impl Api for Web {
    fn get(&self, request: Request) -> BoxFuture<'_, Result<Value, Failure>> {
        Box::pin(async move {
            let session = self.client.open_session(&self.token);
            let mut value = match request {
                Request::Identity => {
                    serde_json::to_value(session.auth_test().await.map_err(connector::failure)?)
                }
                Request::Channels { private, cursor } => {
                    if cursor.len() > 4096 {
                        return Err(Failure::InvalidResponse);
                    }
                    let mut list = SlackApiConversationsListRequest::new()
                        .with_types(vec![if private {
                            SlackConversationType::Private
                        } else {
                            SlackConversationType::Public
                        }])
                        .with_exclude_archived(true)
                        .with_limit(200);
                    if !cursor.is_empty() {
                        list = list.with_cursor(SlackCursorId(cursor));
                    }
                    serde_json::to_value(
                        session
                            .conversations_list(&list)
                            .await
                            .map_err(connector::failure)?,
                    )
                }
            }
            .map_err(|_| Failure::InvalidResponse)?;
            redact(&mut value, &self.token.token_value.0);
            Ok(value)
        })
    }
}
