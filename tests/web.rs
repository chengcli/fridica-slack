//! The Web API client against a loopback Slack, with an in-memory journal.
use fridica_slack::{
    web::{Post, WebClient},
    BoxFuture, Failure, Identity, Journal, Recording, Scope,
};
use reqwest::Url;
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Default)]
struct Memory {
    events: Mutex<Vec<(String, Value)>>,
    identity: Mutex<Option<Identity>>,
}
impl Journal for Memory {
    fn record(
        &self,
        kind: &'static str,
        payload: Value,
        _: bool,
    ) -> BoxFuture<'_, Result<i64, Recording>> {
        let mut events = self.events.lock().unwrap();
        events.push((kind.into(), payload));
        let seq = events.len() as i64;
        Box::pin(async move { Ok(seq) })
    }
    fn complete(
        &self,
        _: i64,
        kind: &'static str,
        payload: Value,
        _: bool,
    ) -> BoxFuture<'_, Result<(), Recording>> {
        self.events.lock().unwrap().push((kind.into(), payload));
        Box::pin(async { Ok(()) })
    }
    fn identity(&self, identity: &Identity) -> BoxFuture<'_, Result<(), Recording>> {
        *self.identity.lock().unwrap() = Some(identity.clone());
        Box::pin(async { Ok(()) })
    }
}
/// Answers each request with the next queued (status, headers, body), and
/// keeps the request lines.
async fn slack(replies: Vec<(u16, &'static str, Value)>) -> (Url, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}/api/", listener.local_addr().unwrap())).unwrap();
    let seen = Arc::new(Mutex::new(vec![]));
    let log = seen.clone();
    let mut replies = VecDeque::from(replies);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut raw = vec![];
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw).to_string();
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if raw.len() >= end + 4 + length || n == 0 {
                        break;
                    }
                }
            }
            log.lock().unwrap().push(
                String::from_utf8_lossy(&raw)
                    .lines()
                    .next()
                    .unwrap()
                    .to_string(),
            );
            let (status, headers, body) = replies.pop_front().unwrap();
            let body = body.to_string();
            let reply = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n{body}", body.len());
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    (base, seen)
}
fn client(base: Url, journal: Arc<Memory>) -> WebClient {
    let scope = Scope {
        owner: "U1".into(),
        workspace: "T1".into(),
        channels: vec!["C1".into()],
    };
    WebClient::new(
        scope,
        journal,
        "xoxp-secret-token".into(),
        Duration::from_secs(2),
    )
    .unwrap()
    .with_test_endpoints(base.clone(), base.clone(), base)
}
fn validation() -> Vec<(u16, &'static str, Value)> {
    vec![
        (
            200,
            "x-oauth-scopes: chat:write,files:read\r\n",
            json!({"ok":true,"user_id":"U1","team_id":"T1","team":"Acme","url":"https://acme.slack.com/"}),
        ),
        (
            200,
            "",
            json!({"ok":true,"channel":{"id":"C1","created":1,"name":"general","is_member":true}}),
        ),
    ]
}

#[tokio::test]
async fn validation_enables_journaled_posts_without_leaking_the_token() {
    let mut replies = validation();
    replies.push((
        200,
        "",
        json!({"ok":true,"channel":"C1","ts":"300.1","echo":"xoxp-secret-token"}),
    ));
    let (base, seen) = slack(replies).await;
    let journal = Arc::new(Memory::default());
    let web = client(base, journal.clone());
    let post = Post {
        channel: "C1".into(),
        thread_ts: Some("100.1".into()),
        text: "hello".into(),
        metadata: Some(json!({"event_type":"e","event_payload":{"turn":2}})),
    };
    assert_eq!(
        web.post(post.clone(), None).await,
        Err(Failure::NotValidated)
    );
    let identity = web.validate().await.unwrap();
    assert_eq!(identity.workspace_name, "Acme");
    assert_eq!(identity.channel_names["C1"], "general");
    assert!(identity.scopes.unwrap().contains("files:read"));
    assert_eq!(
        journal.identity.lock().unwrap().as_ref().unwrap().owner,
        "U1"
    );
    assert_eq!(
        web.post(post.clone(), Some(json!({"outbox":7})))
            .await
            .unwrap(),
        "300.1"
    );
    let other = Post {
        channel: "C2".into(),
        ..post
    };
    assert_eq!(web.post(other, None).await, Err(Failure::Scope));
    let lines = seen.lock().unwrap().clone();
    assert!(lines[0].starts_with("GET /api/auth.test "), "{lines:?}");
    assert!(lines[2].starts_with("POST /api/chat.postMessage "));
    let events = journal.events.lock().unwrap();
    let call = &events
        .iter()
        .find(|(_, v)| v["method"] == "chat.postMessage")
        .unwrap()
        .1;
    // Metadata keeps its numeric fields; the call is journaled with its context.
    assert_eq!(call["arguments"]["metadata"]["event_payload"]["turn"], 2);
    assert_eq!(call["context"]["outbox"], 7);
    assert!(!serde_json::to_string(&*events)
        .unwrap()
        .contains("xoxp-secret-token"));
}

#[tokio::test]
async fn server_errors_are_ambiguous_and_client_errors_rejected() {
    let mut replies = validation();
    replies.push((500, "", json!({"ok":false,"error":"internal_error"})));
    replies.push((200, "", json!({"ok":false,"error":"channel_not_found"})));
    replies.push((
        429,
        "retry-after: 7\r\n",
        json!({"ok":false,"error":"ratelimited"}),
    ));
    let (base, _) = slack(replies).await;
    let web = client(base, Arc::new(Memory::default()));
    web.validate().await.unwrap();
    let post = Post {
        channel: "C1".into(),
        thread_ts: None,
        text: "x".into(),
        metadata: None,
    };
    assert_eq!(
        web.post(post.clone(), None).await,
        Err(Failure::Ambiguous {
            code: "internal_error".into()
        })
    );
    assert_eq!(
        web.post(post.clone(), None).await,
        Err(Failure::Rejected {
            code: "channel_not_found".into()
        })
    );
    assert_eq!(
        web.post(post, None).await,
        Err(Failure::RateLimited { retry_after: 7. })
    );
}

#[tokio::test]
async fn a_bot_token_or_unjoined_channel_never_validates() {
    let (base, _) = slack(vec![(200, "", json!({"ok":true,"user_id":"U1","team_id":"T1","team":"A","url":"https://a.slack.com/","bot_id":"B1"}))]).await;
    assert_eq!(
        client(base, Arc::new(Memory::default())).validate().await,
        Err(Failure::Identity)
    );
    let (base, _) = slack(vec![
        validation().remove(0),
        (
            200,
            "",
            json!({"ok":true,"channel":{"id":"C1","created":1,"is_member":false}}),
        ),
    ])
    .await;
    let web = client(base, Arc::new(Memory::default()));
    assert_eq!(web.validate().await, Err(Failure::Membership));
    assert!(!web.is_validated());
}
