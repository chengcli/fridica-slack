# fridica-slack

A durable Slack transport for agents that act as a person through a **user
token** (`xoxp-`), receiving events over **Socket Mode** (`xapp-`). It is the
Slack layer of [Fridica](https://github.com/chengcli/fridica).

What makes it different from a typical bot library is its delivery
guarantees:

- **Commit before acknowledge.** Socket Mode hands every envelope to your
  [`Intake`] and acknowledges it only after `Intake::receive` returns, that is,
  after your store committed it. Losing the connection after the commit is
  safe: Slack redelivers and you deduplicate.
- **Journal before I/O.** Every Web API call is recorded through your
  [`Journal`] before it is sent, and its outcome afterwards: status,
  rate-limit and scope headers, and body, with credentials and Socket Mode
  tickets redacted. A failed record stops the call.
- **Facts, not policy.** Failures say what happened. `Ambiguous` means the
  request may have taken effect (a server error, a timeout after sending, an
  unconfirmable upload), so you decide not to blindly retry; `Rejected` means
  Slack refused it.
- **Bounded and fixed.** No redirects, no automatic retries, responses capped
  at 4 MiB, file reads at 64 KiB, uploads only to `files.slack.com`, and Socket
  Mode URLs only from `wss://*.slack.com/link/`.

The typed Web API calls (`auth.test`, `conversations.info`,
`conversations.list`, `apps.connections.open`, `files.getUploadURLExternal`,
`files.completeUploadExternal`) use
[slack-morphism](https://crates.io/crates/slack-morphism) models over this
crate's own HTTP connector, which provides the journaling, limits and failure
classification. `chat.postMessage` (metadata payloads keep their numeric
fields), history and replies (raw message JSON), and `users.info` (a member's
display name) are sent directly.

## What you supply

| Trait | Purpose |
|---|---|
| [`Journal`] | Record boundaries; optionally note the validated identity and Socket Mode status |
| [`Intake`] | Commit an envelope durably; return the acknowledgement afterwards |
| [`Ids`] | Connection and ping identifiers |

[`DiscardJournal`] records nothing, for clients without a store.

## Modules

- [`web`]: `WebClient`: identity validation, posting, uploads, history pages,
  linked messages and file reads, limited to a [`Scope`] of channels.
- [`socket`]: `SocketMode`: one WebSocket at a time, hello/ping/pong and
  disconnect handling, reconnects with backoff.
- [`ingress`]: envelope decoding and message normalization.
- [`links`]: permalink parsing and selection.
- [`history`], [`files`]: page and download types.
- [`discovery`]: read-only onboarding calls (identity and channel lists).

## Example

```rust,no_run
use fridica_slack::{socket::Options, *};
use std::{sync::Arc, time::Duration};

struct Store;
impl Intake for Store {
    fn receive<'a>(
        &'a self,
        envelope: &'a [u8],
    ) -> BoxFuture<'a, Result<Option<Acknowledgement>, socket::Refused>> {
        Box::pin(async move {
            let e = ingress::envelope(envelope).map_err(|_| socket::Refused)?;
            if e.id.is_empty() {
                return Ok(None);
            }
            if let Some(message) = ingress::normalize(&e.value["payload"], "socket") {
                // Commit `message` (deduplicated by event_id) before returning.
                println!("{}: {}", message.sender, message.text);
            }
            Ok(Some(Acknowledgement { envelope_id: e.id }))
        })
    }
}
struct Counter(std::sync::atomic::AtomicU64);
impl Ids for Counter {
    fn next(&self, namespace: &str) -> String {
        format!("{namespace}-{}", self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let scope = Scope {
        owner: "U0123".into(),
        workspace: "T0123".into(),
        channels: vec!["C0123".into()],
    };
    let journal = Arc::new(DiscardJournal::default());
    let web = Arc::new(WebClient::new(scope, journal, std::env::var("SLACK_USER_TOKEN")?, Duration::from_secs(30))?);
    web.validate().await?;
    let socket = SocketMode::new(
        web.clone(),
        Arc::new(Store),
        Arc::new(Counter(Default::default())),
        std::env::var("SLACK_APP_TOKEN")?,
        Options::default(),
    )?;
    let (_stop, stop) = tokio::sync::watch::channel(false);
    socket.run(stop).await?;
    Ok(())
}
```

## License

MIT
