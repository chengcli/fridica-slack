use fridica_slack::{ingress, links, socket};
use serde_json::json;

#[test]
fn messages_normalize_and_unsupported_events_do_not() {
    let payload = json!({"type":"event_callback","event_id":"Ev1","team_id":"T1","event":{
        "type":"message","channel":"C1","user":"U1","ts":"200.2","thread_ts":"100.1","text":"hi",
        "files":[{"id":"F1","name":"a.txt","mimetype":"text/plain","size":3,"url_private":"https://files.slack.com/a"}],
        "metadata":{"event_type":"x"}}});
    let m = ingress::normalize(&payload, "socket").unwrap();
    assert_eq!(
        (m.channel.as_str(), m.thread_ts.as_deref(), m.text.as_str()),
        ("C1", Some("100.1"), "hi")
    );
    assert_eq!(m.attachments[0]["url"], "https://files.slack.com/a");
    assert_eq!(m.metadata["event_type"], "x");
    let mut edited = payload.clone();
    edited["event"]["subtype"] = json!("message_changed");
    assert!(ingress::normalize(&edited, "socket").is_none());
    assert!(!ingress::file_url("https://files.slack.com.evil.test/a"));
    assert!(!ingress::timestamp("1e9.5"));
}

#[test]
fn envelopes_drop_verification_tokens_and_need_ids() {
    let e = ingress::envelope(
        br#"{"type":"events_api","envelope_id":"E1","payload":{"token":"t","x":1}}"#,
    )
    .unwrap();
    assert_eq!((e.kind.as_str(), e.id.as_str()), ("events_api", "E1"));
    assert!(e.value["payload"].get("token").is_none());
    assert_eq!(ingress::envelope(br#"{"type":"hello"}"#).unwrap().id, "");
    assert_eq!(
        ingress::envelope(br#"{"type":"events_api"}"#).unwrap_err(),
        ingress::EnvelopeError::InvalidId
    );
}

#[test]
fn permalinks_and_socket_urls_are_strict() {
    let found = links::permalinks("see https://acme.slack.com/archives/C123/p1700000000123456?thread_ts=1700000000.000001 and https://evil.test/archives/C1/p1700000000123456");
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].ts.as_str(), found[0].root.as_deref()),
        ("1700000000.123456", Some("1700000000.000001"))
    );
    assert!(socket::ticket_url("wss://wss-primary.slack.com/link/?ticket=x").is_ok());
    for bad in [
        "ws://wss.slack.com/link/?ticket=x",
        "wss://evil.test/link/?ticket=x",
        "wss://wss.slack.com/link/",
    ] {
        assert!(socket::ticket_url(bad).is_err(), "{bad}");
    }
}
