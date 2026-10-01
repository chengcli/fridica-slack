//! Bounded authenticated file reads with replayable cache decisions. The cache
//! key includes HTML eligibility and whether scopes are known, so cached bytes
//! cannot bypass a later sign-in-page check.
use super::WebClient;
use crate::{
    connector::{bearer, scrub_bytes},
    files::{Download, Downloader, Failure, FILE_LIMIT},
    ingress::file_url,
    BoxFuture,
};
use reqwest::{header::AUTHORIZATION, Url};
use serde_json::json;
use std::{collections::VecDeque, time::Duration};
#[derive(Default)]
pub(super) struct Cache {
    success: VecDeque<((String, bool, bool), Download)>,
    failure: VecDeque<((String, bool, bool), f64, Failure)>,
}
impl Cache {
    fn get(&mut self, key: &(String, bool, bool), now: f64) -> Option<Result<Download, Failure>> {
        self.failure.retain(|(_, until, _)| *until > now);
        self.success
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| Ok(v.clone()))
            .or_else(|| {
                self.failure
                    .iter()
                    .find(|(k, _, _)| k == key)
                    .map(|(_, _, e)| Err(e.clone()))
            })
    }
    fn put(&mut self, key: (String, bool, bool), result: &Result<Download, Failure>, now: f64) {
        self.success.retain(|(k, _)| k != &key);
        self.failure
            .retain(|(k, until, _)| k != &key && *until > now);
        match result {
            Ok(value) => {
                if self.success.len() >= 32 {
                    self.success.pop_front();
                }
                self.success.push_back((key, value.clone()));
            }
            Err(failure) => {
                if self.failure.len() >= 256 {
                    self.failure.pop_front();
                }
                let ttl = match failure {
                    Failure::RateLimited { retry_after } if retry_after.is_finite() => {
                        retry_after.max(300.)
                    }
                    _ => 300.,
                };
                self.failure.push_back((key, now + ttl, failure.clone()));
            }
        }
    }
}
impl WebClient {
    fn file_target(&self, value: &str) -> Result<Url, Failure> {
        let url = Url::parse(value).map_err(|_| Failure::Url)?;
        #[cfg(feature = "testing")]
        if self
            .file_origin
            .as_ref()
            .is_some_and(|base| base.origin() == url.origin())
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
        {
            return Ok(url);
        }
        if value.len() > 8192
            || !file_url(value)
            || value.contains('\\')
            || url.fragment().is_some()
        {
            return Err(Failure::Url);
        }
        Ok(url)
    }
    async fn file_bytes(
        &self,
        url: Url,
        html: bool,
        known_scopes: bool,
    ) -> Result<Download, Failure> {
        let failure = |e: reqwest::Error| {
            if e.is_timeout() {
                Failure::Timeout
            } else {
                Failure::Connection
            }
        };
        let authorization = bearer(&self.token).map_err(|_| Failure::Url)?;
        let mut response = self
            .transport
            .client
            .get(url)
            .header(AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(failure)?;
        if response.status().as_u16() == 429 {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<f64>().ok())
                .filter(|n| n.is_finite())
                .unwrap_or(30.);
            return Err(Failure::RateLimited { retry_after });
        }
        let is_html = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("text/html");
        if response.status().as_u16() != 200 || (is_html && !html) {
            return Err(Failure::Unavailable);
        }
        if is_html && !known_scopes {
            return Err(Failure::UnknownHtml);
        }
        let size = response.content_length().unwrap_or(0);
        let mut data = Vec::new();
        while data.len() <= FILE_LIMIT {
            let Some(chunk) = response.chunk().await.map_err(failure)? else {
                break;
            };
            let n = chunk.len().min(FILE_LIMIT + 1 - data.len());
            data.extend_from_slice(&chunk[..n]);
        }
        scrub_bytes(&mut data, self.token.as_bytes());
        // Redaction can expand tiny synthetic tokens; retain the same byte bound.
        data.truncate(FILE_LIMIT + 1);
        Ok(Download { data, size })
    }
    async fn download_file(&self, url: String, html: bool) -> Result<Download, Failure> {
        if !self.is_validated() {
            return Err(Failure::NotValidated);
        }
        let scopes = self
            .file_scopes
            .read()
            .map_err(|_| Failure::Recording)?
            .clone();
        if scopes.as_ref().is_some_and(|s| !s.contains("files:read")) {
            return Err(Failure::MissingScope);
        }
        let target = self.file_target(&url)?;
        let journal = &self.transport.journal;
        let now = journal.now();
        if !now.is_finite() {
            return Err(Failure::InvalidResponse);
        }
        let record =
            json!({"url":url.replace(&self.token,"[credential]"),"html":html,"limit":FILE_LIMIT});
        let call = journal
            .record("slack_file_call", record, false)
            .await
            .map_err(|_| Failure::Recording)?;
        let key = (url, html, scopes.is_some());
        let cached = self.downloads.lock().await.get(&key, now);
        let cache_hit = cached.is_some();
        let result = match cached {
            Some(result) => result,
            None => tokio::time::timeout(
                Duration::from_secs(20),
                self.file_bytes(target, html, scopes.is_some()),
            )
            .await
            .unwrap_or(Err(Failure::Timeout)),
        };
        let complete = !matches!(result, Err(Failure::Timeout | Failure::Connection));
        let record = json!({"call":call,"cache_hit":cache_hit,"result":result});
        journal
            .complete(call, "slack_file_result", record, complete)
            .await
            .map_err(|_| Failure::Recording)?;
        if !cache_hit {
            self.downloads.lock().await.put(key, &result, now);
        }
        result
    }
}
impl Downloader for WebClient {
    fn download(&self, url: String, html: bool) -> BoxFuture<'_, Result<Download, Failure>> {
        Box::pin(self.download_file(url, html))
    }
}
