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
use std::{collections::VecDeque, path::PathBuf, time::Duration};
use tokio::io::AsyncWriteExt;
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
    /// `files.info`, journaled like every API call, for a file's private URL.
    async fn file_url(&self, file_id: String) -> Result<String, Failure> {
        if !self.is_validated() {
            return Err(Failure::NotValidated);
        }
        if file_id.len() < 2
            || file_id.len() > 64
            || !file_id.starts_with('F')
            || !file_id.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(Failure::Url);
        }
        let info = self
            .files_info(file_id)
            .await
            .map_err(|failure| match failure {
                crate::web::Failure::Recording => Failure::Recording,
                crate::web::Failure::RateLimited { retry_after } => {
                    Failure::RateLimited { retry_after }
                }
                crate::web::Failure::Timeout => Failure::Timeout,
                _ => Failure::Unavailable,
            })?;
        info.filter(|url| file_url(url)).ok_or(Failure::Url)
    }
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
    /// Stream a response body into a new file, removing it on any failure.
    async fn file_stream(&self, url: Url, path: &PathBuf, limit: u64) -> Result<u64, Failure> {
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
        if response.status().as_u16() != 200 || is_html {
            return Err(Failure::Unavailable);
        }
        if response.content_length().is_some_and(|n| n > limit) {
            return Err(Failure::TooLarge);
        }
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .await
            .map_err(|_| Failure::Unavailable)?;
        let written = async {
            let mut written = 0u64;
            while let Some(chunk) = response.chunk().await.map_err(failure)? {
                written += chunk.len() as u64;
                if written > limit {
                    return Err(Failure::TooLarge);
                }
                file.write_all(&chunk)
                    .await
                    .map_err(|_| Failure::Unavailable)?;
            }
            file.flush().await.map_err(|_| Failure::Unavailable)?;
            Ok(written)
        }
        .await;
        drop(file);
        if written.is_err() {
            let _ = tokio::fs::remove_file(path).await;
        }
        written
    }
    async fn save_file(&self, url: String, path: PathBuf, limit: u64) -> Result<u64, Failure> {
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
        let record =
            json!({"url":url.replace(&self.token,"[credential]"),"save":true,"limit":limit});
        let call = journal
            .record("slack_file_call", record, false)
            .await
            .map_err(|_| Failure::Recording)?;
        // A large file takes a while; a stalled stream is still bounded.
        let allowance = Duration::from_secs(60 + limit / (1 << 20));
        let result = tokio::time::timeout(allowance, self.file_stream(target, &path, limit))
            .await
            .unwrap_or(Err(Failure::Timeout));
        if matches!(result, Err(Failure::Timeout)) {
            let _ = tokio::fs::remove_file(&path).await;
        }
        let complete = !matches!(result, Err(Failure::Timeout | Failure::Connection));
        let record = json!({"call":call,"saved":result});
        journal
            .complete(call, "slack_file_result", record, complete)
            .await
            .map_err(|_| Failure::Recording)?;
        result
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
    fn resolve(&self, file_id: String) -> BoxFuture<'_, Result<String, Failure>> {
        Box::pin(self.file_url(file_id))
    }
    fn save(&self, url: String, path: PathBuf, limit: u64) -> BoxFuture<'_, Result<u64, Failure>> {
        Box::pin(self.save_file(url, path, limit))
    }
}
