//! The model classifies untrusted text; it never decides refunds or writes replies.

use crate::cache::{AnalysisCache, CacheConfig, CacheStatistics, Lookup};
use crate::domain::{
    Analysis, AnalysisOutcome, AnalysisSource, Category, Language, Severity, Ticket,
};
use anyhow::{Result, bail};
use reqwest::{Client, Url, redirect::Policy};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::Instant};

const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_ATTEMPTS: u8 = 2;

/// Exact system prompt sent to the local model. No billing records, IDs, or
/// internal refund rules are sent. Prompt changes belong in code review.
pub const SYSTEM_PROMPT: &str = crate::deepseek::SYSTEM_PROMPT;

#[derive(Clone)]
pub struct Analyzer {
    backend: Arc<Backend>,
    cache: Option<Arc<AnalysisCache>>,
    cache_identity: String,
}

enum Backend {
    Replay(HashMap<String, Analysis>),
    Ollama(Ollama),
    Deepseek(crate::deepseek::DeepSeek),
}

struct Ollama {
    client: Client,
    endpoint: Url,
    model: String,
    permits: Arc<Semaphore>,
    timeout: Duration,
}

#[derive(Deserialize)]
struct ChatResponse {
    message: ChatMessage,
    done: bool,
    done_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Clone, Copy)]
enum ModelError {
    Timeout,
    Transport,
    Http,
    TooLarge,
    Invalid,
}

impl ModelError {
    fn code(self) -> &'static str {
        match self {
            Self::Timeout => "model_timeout",
            Self::Transport => "model_transport",
            Self::Http => "model_http",
            Self::TooLarge => "model_response_too_large",
            Self::Invalid => "model_invalid_response",
        }
    }
}

impl Analyzer {
    pub fn deepseek(config: crate::deepseek::DeepSeekConfig) -> Result<Self> {
        let identity = json!([
            "deepseek",
            config.model,
            config.max_tokens,
            "thinking-disabled",
            0
        ])
        .to_string();
        Ok(Self::from_backend(
            Backend::Deepseek(crate::deepseek::DeepSeek::new(config)?),
            &identity,
        ))
    }

    fn from_backend(backend: Backend, identity: &str) -> Self {
        let cache_identity = json!([
            "analysis-schema-v2",
            crate::domain::hash_bytes(SYSTEM_PROMPT.as_bytes()),
            identity
        ])
        .to_string();
        let cache = AnalysisCache::new(&cache_identity, CacheConfig::default())
            .expect("valid default cache limits");
        Self {
            backend: Arc::new(backend),
            cache: Some(cache),
            cache_identity,
        }
    }

    /// An Analyzer is a single-tenant runtime. Give separately authorized tenant
    /// contexts separate instances/namespaces. Reconfiguration creates a fresh
    /// cache while retaining the shared backend and its paid-call budget.
    pub fn with_cache(mut self, namespace: &str, config: CacheConfig) -> Result<Self> {
        if namespace.trim().is_empty()
            || namespace.len() > 256
            || namespace.chars().any(char::is_control)
        {
            bail!("invalid analysis cache namespace");
        }
        let namespace = json!([namespace, self.cache_identity]).to_string();
        self.cache = Some(AnalysisCache::new(&namespace, config)?);
        Ok(self)
    }

    pub fn without_cache(mut self) -> Self {
        self.cache = None;
        self
    }

    pub fn cache_statistics(&self) -> CacheStatistics {
        self.cache
            .as_ref()
            .map(|cache| cache.statistics())
            .unwrap_or_default()
    }

    pub fn usage_totals(&self) -> crate::deepseek::UsageTotals {
        match self.backend.as_ref() {
            Backend::Deepseek(runtime) => runtime.usage_totals(),
            _ => Default::default(),
        }
    }

    pub fn budget_snapshot(&self) -> Option<crate::deepseek::BudgetSnapshot> {
        match self.backend.as_ref() {
            Backend::Deepseek(runtime) => Some(runtime.budget_snapshot()),
            _ => None,
        }
    }
    /// Deterministic, explicitly labelled analyst-authored fixture, not an LLM run.
    /// Matching content hashes prevent a reused ticket ID from receiving a stale
    /// classification. The checked-in fixture contains no customer text.
    pub fn replay() -> Self {
        let entries = serde_json::from_str(include_str!("../fixtures/replay.json"))
            .expect("checked-in replay fixture must contain valid analyses");
        Self::from_backend(
            Backend::Replay(entries),
            &format!(
                "replay:{}",
                crate::domain::hash_bytes(include_bytes!("../fixtures/replay.json"))
            ),
        )
    }

    /// Use a local Ollama server. Redirects, proxies and remote hosts are disabled
    /// so ticket text cannot accidentally leave the machine through this client.
    pub fn ollama(
        base_url: &str,
        model: &str,
        max_in_flight: usize,
        timeout: Duration,
    ) -> Result<Self> {
        if max_in_flight == 0 || max_in_flight > Semaphore::MAX_PERMITS {
            bail!("invalid model concurrency limit");
        }
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            bail!("invalid model timeout");
        }
        if model.trim().is_empty() || model.len() > 128 || model.chars().any(char::is_control) {
            bail!("invalid model name");
        }
        // Never include a rejected URL in errors; it might contain credentials.
        let mut endpoint =
            Url::parse(base_url).map_err(|_| anyhow::anyhow!("invalid model URL"))?;
        let is_loopback = endpoint.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !is_loopback
            || endpoint.scheme() != "http"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            bail!("model URL must be a loopback HTTP origin without credentials, query or path");
        }
        endpoint.set_path("/api/chat");
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| anyhow::anyhow!("cannot initialize model client"))?;
        let identity = json!(["ollama", endpoint.as_str(), model, 384, 0]).to_string();
        Ok(Self::from_backend(
            Backend::Ollama(Ollama {
                client,
                endpoint,
                model: model.to_owned(),
                permits: Arc::new(Semaphore::new(max_in_flight)),
                timeout,
            }),
            &identity,
        ))
    }

    pub async fn analyze(&self, ticket: &Ticket) -> AnalysisOutcome {
        let Some(cache) = &self.cache else {
            return self.analyze_uncached(ticket).await;
        };
        match cache.lookup(ticket) {
            Lookup::Hit(outcome) => outcome,
            Lookup::Leader(leader) => {
                let outcome = self.analyze_uncached(ticket).await;
                leader.finish(&outcome);
                outcome
            }
            Lookup::Follower(follower) => follower
                .wait()
                .await
                .unwrap_or_else(|| fallback(ticket, 0, "model_cancelled")),
            Lookup::Busy => fallback(ticket, 0, "model_busy"),
        }
    }

    async fn analyze_uncached(&self, ticket: &Ticket) -> AnalysisOutcome {
        let runtime = match self.backend.as_ref() {
            Backend::Replay(entries) => {
                return match entries.get(&ticket.content_fingerprint()) {
                    Some(analysis) => AnalysisOutcome {
                        analysis: analysis.clone(),
                        source: AnalysisSource::Replay,
                        attempts: 0,
                        degraded_reason: None,
                        usage: Default::default(),
                        cached: false,
                    },
                    None => fallback(ticket, 0, "unknown_replay_content"),
                };
            }
            Backend::Ollama(runtime) => runtime,
            Backend::Deepseek(runtime) => {
                let response = runtime.analyze(ticket).await;
                return match response.analysis {
                    Some(analysis) => AnalysisOutcome {
                        analysis,
                        source: AnalysisSource::Deepseek,
                        attempts: response.attempts,
                        degraded_reason: None,
                        usage: response.usage,
                        cached: false,
                    },
                    None => {
                        let mut result = fallback(
                            ticket,
                            response.attempts,
                            response.degraded_reason.unwrap_or("model_invalid_response"),
                        );
                        result.usage = response.usage;
                        result
                    }
                };
            }
        };

        // No queue of potentially sensitive tickets, and no unbounded waiting.
        let Ok(_permit) = runtime.permits.clone().try_acquire_owned() else {
            return fallback(ticket, 0, "model_busy");
        };
        let Some(deadline) = Instant::now().checked_add(runtime.timeout) else {
            return fallback(ticket, 0, "model_timeout");
        };
        let mut last_error = ModelError::Timeout;
        let mut attempts = 0;
        for attempt in 1..=MAX_ATTEMPTS {
            if Instant::now() >= deadline {
                break;
            }
            attempts = attempt;
            match tokio::time::timeout_at(deadline, runtime.attempt(ticket, attempt > 1)).await {
                Ok(Ok(analysis)) => {
                    return AnalysisOutcome {
                        analysis,
                        source: AnalysisSource::Ollama,
                        attempts,
                        degraded_reason: None,
                        usage: Default::default(),
                        cached: false,
                    };
                }
                Ok(Err(error)) => last_error = error,
                Err(_) => {
                    last_error = ModelError::Timeout;
                    break;
                }
            }
        }
        fallback(ticket, attempts, last_error.code())
    }
}

impl Ollama {
    async fn attempt(&self, ticket: &Ticket, retry: bool) -> Result<Analysis, ModelError> {
        let system = if retry {
            format!(
                "{SYSTEM_PROMPT}\nThe previous attempt failed validation. Return only the required JSON object."
            )
        } else {
            SYSTEM_PROMPT.to_owned()
        };
        let request = json!({
            "model": self.model,
            "stream": false,
            "format": "json",
            "options": { "temperature": 0, "num_predict": 384 },
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": json!({"subject": ticket.subject, "body": ticket.body}).to_string() }
            ]
        });
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .json(&request)
            .send()
            .await
            .map_err(transport_error)?;
        if !response.status().is_success() {
            return Err(ModelError::Http);
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ModelError::TooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                return Err(ModelError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: ChatResponse =
            serde_json::from_slice(&bytes).map_err(|_| ModelError::Invalid)?;
        if !envelope.done
            || envelope.message.role != "assistant"
            || envelope
                .done_reason
                .as_deref()
                .is_some_and(|reason| reason != "stop")
        {
            return Err(ModelError::Invalid);
        }
        let analysis: Analysis =
            serde_json::from_str(&envelope.message.content).map_err(|_| ModelError::Invalid)?;
        if !analysis.validate() {
            return Err(ModelError::Invalid);
        }
        Ok(analysis)
    }
}

fn transport_error(error: reqwest::Error) -> ModelError {
    // Intentionally discard provider text and raw error strings: they can carry
    // URLs, bodies, credentials or other customer information.
    if error.is_timeout() {
        ModelError::Timeout
    } else {
        ModelError::Transport
    }
}

fn fallback(ticket: &Ticket, attempts: u8, reason: &str) -> AnalysisOutcome {
    AnalysisOutcome {
        analysis: Analysis {
            category: Category::Other,
            severity: Severity::Medium,
            language: infer_language(ticket),
            confidence: 0.0,
            refund_requested: false,
            details: Default::default(),
        },
        source: AnalysisSource::Fallback,
        attempts,
        degraded_reason: Some(reason.to_owned()),
        usage: Default::default(),
        cached: false,
    }
}

fn infer_language(ticket: &Ticket) -> Language {
    let text = format!("{} {}", ticket.subject, ticket.body).to_lowercase();
    let hints = [
        "paisa", "paise", "bhai", "maine", "nahi", "nahin", "kiya", "karo", "gaya", "dikha",
        "jaldi", "mera", "mujhe", "hai", "hoon",
    ];
    let matches = text
        .split(|c: char| !c.is_alphabetic())
        .filter(|word| hints.contains(word))
        .take(2)
        .count();
    if text.chars().any(|c| ('\u{0900}'..='\u{097f}').contains(&c)) || matches >= 2 {
        Language::Hinglish
    } else {
        Language::English
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replay_matches_synthetic_content_and_ignores_ticket_identifier() {
        let mut input: Ticket = serde_json::from_value(json!({
            "id": "synthetic-reference-one",
            "received_at": "2030-01-15T12:00:00+00:00",
            "subject": "Synthetic request about a sample transaction",
            "body": "Please return the payment in this invented testing scenario.",
            "purchases": [],
            "app_opens_since_renewal": 0
        }))
        .unwrap();
        let analysis = Analysis {
            category: Category::BillingRefund,
            severity: Severity::High,
            language: Language::English,
            confidence: 0.97,
            refund_requested: true,
            details: Default::default(),
        };
        let entries = HashMap::from([(input.content_fingerprint(), analysis)]);
        let analyzer = Analyzer::from_backend(Backend::Replay(entries), "synthetic-replay");
        let replay = analyzer.analyze(&input).await;
        assert_eq!(replay.source, AnalysisSource::Replay);
        assert_eq!(replay.analysis.category, Category::BillingRefund);
        assert_eq!(replay.analysis.confidence, 0.97);
        assert!(replay.analysis.refund_requested);
        assert_eq!(replay.attempts, 0);

        input.id = "synthetic-reference-two".into();
        assert_eq!(
            analyzer.analyze(&input).await.source,
            AnalysisSource::Replay
        );
        input
            .body
            .push_str(" Additional synthetic context changes the content.");
        let changed = analyzer.analyze(&input).await;
        assert_eq!(changed.source, AnalysisSource::Fallback);
        assert_eq!(
            changed.degraded_reason.as_deref(),
            Some("unknown_replay_content")
        );
    }
}
