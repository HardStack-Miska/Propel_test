//! The model classifies untrusted text; it never decides refunds or writes replies.

use crate::cache::{AnalysisCache, CacheConfig, CacheStatistics, Lookup};
use crate::domain::{
    Analysis, AnalysisDetails, AnalysisOutcome, AnalysisSource, Category, Language, ReportedFact,
    Severity, Ticket,
};
use anyhow::{Result, bail};
use reqwest::{Client, Url, redirect::Policy};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::Instant};

const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_ATTEMPTS: u8 = 2;

/// Provider-only citations. They are checked and discarded before an Analysis
/// can enter the cache, refund policy, persistence, reply renderer, or logs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelAnalysis {
    category: Category,
    severity: Severity,
    language: Language,
    confidence: f64,
    refund_requested: bool,
    details: AnalysisDetails,
    #[serde(default)]
    evidence: SourceEvidence,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEvidence {
    billing_details: Option<BillingEvidence>,
    payment_reference: Option<ValueEvidence>,
    account_access: Option<AccountEvidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BillingEvidence {
    kind: BillingEvidenceKind,
    value: String,
    quote: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum BillingEvidenceKind {
    BillingName,
    BillingAddress,
    TaxIdentifier,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueEvidence {
    value: String,
    quote: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountEvidence {
    issue: AccountProblem,
    quote: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AccountProblem {
    SignInFailure,
    IdentityMismatch,
    MissingAccountData,
}

pub(crate) fn parse_grounded_analysis(content: &str, ticket: &Ticket) -> Option<Analysis> {
    parse_analysis_evidence(content, ticket, false)
}

pub(crate) fn parse_grounded_analysis_after_retry(
    content: &str,
    ticket: &Ticket,
) -> Option<Analysis> {
    parse_analysis_evidence(content, ticket, true)
}

fn parse_analysis_evidence(
    content: &str,
    ticket: &Ticket,
    final_attempt: bool,
) -> Option<Analysis> {
    // Deserialize the full wire type FIRST: removing evidence from a Value
    // before validation would hide duplicate keys and weaken the boundary.
    let wire: ModelAnalysis = serde_json::from_str(content).ok()?;
    let original: serde_json::Value = serde_json::from_str(content).ok()?;
    let details = original.get("details")?.as_object()?;
    if ![
        "secondary_intent",
        "additional_intents",
        "refund_target",
        "unsupported_language",
        "reported",
        "missing",
    ]
    .iter()
    .all(|field| details.contains_key(*field))
    {
        return None;
    }
    let mut analysis = Analysis {
        category: wire.category,
        severity: wire.severity,
        language: wire.language,
        confidence: wire.confidence,
        refund_requested: wire.refund_requested,
        details: wire.details,
    };
    if !analysis.validate()
        || !wire
            .evidence
            .reconcile(&mut analysis, ticket, final_attempt)
    {
        return None;
    }
    // Only typed labels survive; no quotation or extracted value is serialized.
    Analysis::parse_model_json(&serde_json::to_string(&analysis).ok()?)
}

impl SourceEvidence {
    fn reconcile(&self, analysis: &mut Analysis, ticket: &Ticket, final_attempt: bool) -> bool {
        // Hard wire limits apply before any optional-claim filtering.
        if self
            .billing_details
            .as_ref()
            .is_some_and(|entry| entry.quote.len() > 160 || entry.value.len() > 96)
            || self
                .payment_reference
                .as_ref()
                .is_some_and(|entry| entry.quote.len() > 160 || entry.value.len() > 96)
            || self
                .account_access
                .as_ref()
                .is_some_and(|entry| entry.quote.len() > 160)
        {
            return false;
        }
        let reported = &analysis.details.reported;
        let billing_claimed = reported.contains(&ReportedFact::BillingDetailsProvided);
        let reference_claimed = reported.contains(&ReportedFact::PaymentReferenceProvided);
        let account_claimed = analysis.has_intent(Category::AccountAccess);
        if (!billing_claimed && self.billing_details.is_some())
            || (!reference_claimed && self.payment_reference.is_some())
            || (!account_claimed && self.account_access.is_some())
        {
            return false;
        }
        let billing_valid = self.billing_details.as_ref().is_some_and(|evidence| {
            let labels: &[&str] = match evidence.kind {
                BillingEvidenceKind::BillingName => &[
                    "billing name",
                    "company name",
                    "legal name",
                    "invoice name",
                    "bill to",
                    "invoice to",
                    "naam",
                    "name",
                ],
                BillingEvidenceKind::BillingAddress => &["address", "pata", "pataa"],
                BillingEvidenceKind::TaxIdentifier => &["tax", "gst", "gstin", "vat", "pan"],
            };
            provided_value(&evidence.value, &evidence.quote, ticket)
                && has_phrase(&evidence.quote, labels)
                && evidence.value.chars().any(char::is_alphabetic)
        });
        let reference_valid = self.payment_reference.as_ref().is_some_and(|evidence| {
            provided_value(&evidence.value, &evidence.quote, ticket)
                && evidence.value.chars().count() >= 6
                && !evidence.value.chars().any(char::is_whitespace)
                && has_phrase(
                    &evidence.quote,
                    &[
                        "reference",
                        "ref",
                        "utr",
                        "transaction id",
                        "payment id",
                        "txn",
                        "transaction identifier",
                    ],
                )
                && ![
                    "reference",
                    "missing",
                    "unknown",
                    "unavailable",
                    "pending",
                    "provided",
                ]
                .contains(&evidence.value.to_lowercase().as_str())
        });
        let account_valid = self.account_access.as_ref().is_some_and(|evidence| {
            quoted_source(&evidence.quote, ticket) && supports_account_problem(evidence)
        });
        let remove_billing = billing_claimed && !billing_valid;
        let remove_reference = reference_claimed && !reference_valid;
        // Conservative citation checks never remove substantive goals.
        // Unproved primary or secondary account goals require retry/fallback.
        if account_claimed && !account_valid {
            return false;
        }
        if (remove_billing || remove_reference) && !final_attempt {
            return false;
        }
        analysis.details.reported.retain(|fact| {
            !(*fact == ReportedFact::BillingDetailsProvided && remove_billing
                || *fact == ReportedFact::PaymentReferenceProvided && remove_reference)
        });
        if remove_billing || remove_reference {
            tracing::info!(
                event = "model_evidence_filtered",
                billing_details_removed = remove_billing,
                payment_reference_removed = remove_reference
            );
        }
        true
    }
}

fn quoted_source(quote: &str, ticket: &Ticket) -> bool {
    !quote.trim().is_empty()
        && quote.len() <= 160
        && (ticket.subject.contains(quote) || ticket.body.contains(quote))
}

fn provided_value(value: &str, quote: &str, ticket: &Ticket) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && quoted_source(quote, ticket)
        && quote.contains(value)
        && !bare_billing_scalar(value)
        && ![
            "billing name",
            "company name",
            "name",
            "address",
            "billing address",
            "tax identifier",
            "tax id",
            "reference",
            "payment reference",
            "transaction",
            "transaction reference",
            "transaction id",
            "payment id",
            "utr",
            "txn",
            "none",
            "unknown",
            "missing",
            "unavailable",
            "not available",
        ]
        .contains(&value.to_lowercase().as_str())
}

/// These are guards for a claimed extracted value, never a classifier or a
/// keyword override of the customer's entire message. Source matches prove
/// provenance, not truth; general semantic ambiguity still needs review.
fn bare_billing_scalar(value: &str) -> bool {
    let lower = value.to_lowercase();
    if [
        "successful",
        "failed",
        "initiated",
        "renewal",
        "pending",
        "paid",
        "debited",
        "active",
        "inactive",
        "today",
        "yesterday",
        "aaj",
        "kal",
        "not provided",
        "not supplied",
        "not given",
        "nahi diya",
    ]
    .contains(&lower.as_str())
    {
        return true;
    }
    let trimmed = lower.trim();
    let currency = trimmed.starts_with(['₹', '$', '€', '£'])
        || trimmed.starts_with("inr")
        || trimmed.starts_with("rs");
    let amount = trimmed.trim_start_matches(['₹', '$', '€', '£']).trim();
    let amount = amount
        .strip_prefix("inr")
        .or_else(|| amount.strip_prefix("rs"))
        .unwrap_or(amount)
        .trim_start_matches(['.', ' ']);
    let amount = amount.replace([',', ' '], "");
    if amount.parse::<f64>().is_ok() {
        // Long numeric bank references remain possible. Grounding must not read
        // purchase history: this analysis is cached by subject/body alone.
        if currency || amount.len() < 6 {
            return true;
        }
    }
    chrono::DateTime::parse_from_rfc3339(value).is_ok()
        || ["%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%Y%m%d"]
            .iter()
            .any(|format| chrono::NaiveDate::parse_from_str(value, format).is_ok())
}

fn has_phrase(text: &str, phrases: &[&str]) -> bool {
    let text = format!(
        " {} ",
        text.to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|word| !word.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    );
    phrases
        .iter()
        .any(|phrase| text.contains(&format!(" {phrase} ")))
}

fn supports_account_problem(evidence: &AccountEvidence) -> bool {
    // Contrast clauses must not lend a billing symptom to a successful login.
    // This is conservative quote sanity, not a universal sentence parser.
    let mut quote = evidence.quote.to_lowercase();
    for separator in [" but ", " lekin "] {
        quote = quote.replace(separator, ";");
    }
    quote
        .split([';', '.', '\n'])
        .any(|clause| match evidence.issue {
            AccountProblem::SignInFailure => {
                has_phrase(
                    clause,
                    &[
                        "login",
                        "log in",
                        "sign in",
                        "signin",
                        "authentication",
                        "authenticate",
                        "password",
                        "otp",
                        "verification code",
                    ],
                ) && has_phrase(
                    clause,
                    &[
                        "cannot",
                        "can t",
                        "unable",
                        "failed",
                        "fails",
                        "failure",
                        "error",
                        "invalid",
                        "rejected",
                        "denied",
                        "expired",
                        "not found",
                        "loop",
                        "back",
                        "stuck",
                        "not working",
                        "will not let",
                        "won t let",
                        "does not let",
                        "login nahi",
                        "login nahin",
                        "sign in nahi",
                        "signin nahi",
                        "otp nahi",
                        "wapas",
                        "wapis",
                        "atka",
                    ],
                )
            }
            AccountProblem::IdentityMismatch => {
                has_phrase(clause, &["account", "profile", "identity"])
                    && has_phrase(
                        clause,
                        &[
                            "different",
                            "wrong",
                            "another",
                            "someone",
                            "not mine",
                            "mismatch",
                            "alag",
                            "dusra",
                            "doosra",
                            "galat",
                        ],
                    )
            }
            AccountProblem::MissingAccountData => {
                has_phrase(
                    clause,
                    &[
                        "history",
                        "orders",
                        "saved",
                        "bookmarks",
                        "progress",
                        "notes",
                    ],
                ) && has_phrase(
                    clause,
                    &[
                        "missing",
                        "empty",
                        "lost",
                        "gone",
                        "disappeared",
                        "vanished",
                        "not showing",
                        "cannot see",
                        "can t see",
                        "khali",
                        "khaali",
                        "gayab",
                        "gaayab",
                        "nahi",
                        "nahin",
                    ],
                )
            }
        })
}

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
    tool_calls: Option<Vec<serde_json::Value>>,
    function_call: Option<serde_json::Value>,
    thinking: Option<String>,
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
            "analysis-schema-v3",
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
        let identity = json!(["ollama", endpoint.as_str(), model, 512, 0]).to_string();
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
            "options": { "temperature": 0, "num_predict": 512 },
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
                .message
                .tool_calls
                .as_ref()
                .is_some_and(|v| !v.is_empty())
            || envelope
                .message
                .function_call
                .as_ref()
                .is_some_and(|v| !v.is_null())
            || envelope
                .message
                .thinking
                .as_ref()
                .is_some_and(|v| !v.trim().is_empty())
            || envelope
                .done_reason
                .as_deref()
                .is_some_and(|reason| reason != "stop")
        {
            return Err(ModelError::Invalid);
        }
        let analysis = if retry {
            parse_grounded_analysis_after_retry(&envelope.message.content, ticket)
        } else {
            parse_grounded_analysis(&envelope.message.content, ticket)
        };
        analysis.ok_or(ModelError::Invalid)
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
    // Fallback language is only a best-effort presentation choice. A non-Latin
    // script alone does not establish that an unsupported request is Hinglish.
    if matches >= 2 {
        Language::Hinglish
    } else {
        Language::English
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_ticket(body: &str) -> Ticket {
        serde_json::from_value(json!({"id":"synthetic-evidence-case",
            "received_at":"2033-01-15T12:00:00Z", "subject":"Support request", "body":body,
            "purchases":[], "app_opens_since_renewal":0}))
        .unwrap()
    }

    fn evidence_output(category: Category, reported: &[&str]) -> serde_json::Value {
        json!({"category":category,"severity":"medium","language":"english","confidence":0.95,
            "refund_requested":false,"details":{"secondary_intent":null,"additional_intents":[],
                "refund_target":"unspecified","unsupported_language":false,"reported":reported,"missing":[]}})
    }

    #[test]
    fn supplied_billing_facts_require_grounded_values_not_just_amounts_dates_or_status() {
        let ticket = evidence_ticket(
            "My payment of Rs 249 on 2033-01-14 is pending. Please check activation.",
        );
        for fact in ["billing_details_provided", "payment_reference_provided"] {
            let mut output = evidence_output(Category::BillingStatus, &[fact]);
            assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_none());
            for value in ["Rs 249", "249", "2033-01-14", "pending"] {
                output["evidence"] = if fact == "billing_details_provided" {
                    json!({"billing_details":{"kind":"billing_name","value":value,"quote":ticket.body}})
                } else {
                    json!({"payment_reference":{"value":value,"quote":ticket.body}})
                };
                assert!(
                    parse_grounded_analysis(&output.to_string(), &ticket).is_none(),
                    "accepted {fact} from {value}"
                );
            }
        }
        for scalar in [
            "Rs.249",
            "INR 1234567",
            "₹1000000",
            "2033-01-14T12:00:00Z",
            "yesterday",
        ] {
            assert!(bare_billing_scalar(scalar), "accepted scalar {scalar}");
        }
    }

    #[test]
    fn real_english_and_hinglish_billing_values_survive_without_persisting_evidence() {
        for (body, label) in [
            (
                "Billing name is Example Workshop. Payment reference is REF-981234.",
                "Billing name is Example Workshop.",
            ),
            (
                "Billing naam Example Workshop hai. Payment reference REF-981234 hai.",
                "Billing naam Example Workshop hai.",
            ),
            (
                "Invoice to Example Workshop. Payment reference is REF-981234.",
                "Invoice to Example Workshop.",
            ),
        ] {
            let ticket = evidence_ticket(body);
            let mut output = evidence_output(
                Category::Invoice,
                &["billing_details_provided", "payment_reference_provided"],
            );
            output["evidence"] = json!({
                "billing_details":{"kind":"billing_name","value":"Example Workshop","quote":label},
                "payment_reference":{"value":"REF-981234","quote":body}
            });
            let analysis = parse_grounded_analysis(&output.to_string(), &ticket).unwrap();
            assert!(
                analysis
                    .details
                    .reported
                    .contains(&ReportedFact::BillingDetailsProvided)
            );
            assert!(
                analysis
                    .details
                    .reported
                    .contains(&ReportedFact::PaymentReferenceProvided)
            );
            let retained = serde_json::to_string(&analysis).unwrap();
            for private in ["Example Workshop", "REF-981234", "quote", "evidence"] {
                assert!(!retained.contains(private));
            }
        }
    }

    #[test]
    fn fabricated_mismatched_and_oversized_source_quotes_fail_closed() {
        let ticket = evidence_ticket("Billing name is Sample Studio.");
        for (value, quote) in [
            (
                "Sample Studio",
                "Billing name is Invented Studio.".to_owned(),
            ),
            ("Invented Studio", ticket.body.clone()),
            ("Sample Studio", "x".repeat(161)),
        ] {
            let mut output = evidence_output(Category::Invoice, &["billing_details_provided"]);
            output["evidence"] =
                json!({"billing_details":{"kind":"billing_name","value":value,"quote":quote}});
            assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_none());
        }
        for (body, fact, evidence) in [
            (
                "I have not supplied my billing name.",
                "billing_details_provided",
                json!({"billing_details":{"kind":"billing_name","value":"billing name","quote":"billing name"}}),
            ),
            (
                "No transaction reference was supplied.",
                "payment_reference_provided",
                json!({"payment_reference":{"value":"transaction","quote":"transaction reference"}}),
            ),
        ] {
            let ticket = evidence_ticket(body);
            let mut output = evidence_output(Category::BillingStatus, &[fact]);
            output["evidence"] = evidence;
            assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_none());
        }
    }

    #[test]
    fn activation_alone_does_not_support_an_extra_account_access_intent() {
        for body in [
            "The subscription payment is pending and paid content is locked.",
            "I can sign in, but the paid lessons are locked after payment.",
            "Login ho gaya. Payment ke baad paid lessons abhi bhi locked hain.",
            "Login works normally, but the subscription is not working.",
        ] {
            let ticket = evidence_ticket(body);
            let mut output = evidence_output(Category::BillingStatus, &["bank_debit_reported"]);
            assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_some());
            output["details"]["secondary_intent"] = json!("account_access");
            assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_none());
            output["evidence"] = json!({"account_access":{"issue":"sign_in_failure","quote":body}});
            assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_none());
        }
    }

    #[test]
    fn genuine_missing_history_and_english_or_latin_hindi_auth_failures_remain_supported() {
        for (body, issue) in [
            (
                "Order history is empty after I changed my phone, using the same Google account.",
                "missing_account_data",
            ),
            (
                "Meri order history khali hai, Google account wahi hai.",
                "missing_account_data",
            ),
            (
                "Phone sign-in sends me back to the login page.",
                "sign_in_failure",
            ),
            (
                "Phone se login karte waqt OTP accept hota hai, phir wapas login page aa jata hai.",
                "sign_in_failure",
            ),
            (
                "My profile shows a different account identity.",
                "identity_mismatch",
            ),
            ("My OTP expired.", "sign_in_failure"),
            ("My saved items vanished.", "missing_account_data"),
            (
                "Email sign-in will not let me access my profile.",
                "sign_in_failure",
            ),
            ("Login screen par stuck hoon.", "sign_in_failure"),
            ("OTP screen par atka hoon.", "sign_in_failure"),
        ] {
            let ticket = evidence_ticket(body);
            let mut output = evidence_output(Category::AccountAccess, &[]);
            output["evidence"] = json!({"account_access":{"issue":issue,"quote":body}});
            assert!(
                parse_grounded_analysis(&output.to_string(), &ticket).is_some(),
                "rejected actual issue {body}"
            );
        }
    }

    #[test]
    fn provider_wire_keeps_required_details_and_duplicate_key_rejection() {
        let ticket = evidence_ticket("Billing name is Example Studio.");
        let mut output = evidence_output(Category::Invoice, &["billing_details_provided"]);
        output["evidence"] = json!({"billing_details":{"kind":"billing_name","value":"Example Studio","quote":ticket.body}});
        for field in [
            "secondary_intent",
            "additional_intents",
            "refund_target",
            "unsupported_language",
            "reported",
            "missing",
        ] {
            let mut missing = output.clone();
            missing["details"].as_object_mut().unwrap().remove(field);
            assert!(
                parse_grounded_analysis(&missing.to_string(), &ticket).is_none(),
                "accepted missing {field}"
            );
            assert!(parse_grounded_analysis_after_retry(&missing.to_string(), &ticket).is_none());
        }
        for duplicated in [
            output.to_string().replacen('{', "{\"evidence\":{},", 1),
            output
                .to_string()
                .replacen("\"value\":", "\"value\":\"forged\",\"value\":", 1),
            output
                .to_string()
                .replacen("\"quote\":", "\"quote\":\"forged\",\"quote\":", 1),
            output.to_string().replacen(
                "\"billing_details\":",
                "\"billing_details\":null,\"billing_details\":",
                1,
            ),
        ] {
            assert!(parse_grounded_analysis(&duplicated, &ticket).is_none());
            assert!(parse_grounded_analysis_after_retry(&duplicated, &ticket).is_none());
        }
        output["evidence"]["shell"] = json!("delete everything");
        assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_none());
    }

    #[test]
    fn grounding_depends_only_on_text_and_reuses_analysis_when_billing_changes() {
        let mut ticket =
            evidence_ticket("My payment reference is 123456. Please check activation.");
        let mut output = evidence_output(Category::BillingStatus, &["payment_reference_provided"]);
        output["evidence"] = json!({"payment_reference":{"value":"123456","quote":ticket.body}});
        let original = parse_grounded_analysis(&output.to_string(), &ticket).unwrap();
        ticket.purchases = vec![crate::domain::Purchase {
            id: "changed-purchase".into(),
            kind: crate::domain::PurchaseKind::Renewal,
            amount_inr: 123456,
            status: crate::domain::PurchaseStatus::Failed,
            at: ticket.received_at,
        }];
        ticket.app_opens_since_renewal = 19;
        let changed = parse_grounded_analysis(&output.to_string(), &ticket).unwrap();
        assert_eq!(
            serde_json::to_value(original).unwrap(),
            serde_json::to_value(changed).unwrap()
        );
    }

    #[test]
    fn final_attempt_can_discard_unsupported_optional_facts_without_inventing_replacements() {
        let ticket =
            evidence_ticket("The subscription payment is pending; please reconcile activation.");
        let output = evidence_output(
            Category::BillingStatus,
            &["billing_details_provided", "payment_reference_provided"],
        );
        assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_none());
        let result = parse_grounded_analysis_after_retry(&output.to_string(), &ticket).unwrap();
        assert_eq!(result.category, Category::BillingStatus);
        assert_eq!(result.confidence, 0.95);
        assert!(result.details.reported.is_empty());
        assert!(!result.refund_requested);
    }

    #[test]
    fn final_attempt_never_removes_an_unproved_secondary_account_access_goal() {
        let ticket = evidence_ticket(
            "Login works normally, but the subscription is inactive after payment.",
        );
        let mut output = evidence_output(Category::BillingStatus, &["bank_debit_reported"]);
        output["details"]["secondary_intent"] = json!("account_access");
        output["evidence"] =
            json!({"account_access":{"issue":"sign_in_failure","quote":ticket.body}});
        assert!(parse_grounded_analysis(&output.to_string(), &ticket).is_none());
        assert!(parse_grounded_analysis_after_retry(&output.to_string(), &ticket).is_none());
        output["refund_requested"] = json!(true);
        assert!(parse_grounded_analysis_after_retry(&output.to_string(), &ticket).is_none());
        output["refund_requested"] = json!(false);
        output["category"] = json!("invoice");
        assert!(parse_grounded_analysis_after_retry(&output.to_string(), &ticket).is_none());

        let ticket = evidence_ticket(
            "Authentication is denied after entering credentials. Subscription activation also needs checking.",
        );
        output["category"] = json!("billing_status");
        output["evidence"] = json!({"account_access":{"issue":"sign_in_failure",
            "quote":"Authentication is denied after entering credentials."}});
        let result = parse_grounded_analysis_after_retry(&output.to_string(), &ticket).unwrap();
        assert_eq!(result.category, Category::BillingStatus);
        assert!(result.has_intent(Category::AccountAccess));
    }

    #[test]
    fn final_attempt_still_rejects_an_unproved_primary_account_access_goal() {
        let ticket = evidence_ticket("The subscription is inactive after payment.");
        let mut output = evidence_output(Category::AccountAccess, &[]);
        assert!(parse_grounded_analysis_after_retry(&output.to_string(), &ticket).is_none());
        output["evidence"] =
            json!({"account_access":{"issue":"sign_in_failure","quote":ticket.body}});
        assert!(parse_grounded_analysis_after_retry(&output.to_string(), &ticket).is_none());
    }

    #[test]
    fn final_attempt_never_filters_away_hard_shape_or_size_violations() {
        let ticket = evidence_ticket("Billing name is Example Studio.");
        let mut output = evidence_output(Category::Invoice, &["billing_details_provided"]);
        output["evidence"] = json!({"billing_details":{"kind":"billing_name","value":"Example Studio","quote":ticket.body}});
        for (pointer, invalid) in [
            ("/evidence/billing_details/quote", json!("x".repeat(161))),
            ("/evidence/billing_details/value", json!("x".repeat(97))),
            ("/details/reported", json!(vec!["crash"; 9])),
            ("/details/missing", json!(vec!["device"; 5])),
        ] {
            let mut invalid_output = output.clone();
            *invalid_output.pointer_mut(pointer).unwrap() = invalid;
            assert!(
                parse_grounded_analysis_after_retry(&invalid_output.to_string(), &ticket).is_none()
            );
        }
        output["evidence"]["billing_details"]["shell"] = json!("delete records");
        assert!(parse_grounded_analysis_after_retry(&output.to_string(), &ticket).is_none());
    }

    #[test]
    fn fallback_matches_latin_hinglish_without_treating_any_hindi_script_as_hinglish() {
        let mut ticket: Ticket = serde_json::from_value(json!({
            "id": "synthetic-fallback-language", "received_at": "2033-01-01T12:00:00Z",
            "subject": "Support", "body": "Bhai mera plan nahi chal raha hai.",
            "purchases": [], "app_opens_since_renewal": 0
        }))
        .unwrap();
        let outcome = fallback(&ticket, 0, "unknown_replay_content");
        assert_eq!(outcome.analysis.language, Language::Hinglish);
        assert_eq!(outcome.analysis.confidence, 0.0);
        for body in [
            "कृपया सहायता करें।",
            "Please help with my account.",
            "Помогите с оплатой.",
        ] {
            ticket.body = body.into();
            assert_eq!(
                fallback(&ticket, 0, "unknown_replay_content")
                    .analysis
                    .language,
                Language::English
            );
        }
    }

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
