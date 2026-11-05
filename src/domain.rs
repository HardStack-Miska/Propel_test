use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub id: String,
    pub received_at: DateTime<FixedOffset>,
    pub subject: String,
    pub body: String,
    pub purchases: Vec<Purchase>,
    pub app_opens_since_renewal: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Purchase {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: PurchaseKind,
    pub amount_inr: u32,
    pub status: PurchaseStatus,
    pub at: DateTime<FixedOffset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurchaseKind {
    Trial,
    Renewal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurchaseStatus {
    Initiated,
    Failed,
    Successful,
    Renewal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    BillingRefund,
    BillingStatus,
    Cancellation,
    Technical,
    AccountAccess,
    FeatureRequest,
    Fraud,
    Invoice,
    ProductQuestion,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Urgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    English,
    Hinglish,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Analysis {
    pub category: Category,
    pub severity: Severity,
    pub language: Language,
    pub confidence: f64,
    pub refund_requested: bool,
    #[serde(default)]
    pub details: AnalysisDetails,
}

/// These are predictions about the customer's words, never verified account
/// state or authority to perform an action. No free text crosses this boundary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisDetails {
    #[serde(default)]
    pub secondary_intent: Option<Category>,
    #[serde(default)]
    pub reported: Vec<ReportedFact>,
    #[serde(default)]
    pub missing: Vec<MissingDetail>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportedFact {
    GoogleSignIn,
    PhoneSignIn,
    EmailSignIn,
    DeviceProvided,
    AppVersionProvided,
    ErrorDetailsProvided,
    MissingHistory,
    Crash,
    BillingDetailsProvided,
    PaymentReferenceProvided,
    OfflineAccess,
    CancellationExplicit,
    RefundExplicit,
    AutopayDisabled,
    BankDebitReported,
    TwoDebitsReported,
    RestartTried,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingDetail {
    CancellationTarget,
    TechnicalSymptom,
    Device,
    AppVersion,
    ErrorDetails,
    SignInMethod,
    MissingAccountData,
    PaymentReference,
    BillingDetails,
    RequestedFeature,
    RequestGoal,
}

impl Analysis {
    pub fn validate(&self) -> bool {
        self.confidence.is_finite()
            && (0.0..=1.0).contains(&self.confidence)
            && self.details.reported.len() <= 8
            && self.details.missing.len() <= 4
            && self.details.reported.iter().collect::<HashSet<_>>().len()
                == self.details.reported.len()
            && self.details.missing.iter().collect::<HashSet<_>>().len()
                == self.details.missing.len()
            && self.details.secondary_intent != Some(self.category)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSource {
    Replay,
    Ollama,
    Deepseek,
    Fallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOutcome {
    pub analysis: Analysis,
    pub source: AnalysisSource,
    pub attempts: u8,
    pub degraded_reason: Option<String>,
    #[serde(default)]
    pub usage: crate::deepseek::UsageTotals,
    #[serde(default)]
    pub cached: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundDecision {
    Approved,
    ReviewRequired,
    NotRequested,
    NotEligible,
    AlreadyRecorded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refund {
    pub decision: RefundDecision,
    pub amount_inr: u32,
    pub purchase_id: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub ticket_id: String,
    pub category: Category,
    pub severity: Severity,
    pub refund: Refund,
    pub reply_draft: String,
    pub needs_human: bool,
    pub confidence: f64,
    pub safety: Safety,
    pub meta: ResultMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Safety {
    pub injection_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMeta {
    pub source: AnalysisSource,
    pub model_attempts: u8,
    pub degraded_reason: Option<String>,
    pub policy_version: String,
    #[serde(default)]
    pub usage: crate::deepseek::UsageTotals,
    #[serde(default)]
    pub analysis_cached: bool,
    #[serde(default)]
    pub language: Option<Language>,
}

impl Ticket {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty() || self.id.len() > 128 {
            return Err("invalid_ticket_id");
        }
        if self.subject.trim().is_empty() || self.subject.len() > 512 {
            return Err("invalid_subject");
        }
        if self.body.trim().is_empty() || self.body.len() > 16_384 {
            return Err("invalid_body");
        }
        if self.purchases.len() > 128 {
            return Err("too_many_purchases");
        }
        let mut ids = HashSet::new();
        for p in &self.purchases {
            if p.id.trim().is_empty() || p.id.len() > 128 || !ids.insert(&p.id) {
                return Err("invalid_purchase_id");
            }
            if p.amount_inr == 0 || p.amount_inr > 1_000_000 {
                return Err("invalid_amount");
            }
            if p.at > self.received_at {
                return Err("purchase_after_ticket");
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        // Struct serialization has stable field order; purchase order is significant.
        hash_bytes(&serde_json::to_vec(self).expect("serializable ticket"))
    }

    pub fn content_fingerprint(&self) -> String {
        hash_bytes(&serde_json::to_vec(&(&self.subject, &self.body)).expect("serializable text"))
    }
}

pub fn hash_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}
