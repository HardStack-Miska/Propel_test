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

    /// Resolve contradictory clarification flags using only existing typed
    /// evidence. This neither reads customer text nor adds facts or authority.
    /// Providers call this after validating the original output's shape/limits.
    pub fn normalize_details(&mut self) {
        let reported = &self.details.reported;
        self.details.missing.retain(|missing| {
            let provided = match missing {
                MissingDetail::Device => reported.contains(&ReportedFact::DeviceProvided),
                MissingDetail::AppVersion => reported.contains(&ReportedFact::AppVersionProvided),
                MissingDetail::PaymentReference => {
                    reported.contains(&ReportedFact::PaymentReferenceProvided)
                }
                MissingDetail::BillingDetails => {
                    reported.contains(&ReportedFact::BillingDetailsProvided)
                }
                MissingDetail::SignInMethod => reported.iter().any(|fact| {
                    matches!(
                        fact,
                        ReportedFact::GoogleSignIn
                            | ReportedFact::PhoneSignIn
                            | ReportedFact::EmailSignIn
                    )
                }),
                MissingDetail::MissingAccountData => {
                    reported.contains(&ReportedFact::MissingHistory)
                }
                MissingDetail::ErrorDetails | MissingDetail::TechnicalSymptom => {
                    reported.iter().any(|fact| {
                        matches!(
                            fact,
                            ReportedFact::ErrorDetailsProvided | ReportedFact::Crash
                        )
                    })
                }
                MissingDetail::CancellationTarget => {
                    reported.contains(&ReportedFact::CancellationExplicit)
                }
                MissingDetail::RequestedFeature => reported.contains(&ReportedFact::OfflineAccess),
                MissingDetail::RequestGoal => false,
            };
            !provided
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn analysis(reported: Vec<ReportedFact>, missing: Vec<MissingDetail>) -> Analysis {
        Analysis {
            category: Category::Technical,
            severity: Severity::High,
            language: Language::Hinglish,
            confidence: 0.91,
            refund_requested: false,
            details: AnalysisDetails {
                secondary_intent: Some(Category::Cancellation),
                reported,
                missing,
            },
        }
    }

    #[test]
    fn normalization_removes_only_missing_details_answered_by_typed_evidence() {
        use MissingDetail as M;
        use ReportedFact as R;
        for (reported, missing) in [
            (R::DeviceProvided, M::Device),
            (R::AppVersionProvided, M::AppVersion),
            (R::PaymentReferenceProvided, M::PaymentReference),
            (R::BillingDetailsProvided, M::BillingDetails),
            (R::GoogleSignIn, M::SignInMethod),
            (R::PhoneSignIn, M::SignInMethod),
            (R::EmailSignIn, M::SignInMethod),
            (R::MissingHistory, M::MissingAccountData),
            (R::ErrorDetailsProvided, M::ErrorDetails),
            (R::ErrorDetailsProvided, M::TechnicalSymptom),
            (R::Crash, M::ErrorDetails),
            (R::Crash, M::TechnicalSymptom),
            (R::CancellationExplicit, M::CancellationTarget),
            (R::OfflineAccess, M::RequestedFeature),
        ] {
            let mut value = analysis(vec![reported], vec![missing, M::RequestGoal]);
            assert!(value.validate());
            value.normalize_details();
            assert_eq!(value.details.reported, vec![reported]);
            assert_eq!(value.details.missing, vec![M::RequestGoal]);
            assert!(value.validate());
        }
    }

    #[test]
    fn normalization_is_idempotent_and_does_not_change_decision_authority() {
        let mut value = analysis(
            vec![ReportedFact::MissingHistory, ReportedFact::EmailSignIn],
            vec![
                MissingDetail::MissingAccountData,
                MissingDetail::SignInMethod,
                MissingDetail::AppVersion,
            ],
        );
        let before = value.clone();
        value.normalize_details();
        let once = serde_json::to_value(&value).unwrap();
        value.normalize_details();
        assert_eq!(serde_json::to_value(&value).unwrap(), once);
        assert_eq!(value.category, before.category);
        assert_eq!(value.severity, before.severity);
        assert_eq!(value.language, before.language);
        assert_eq!(value.confidence, before.confidence);
        assert_eq!(value.refund_requested, before.refund_requested);
        assert_eq!(
            value.details.secondary_intent,
            before.details.secondary_intent
        );
        assert_eq!(value.details.reported, before.details.reported);
        assert_eq!(value.details.missing, vec![MissingDetail::AppVersion]);

        let mut no_evidence = analysis(
            Vec::new(),
            vec![MissingDetail::Device, MissingDetail::ErrorDetails],
        );
        no_evidence.refund_requested = true;
        let before = serde_json::to_value(&no_evidence).unwrap();
        no_evidence.normalize_details();
        assert_eq!(serde_json::to_value(&no_evidence).unwrap(), before);
        assert!(no_evidence.details.reported.is_empty());
    }
}
