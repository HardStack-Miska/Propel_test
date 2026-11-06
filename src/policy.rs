//! Deterministic, deliberately narrow refund policy for this assessment.
//!
//! These are explicit implementation assumptions, not a supplied Propel policy.
//! Model output describes intent; only trusted billing fields determine money.

use crate::domain::*;
use chrono::Duration;

pub const POLICY_VERSION: &str = "assumed-dhaba-v4";
const MIN_CONFIDENCE: f64 = 0.85;
const MONTHLY_PRICE_INR: u32 = 249;

pub fn evaluate(ticket: &Ticket, outcome: &AnalysisOutcome) -> TriageResult {
    let analysis = &outcome.analysis;
    let content = format!("{}\n{}", ticket.subject, ticket.body).to_lowercase();
    let injection_detected = detects_injection(&content);
    // Fraud is a semantic intent. Raw phrases cannot distinguish an unauthorized
    // payment from an optional installation, a quotation, or a hypothetical.
    // Financial authorization remains independently bounded by trusted records.
    let unsupported_language = analysis.details.unsupported_language;
    let fraud = !unsupported_language && analysis.has_intent(Category::Fraud);
    let valid_confidence = analysis.validate();
    let confidence = if valid_confidence && !unsupported_language {
        analysis.confidence
    } else {
        0.0
    };
    let uncertain = confidence < MIN_CONFIDENCE;
    let degraded = outcome.source == AnalysisSource::Fallback || outcome.degraded_reason.is_some();
    let invalid_ticket = ticket.validate().is_err();
    let category = if unsupported_language {
        Category::Other
    } else if fraud {
        Category::Fraud
    } else {
        analysis.category
    };
    let severity = if fraud {
        Severity::Urgent
    } else if injection_detected && !matches!(analysis.severity, Severity::High | Severity::Urgent)
    {
        Severity::High
    } else {
        analysis.severity
    };

    // Safety gates apply even if an adversarial classifier returns high
    // confidence and asks to approve a refund for the injected instructions.
    let refund = if fraud {
        review("suspected_fraud_requires_review")
    } else if unsupported_language {
        review("unsupported_language_requires_review")
    } else if injection_detected {
        review("untrusted_instructions_require_review")
    } else if invalid_ticket {
        review("invalid_ticket_requires_review")
    } else if degraded {
        review("analysis_unavailable_requires_review")
    } else if uncertain {
        review("low_confidence_requires_review")
    } else if analysis.refund_requested {
        if analysis.has_intent(Category::BillingRefund) {
            evaluate_refund(ticket, analysis.details.refund_target)
        } else {
            review("refund_context_requires_review")
        }
    } else if analysis.has_intent(Category::BillingRefund) {
        review("refund_intent_ambiguous")
    } else {
        Refund {
            decision: RefundDecision::NotRequested,
            amount_inr: 0,
            purchase_id: None,
            reason: "no_explicit_refund_request".into(),
        }
    };

    let reply_plan = crate::reply::ReplyPlan::build(
        ticket,
        outcome,
        &refund,
        category,
        severity,
        injection_detected,
    );
    let needs_human = matches!(refund.decision, RefundDecision::ReviewRequired)
        || unsupported_language
        || reply_plan.requires_human()
        || matches!(severity, Severity::High | Severity::Urgent);
    let reply_draft = reply_plan.render();

    TriageResult {
        ticket_id: ticket.id.clone(),
        category,
        severity,
        refund,
        reply_draft,
        needs_human,
        confidence,
        safety: Safety { injection_detected },
        meta: ResultMeta {
            source: outcome.source,
            model_attempts: outcome.attempts,
            degraded_reason: outcome.degraded_reason.clone(),
            policy_version: POLICY_VERSION.into(),
            usage: outcome.usage.clone(),
            analysis_cached: outcome.cached,
            // Match the supported language of the request. Unsupported-language
            // clarification remains in English rather than inventing a translation.
            language: Some(if unsupported_language {
                Language::English
            } else {
                analysis.language
            }),
        },
    }
}

/// Called inside the persistence transaction when another ticket has already
/// reserved the same purchase. This result authorizes zero additional money.
pub fn mark_already_recorded(result: &mut TriageResult) {
    let language = result.meta.language.unwrap_or_else(|| {
        if result.reply_draft.starts_with("Aapka") {
            Language::Hinglish
        } else {
            Language::English
        }
    });
    let reply = crate::reply::replace_approval_with_recorded(
        &result.reply_draft,
        language,
        result.refund.amount_inr,
    );
    result.refund.decision = RefundDecision::AlreadyRecorded;
    result.refund.amount_inr = 0;
    result.refund.reason = "approval_already_recorded_for_purchase".into();
    result.needs_human = true;
    result.reply_draft = reply;
    result.meta.language = Some(language);
}

fn settled(status: PurchaseStatus) -> bool {
    matches!(status, PurchaseStatus::Successful | PurchaseStatus::Renewal)
}

fn review(reason: &str) -> Refund {
    Refund {
        decision: RefundDecision::ReviewRequired,
        amount_inr: 0,
        purchase_id: None,
        reason: reason.into(),
    }
}

fn evaluate_refund(ticket: &Ticket, target: RefundTarget) -> Refund {
    match target {
        RefundTarget::Trial => {
            return Refund {
                decision: RefundDecision::NotEligible,
                amount_inr: 0,
                purchase_id: None,
                reason: "trial_payments_non_refundable".into(),
            };
        }
        // Never silently substitute the newest subscription for another charge.
        // A target is a bounded interpretation of the request, not authority:
        // even LatestRenewal must pass every trusted-record check below.
        RefundTarget::Unspecified | RefundTarget::AllPayments | RefundTarget::OtherPayment => {
            return review("refund_target_requires_review");
        }
        RefundTarget::LatestRenewal => {}
    }
    let renewals: Vec<_> = ticket
        .purchases
        .iter()
        .filter(|p| p.kind == PurchaseKind::Renewal)
        .collect();
    // Choose the latest *attempt*, not just the latest successful payment.
    // Usage is reported since the latest renewal and cannot safely be attached
    // to an older successful payment after a newer failed/initiated attempt.
    let Some(latest) = renewals.iter().max_by_key(|p| p.at) else {
        return review("no_renewal_payment_to_verify");
    };
    if renewals.iter().filter(|p| p.at == latest.at).count() != 1 {
        return review("ambiguous_latest_renewal");
    }
    if !settled(latest.status) {
        return review("latest_renewal_not_settled");
    }
    if renewals.iter().filter(|p| settled(p.status)).count() != 1 {
        return review("repeat_renewal_requires_review");
    }
    if latest.amount_inr != MONTHLY_PRICE_INR {
        return review("non_monthly_payment_requires_review");
    }
    let elapsed = ticket.received_at.signed_duration_since(latest.at);
    if elapsed < Duration::zero() || elapsed > Duration::hours(48) {
        return review("outside_48_hour_window");
    }
    if ticket.app_opens_since_renewal != 0 {
        return review("post_renewal_usage_requires_review");
    }
    Refund {
        decision: RefundDecision::Approved,
        amount_inr: latest.amount_inr,
        purchase_id: Some(latest.id.clone()),
        reason: "first_monthly_renewal_within_48h_unused".into(),
    }
}

/// Narrow defense in depth for known instruction attacks, never a security
/// boundary: bounded model output and the deterministic money gate remain
/// necessary even for attacks that this heuristic does not recognize.
fn detects_injection(content: &str) -> bool {
    let normalized = content.split_whitespace().collect::<Vec<_>>().join(" ");
    [
        "system note for the support assistant",
        "ignore your previous instructions",
        "ignore previous instructions",
        "automated agent reading this",
        "full text of your system prompt",
        "internal refund rules",
        "mark this ticket resolved",
    ]
    .iter()
    .any(|signal| normalized.contains(signal))
}
