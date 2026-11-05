//! Deterministic, deliberately narrow refund policy for this assessment.
//!
//! These are explicit implementation assumptions, not a supplied Propel policy.
//! Model output describes intent; only trusted billing fields determine money.

use crate::domain::*;
use chrono::Duration;

pub const POLICY_VERSION: &str = "assumed-dhaba-v1";
const MIN_CONFIDENCE: f64 = 0.85;
const MONTHLY_PRICE_INR: u32 = 249;

pub fn evaluate(ticket: &Ticket, outcome: &AnalysisOutcome) -> TriageResult {
    let analysis = &outcome.analysis;
    let content = format!("{}\n{}", ticket.subject, ticket.body).to_lowercase();
    let injection_detected = detects_injection(&content);
    // This supplementary check protects the supplied fraud example even if the
    // classifier labels it as a billing question. It is not a fraud detector.
    let fraud = analysis.category == Category::Fraud
        || [
            "fraud",
            "never installed",
            "cyber cell",
            "unauthorized card",
            "unauthorised card",
        ]
        .iter()
        .any(|signal| content.contains(signal));
    let valid_confidence =
        analysis.confidence.is_finite() && (0.0..=1.0).contains(&analysis.confidence);
    let confidence = if valid_confidence {
        analysis.confidence
    } else {
        0.0
    };
    let uncertain = confidence < MIN_CONFIDENCE;
    let degraded = outcome.source == AnalysisSource::Fallback || outcome.degraded_reason.is_some();
    let invalid_ticket = ticket.validate().is_err();
    let category = if fraud {
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
    } else if injection_detected {
        review("untrusted_instructions_require_review")
    } else if invalid_ticket {
        review("invalid_ticket_requires_review")
    } else if degraded {
        review("analysis_unavailable_requires_review")
    } else if uncertain {
        review("low_confidence_requires_review")
    } else if analysis.refund_requested {
        if category == Category::BillingRefund {
            evaluate_refund(ticket)
        } else {
            review("refund_context_requires_review")
        }
    } else if category == Category::BillingRefund {
        review("refund_intent_ambiguous")
    } else {
        Refund {
            decision: RefundDecision::NotRequested,
            amount_inr: 0,
            purchase_id: None,
            reason: "no_explicit_refund_request".into(),
        }
    };

    let needs_human = matches!(refund.decision, RefundDecision::ReviewRequired)
        || matches!(
            category,
            Category::Cancellation
                | Category::AccountAccess
                | Category::Invoice
                | Category::ProductQuestion
                | Category::Other
        )
        || (category == Category::BillingStatus
            && ticket.purchases.iter().any(|p| !settled(p.status)))
        || matches!(severity, Severity::High | Severity::Urgent);
    let reply_draft = if fraud {
        fraud_reply(analysis.language)
    } else if uncertain || degraded || invalid_ticket {
        clarification_reply(analysis.language)
    } else if injection_detected {
        injection_reply(analysis.language)
    } else {
        reply(ticket, category, analysis.language, &refund)
    };

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
        },
    }
}

/// Called inside the persistence transaction when another ticket has already
/// reserved the same purchase. This result authorizes zero additional money.
pub fn mark_already_recorded(result: &mut TriageResult) {
    let hinglish = result.reply_draft.starts_with("Aapka");
    result.refund.decision = RefundDecision::AlreadyRecorded;
    result.refund.amount_inr = 0;
    result.refund.reason = "approval_already_recorded_for_purchase".into();
    result.needs_human = true;
    result.reply_draft = if hinglish {
        "Aapka is payment ka refund approval pehle se recorded hai. Support agent ko payment processing ka status verify karna hoga."
    } else {
        "A refund approval for this payment is already recorded. A support agent needs to verify payment processing."
    }.into();
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

fn evaluate_refund(ticket: &Ticket) -> Refund {
    let renewals: Vec<_> = ticket
        .purchases
        .iter()
        .filter(|p| p.kind == PurchaseKind::Renewal)
        .collect();
    // Choose the latest *attempt*, not just the latest successful payment.
    // Usage is reported since the latest renewal and cannot safely be attached
    // to an older successful payment after a newer failed/initiated attempt.
    let Some(latest) = renewals.iter().max_by_key(|p| p.at) else {
        if !ticket.purchases.is_empty()
            && ticket
                .purchases
                .iter()
                .all(|p| p.kind == PurchaseKind::Trial)
        {
            return Refund {
                decision: RefundDecision::NotEligible,
                amount_inr: 0,
                purchase_id: None,
                reason: "trial_payments_non_refundable".into(),
            };
        }
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

fn clarification_reply(language: Language) -> String {
    match language {
        Language::English => "Please clarify what you need help with and share the relevant payment reference or error details. A support agent needs to review this request before any account or billing action can be confirmed.",
        Language::Hinglish => "Aapko kis cheez mein help chahiye? Relevant payment reference ya error details share karein. Account ya billing action confirm karne se pehle support agent ko request review karni hogi.",
    }.into()
}

fn fraud_reply(language: Language) -> String {
    match language {
        Language::English => "I am sorry these charges have caused concern for your family. This needs urgent human review as a possible unauthorized-payment case. Please contact your bank promptly about charges you do not recognize, and share payment dates and references with support, with sensitive details hidden. No refund or cancellation is confirmed by this reply.",
        Language::Hinglish => "Aapke parivaar ko in charges se pareshani hui, iska afsos hai. Possible unauthorized payment ke liye urgent human review zaroori hai. Jin charges ko aap nahi pehchante unke liye bank se jaldi contact karein; payment dates aur references support ko sensitive details hide karke bhejein. Is reply se refund ya cancellation confirm nahi hota.",
    }.into()
}

fn injection_reply(language: Language) -> String {
    match language {
        Language::English => "A support agent needs to review your original account or product question. Please share the relevant account issue or feature question. This reply does not confirm any refund, account restoration, or ticket resolution.",
        Language::Hinglish => "Aapke original account ya product question ko support agent ko review karna hoga. Relevant account problem ya feature question share karein. Is reply se refund, account restore ya ticket resolution confirm nahi hota.",
    }.into()
}

fn reply(ticket: &Ticket, category: Category, language: Language, refund: &Refund) -> String {
    if refund.decision == RefundDecision::Approved {
        return match language {
            Language::English => format!(
                "Your Rs {} refund request is approved. Payment processing still needs confirmation; this reply does not confirm that the money has been returned.",
                refund.amount_inr
            ),
            Language::Hinglish => format!(
                "Aapka Rs {} refund request approved hai. Payment processing abhi confirm honi baaki hai; is reply se paisa wapas aane ka confirmation nahi hota.",
                refund.amount_inr
            ),
        };
    }
    if refund.decision == RefundDecision::NotEligible {
        return match language {
            Language::English => "Trial payments are not refundable under this policy. If you mean a different charge, please share its payment reference for review.",
            Language::Hinglish => "Trial payment is policy ke hisaab se refundable nahi hai. Agar aap kisi aur charge ki baat kar rahe hain, review ke liye uska payment reference share karein.",
        }.into();
    }
    if refund.decision == RefundDecision::ReviewRequired {
        return match language {
            Language::English if category == Category::Technical => "I am sorry the app is not working for you. Your refund request needs human review; no refund decision is final yet. Please share your device, app version, and what happens when the problem occurs so support can investigate both the technical issue and refund request.",
            Language::Hinglish if category == Category::Technical => "App kaam nahi kar raha, iska afsos hai. Aapka refund request human review maangta hai; final refund decision abhi nahi hua hai. Device, app version aur error details share karein taaki support technical problem aur refund request dono investigate kar sake.",
            Language::English => "Your refund request needs human review of the payment history and circumstances. This is not a final refusal or a confirmation that a refund has been issued. Please share the payment reference and clarify which charge you want reviewed.",
            Language::Hinglish => "Aapka refund request payment history aur situation ke human review ke liye hai. Yeh final mana karna ya refund issue hone ka confirmation nahi hai. Payment reference aur kaunsa charge review karwana hai, share karein.",
        }.into();
    }
    match (category, language) {
        (Category::BillingStatus, language) => billing_reply(ticket, language),
        (Category::Cancellation, Language::English) => "Do you want to stop the next renewal, request a refund, or close your account? A support agent needs to confirm the intended action. Your subscription has not been confirmed cancelled by this reply.".into(),
        (Category::Cancellation, Language::Hinglish) => "Aap next renewal rokna chahte hain, refund maang rahe hain, ya account close karna hai? Support agent ko intended action confirm karna hoga. Is reply se subscription cancellation confirm nahi hoti.".into(),
        (Category::Technical, Language::English) => "I am sorry the app is not working correctly. Please share your app version and the steps that trigger the problem, including any error message. A support agent can use these details to investigate; a fix is not confirmed yet.".into(),
        (Category::Technical, Language::Hinglish) => "App sahi kaam nahi kar raha, iska afsos hai. App version, problem ke steps aur error message share karein. In details se support agent investigate kar sakta hai; fix abhi confirm nahi hai.".into(),
        (Category::AccountAccess, Language::English) => "Please confirm the sign-in method and describe what account data is missing, without sharing passwords or verification codes. A support agent needs to investigate the account link and history; restoration is not confirmed.".into(),
        (Category::AccountAccess, Language::Hinglish) => "Sign-in method aur kaunsa account data missing hai, batayein; password ya verification code share na karein. Support agent ko account link aur history investigate karni hogi; restore hona confirm nahi hai.".into(),
        (Category::FeatureRequest, Language::English) => "Thank you for suggesting this feature. A product team member can review the request. There is no confirmed availability or release date to share.".into(),
        (Category::FeatureRequest, Language::Hinglish) => "Feature suggest karne ke liye shukriya. Product team ka member request review kar sakta hai. Abhi availability ya release date confirm nahi hai.".into(),
        (Category::Invoice, Language::English) => "A support agent needs to verify the payment reference and billing details before an invoice can be provided. Please confirm those details through the support channel. This reply does not include or confirm an issued GST invoice.".into(),
        (Category::Invoice, Language::Hinglish) => "Invoice dene se pehle support agent ko payment reference aur billing details verify karni hongi. Support channel par details confirm karein. Is reply mein issued GST invoice ka confirmation nahi hai.".into(),
        (Category::ProductQuestion, Language::English) => "A support agent needs to verify the current plan features before confirming whether the app supports your use case, including offline access. Please share which feature you want to use.".into(),
        (Category::ProductQuestion, Language::Hinglish) => "Offline access ya kisi feature ko confirm karne se pehle support agent ko current plan details verify karni hongi. Aap kaunsa feature use karna chahte hain, batayein.".into(),
        _ => clarification_reply(language),
    }
}

fn billing_reply(ticket: &Ticket, language: Language) -> String {
    let renewals: Vec<_> = ticket
        .purchases
        .iter()
        .filter(|p| p.kind == PurchaseKind::Renewal)
        .collect();
    let completed = renewals.iter().filter(|p| settled(p.status)).count();
    let amount: u64 = renewals
        .iter()
        .filter(|p| settled(p.status))
        .map(|p| u64::from(p.amount_inr))
        .sum();
    let failed = renewals
        .iter()
        .filter(|p| p.status == PurchaseStatus::Failed)
        .count();
    let initiated = renewals
        .iter()
        .filter(|p| p.status == PurchaseStatus::Initiated)
        .count();
    match language {
        Language::English => format!(
            "Billing records show {completed} completed renewal payment(s), totalling Rs {amount}, {failed} failed renewal attempt(s), and {initiated} initiated renewal attempt(s). These records do not establish the bank's final debit or reversal status. Please share the payment references or a statement with sensitive details hidden so a support agent can reconcile the charge and plan activation."
        ),
        Language::Hinglish => format!(
            "Billing record mein {completed} completed renewal payment(s), total Rs {amount}, {failed} failed renewal attempt(s), aur {initiated} initiated renewal attempt(s) hain. Isse bank ka final debit ya reversal status confirm nahi hota. Sensitive details hide karke payment references ya statement bhejein, taaki support agent charge aur plan activation reconcile kar sake."
        ),
    }
}
