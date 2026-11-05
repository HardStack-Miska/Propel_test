use crate::{
    domain::{RefundDecision, Ticket, TriageResult, hash_bytes},
    policy,
};
use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};

const RESULTS: TableDefinition<&str, &str> = TableDefinition::new("triage_results_v1");
const REFUNDS: TableDefinition<&str, &str> = TableDefinition::new("refund_approvals_v1");
const REVIEWS: TableDefinition<&str, &str> = TableDefinition::new("triage_reviews_v1");

#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

#[derive(Debug)]
// Results are returned by value, not collected into arrays of mixed variants.
// Boxing would add an allocation to every successful lookup for little benefit.
#[allow(clippy::large_enum_variant)]
pub enum Lookup {
    Missing,
    Found(TriageResult),
    Conflict,
}

#[derive(Serialize, Deserialize)]
struct Record {
    fingerprint: String,
    result: TriageResult,
}

#[derive(Serialize, Deserialize)]
struct ReviewRecord {
    ticket_key: String,
    ticket_fingerprint: String,
    review_key: String,
    request_fingerprint: String,
    original_result_fingerprint: String,
    reason: String,
    recorded_at: String,
    result: TriageResult,
}

#[derive(Serialize)]
struct Approval<'a> {
    ticket_key: &'a str,
    amount_inr: u32,
    policy_version: &'a str,
    recorded_at: String,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).context("open triage database")?;
        let tx = db.begin_write()?;
        {
            tx.open_table(RESULTS)?;
            tx.open_table(REFUNDS)?;
            tx.open_table(REVIEWS)?;
        }
        tx.commit()?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn lookup(&self, ticket: &Ticket) -> Result<Lookup> {
        let key = hash_bytes(ticket.id.as_bytes());
        let tx = self.db.begin_read()?;
        let table = tx.open_table(RESULTS)?;
        match table.get(key.as_str())? {
            Some(value) => decode(value.value(), ticket),
            None => Ok(Lookup::Missing),
        }
    }

    /// Response and unique per-payment approval are committed in one durable transaction.
    /// The boolean is true only for the writer that created the record.
    pub fn complete(&self, ticket: &Ticket, mut result: TriageResult) -> Result<(Lookup, bool)> {
        let key = hash_bytes(ticket.id.as_bytes());
        let tx = self.db.begin_write()?;
        {
            let mut results = tx.open_table(RESULTS)?;
            if let Some(value) = results.get(key.as_str())? {
                return Ok((decode(value.value(), ticket)?, false));
            }
            let mut refunds = tx.open_table(REFUNDS)?;
            record_approval(&mut refunds, &key, &mut result)?;
            let record = serde_json::to_string(&Record {
                fingerprint: ticket.fingerprint(),
                result: result.clone(),
            })?;
            results.insert(key.as_str(), record.as_str())?;
        }
        tx.commit()?;
        Ok((Lookup::Found(result), true))
    }

    /// A review requires the exact original ticket and a globally unique review ID.
    /// Missing means the original exists but this review has not been recorded.
    /// A missing original is an error, so callers can reject it before model work.
    pub fn lookup_review(&self, ticket: &Ticket, review_id: &str, reason: &str) -> Result<Lookup> {
        validate_review(ticket, review_id, reason)?;
        let ticket_key = hash_bytes(ticket.id.as_bytes());
        let review_key = hash_bytes(review_id.as_bytes());
        let tx = self.db.begin_read()?;
        let results = tx.open_table(RESULTS)?;
        let original = results
            .get(ticket_key.as_str())?
            .context("original_ticket_missing")?;
        if matches!(decode(original.value(), ticket)?, Lookup::Conflict) {
            return Ok(Lookup::Conflict);
        }
        let reviews = tx.open_table(REVIEWS)?;
        match reviews.get(review_key.as_str())? {
            Some(value) => decode_review(value.value(), ticket, review_id, reason),
            None => Ok(Lookup::Missing),
        }
    }

    /// Append an immutable review and reserve any approval in the same transaction.
    /// Original responses are never replaced, and all reviews share the original
    /// per-payment ledger. Reusing a review ID never applies a new model result.
    pub fn review(
        &self,
        ticket: &Ticket,
        mut result: TriageResult,
        review_id: &str,
        reason: &str,
    ) -> Result<(Lookup, bool)> {
        validate_review(ticket, review_id, reason)?;
        let ticket_key = hash_bytes(ticket.id.as_bytes());
        let review_key = hash_bytes(review_id.as_bytes());
        let tx = self.db.begin_write()?;
        {
            let (original, original_result_fingerprint): (Record, String) = {
                let results = tx.open_table(RESULTS)?;
                let value = results
                    .get(ticket_key.as_str())?
                    .context("original_ticket_missing")?;
                // Hash the canonical stored JSON before typed defaults can add
                // newer metadata fields to a record from an older application.
                let stored: serde_json::Value = serde_json::from_str(value.value())?;
                (
                    serde_json::from_str(value.value())?,
                    hash_bytes(&serde_json::to_vec(&stored["result"])?),
                )
            };
            if original.fingerprint != ticket.fingerprint() {
                return Ok((Lookup::Conflict, false));
            }
            let mut reviews = tx.open_table(REVIEWS)?;
            if let Some(value) = reviews.get(review_key.as_str())? {
                return Ok((
                    decode_review(value.value(), ticket, review_id, reason)?,
                    false,
                ));
            }
            anyhow::ensure!(
                result.ticket_id == ticket.id,
                "review_result_ticket_mismatch"
            );
            let mut refunds = tx.open_table(REFUNDS)?;
            record_approval(&mut refunds, &ticket_key, &mut result)?;
            let record = serde_json::to_string(&ReviewRecord {
                ticket_key,
                ticket_fingerprint: ticket.fingerprint(),
                review_key: review_key.clone(),
                request_fingerprint: review_fingerprint(ticket, reason)?,
                original_result_fingerprint,
                reason: reason.into(),
                recorded_at: chrono::Utc::now().to_rfc3339(),
                result: result.clone(),
            })?;
            reviews.insert(review_key.as_str(), record.as_str())?;
        }
        tx.commit()?;
        Ok((Lookup::Found(result), true))
    }
}

fn record_approval(
    refunds: &mut redb::Table<'_, &str, &str>,
    ticket_key: &str,
    result: &mut TriageResult,
) -> Result<()> {
    if result.refund.decision != RefundDecision::Approved {
        return Ok(());
    }
    let purchase = result
        .refund
        .purchase_id
        .as_deref()
        .context("approval requires payment")?;
    let payment_key = hash_bytes(purchase.as_bytes());
    if refunds.get(payment_key.as_str())?.is_some() {
        policy::mark_already_recorded(result);
    } else {
        let approval = serde_json::to_string(&Approval {
            ticket_key,
            amount_inr: result.refund.amount_inr,
            policy_version: &result.meta.policy_version,
            recorded_at: chrono::Utc::now().to_rfc3339(),
        })?;
        refunds.insert(payment_key.as_str(), approval.as_str())?;
    }
    Ok(())
}

fn validate_review(ticket: &Ticket, review_id: &str, reason: &str) -> Result<()> {
    ticket.validate().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        !review_id.trim().is_empty()
            && review_id.len() <= 128
            && !review_id.chars().any(char::is_control),
        "invalid_review_id"
    );
    anyhow::ensure!(
        matches!(
            reason,
            "provider_recovery" | "model_update" | "manual_review"
        ),
        "invalid_review_reason"
    );
    Ok(())
}

fn review_fingerprint(ticket: &Ticket, reason: &str) -> Result<String> {
    Ok(hash_bytes(&serde_json::to_vec(&(
        ticket.fingerprint(),
        reason,
    ))?))
}

fn decode_review(raw: &str, ticket: &Ticket, review_id: &str, reason: &str) -> Result<Lookup> {
    let record: ReviewRecord = serde_json::from_str(raw)?;
    Ok(
        if record.ticket_key == hash_bytes(ticket.id.as_bytes())
            && record.ticket_fingerprint == ticket.fingerprint()
            && record.review_key == hash_bytes(review_id.as_bytes())
            && record.request_fingerprint == review_fingerprint(ticket, reason)?
            && record.reason == reason
        {
            Lookup::Found(record.result)
        } else {
            Lookup::Conflict
        },
    )
}

fn decode(raw: &str, ticket: &Ticket) -> Result<Lookup> {
    let record: Record = serde_json::from_str(raw)?;
    Ok(if record.fingerprint == ticket.fingerprint() {
        Lookup::Found(record.result)
    } else {
        Lookup::Conflict
    })
}
