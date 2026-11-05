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

#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

#[derive(Debug)]
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
            if result.refund.decision == RefundDecision::Approved {
                let purchase = result
                    .refund
                    .purchase_id
                    .as_deref()
                    .context("approval requires payment")?;
                let payment_key = hash_bytes(purchase.as_bytes());
                let exists = refunds.get(payment_key.as_str())?.is_some();
                if exists {
                    policy::mark_already_recorded(&mut result);
                } else {
                    let approval = serde_json::to_string(&Approval {
                        ticket_key: &key,
                        amount_inr: result.refund.amount_inr,
                        policy_version: &result.meta.policy_version,
                        recorded_at: chrono::Utc::now().to_rfc3339(),
                    })?;
                    refunds.insert(payment_key.as_str(), approval.as_str())?;
                }
            }
            let record = serde_json::to_string(&Record {
                fingerprint: ticket.fingerprint(),
                result: result.clone(),
            })?;
            results.insert(key.as_str(), record.as_str())?;
        }
        tx.commit()?;
        Ok((Lookup::Found(result), true))
    }
}

fn decode(raw: &str, ticket: &Ticket) -> Result<Lookup> {
    let record: Record = serde_json::from_str(raw)?;
    Ok(if record.fingerprint == ticket.fingerprint() {
        Lookup::Found(record.result)
    } else {
        Lookup::Conflict
    })
}
