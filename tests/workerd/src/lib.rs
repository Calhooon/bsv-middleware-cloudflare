//! The conformance kit of `bsv_middleware_core::store::conformance` over
//! HTTP, against the adapter's `D1PrefixStore` and `D1ClaimStore` on a real
//! D1 binding (`CLAIMS`). `BROKEN` is a D1 binding with no table: the fault
//! switch routes claims there, so a fault is a real D1 error.
//!
//! - `GET /kit?ns=` runs every law of both stores in this isolate.
//! - `GET /kit-wrong?ns=` runs the two concurrent prefix laws against a
//!   store that reads with one statement, awaits, then writes with another.
//! - `POST /claim?prefix=&txid=` is one `D1PrefixStore` claim.
//! - `POST /claim-key?key=` is one `D1ClaimStore` claim.

use std::cell::Cell;

use bsv_middleware_cloudflare::payment_claims::{
    claim_payment_nonce, D1ClaimStore, D1PrefixStore, PAYMENT_CLAIMS_SCHEMA,
};
use bsv_middleware_core::store::conformance::{self, LegacySeeder, Report, Violation};
use bsv_middleware_core::{ClaimStore, PaymentPrefixStore, PrefixClaim, StoreError};
use serde_json::{json, Value};
use worker::{event, Context, D1Database, Env, Request, Response, Result};

/// Routes to the good store, or to the same store over `BROKEN` while on.
struct Switched<T> {
    on: Cell<bool>,
    good: T,
    bad: T,
}

impl<T: PaymentPrefixStore> PaymentPrefixStore for Switched<T> {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> std::result::Result<PrefixClaim, StoreError> {
        if self.on.get() {
            self.bad.claim_prefix(prefix, txid, agent).await
        } else {
            self.good.claim_prefix(prefix, txid, agent).await
        }
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> std::result::Result<(), StoreError> {
        if self.on.get() {
            self.bad.release_prefix(prefix, txid).await
        } else {
            self.good.release_prefix(prefix, txid).await
        }
    }
}

impl<T: ClaimStore> ClaimStore for Switched<T> {
    async fn claim(&self, key: &str, agent: &str) -> std::result::Result<bool, StoreError> {
        if self.on.get() {
            self.bad.claim(key, agent).await
        } else {
            self.good.claim(key, agent).await
        }
    }

    async fn release(&self, key: &str) -> std::result::Result<(), StoreError> {
        if self.on.get() {
            self.bad.release(key).await
        } else {
            self.good.release(key).await
        }
    }
}

/// Reads the binding with one statement, awaits it, then writes with a
/// second statement: a key-value namespace's shape on D1.
struct ReadThenWrite<'a>(&'a D1Database);

fn d1(e: worker::Error) -> StoreError {
    StoreError::new(e.to_string())
}

impl PaymentPrefixStore for ReadThenWrite<'_> {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> std::result::Result<PrefixClaim, StoreError> {
        let row = self
            .0
            .prepare("SELECT txid FROM payment_claims WHERE nonce = ?1")
            .bind(&[prefix.into()])
            .map_err(d1)?
            .first::<Value>(None)
            .await
            .map_err(d1)?;
        match row.as_ref().map(|r| r.get("txid").cloned().unwrap_or(Value::Null)) {
            Some(Value::String(bound)) if bound == txid => Ok(PrefixClaim::SameTransaction),
            Some(Value::String(_)) => Ok(PrefixClaim::OtherTransaction),
            Some(_) => Ok(PrefixClaim::Unknown),
            None => {
                self.0
                    .prepare(
                        "INSERT OR REPLACE INTO payment_claims (nonce, agent, created_at, txid, released) \
                         VALUES (?1, ?2, unixepoch(), ?3, 0)",
                    )
                    .bind(&[prefix.into(), agent.into(), txid.into()])
                    .map_err(d1)?
                    .run()
                    .await
                    .map_err(d1)?;
                Ok(PrefixClaim::Won)
            }
        }
    }

    async fn release_prefix(&self, _prefix: &str, _txid: &str) -> std::result::Result<(), StoreError> {
        Ok(())
    }
}

fn report_json(answer: std::result::Result<Report, Violation>) -> Value {
    match answer {
        Ok(report) => json!({
            "pass": true,
            "checked": report.checked.iter().map(|(law, n)| json!([law, n])).collect::<Vec<_>>(),
            "skipped": report.skipped,
        }),
        Err(v) => violation_json(&v),
    }
}

fn violation_json(v: &Violation) -> Value {
    json!({
        "pass": false,
        "law": v.law,
        "n": v.n,
        "schedule": v.schedule.map(|s| s.to_string()),
        "detail": v.detail,
    })
}

async fn schema(db: &D1Database) -> Result<()> {
    db.prepare(PAYMENT_CLAIMS_SCHEMA).run().await?;
    Ok(())
}

fn param(req: &Request, name: &str) -> Result<String> {
    req.url()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| worker::Error::RustError(format!("missing ?{name}=")))
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let db = env.d1("CLAIMS")?;
    schema(&db).await?;
    let path = req.path();
    match path.as_str() {
        "/kit" => {
            let ns = param(&req, "ns")?;
            let broken = env.d1("BROKEN")?;
            let prefixes = Switched {
                on: Cell::new(false),
                good: D1PrefixStore(&db),
                bad: D1PrefixStore(&broken),
            };
            let switch = |on: bool| prefixes.on.set(on);
            let seed: &LegacySeeder<'_> = &|prefix: String| {
                let db = &db;
                Box::pin(async move {
                    claim_payment_nonce(db, &prefix, "legacy")
                        .await
                        .map(|_| ())
                        .map_err(StoreError::new)
                })
            };
            let prefix = conformance::prefix_store(&prefixes, &ns)
                .fault(&switch)
                .legacy(seed)
                .run()
                .await;
            let claims = Switched {
                on: Cell::new(false),
                good: D1ClaimStore(&db),
                bad: D1ClaimStore(&broken),
            };
            let claim_switch = |on: bool| claims.on.set(on);
            let claim = conformance::claim_store(&claims, &ns)
                .fault(&claim_switch)
                .run()
                .await;
            Response::from_json(&json!({ "prefix": report_json(prefix), "claim": report_json(claim) }))
        }
        "/kit-wrong" => {
            let ns = param(&req, "ns")?;
            let store = ReadThenWrite(&db);
            let mut out = Vec::new();
            for &n in conformance::SIZES {
                for answer in [
                    conformance::prefix_one_transaction(&store, &ns, n).await,
                    conformance::prefix_many_transactions(&store, &ns, n).await,
                ] {
                    out.push(match answer {
                        Ok(()) => json!({ "pass": true, "n": n }),
                        Err(v) => violation_json(&v),
                    });
                }
            }
            Response::from_json(&json!({ "laws": out }))
        }
        "/claim" => {
            let (prefix, txid) = (param(&req, "prefix")?, param(&req, "txid")?);
            let answer = D1PrefixStore(&db).claim_prefix(&prefix, &txid, "kit").await;
            Response::from_json(&match answer {
                Ok(word) => json!({ "word": format!("{word:?}") }),
                Err(e) => json!({ "fault": e.to_string() }),
            })
        }
        "/claim-key" => {
            let key = param(&req, "key")?;
            let answer = D1ClaimStore(&db).claim(&key, "kit").await;
            Response::from_json(&match answer {
                Ok(won) => json!({ "won": won }),
                Err(e) => json!({ "fault": e.to_string() }),
            })
        }
        _ => Response::error("not found", 404),
    }
}
