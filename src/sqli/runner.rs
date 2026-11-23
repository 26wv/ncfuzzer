//! SQLi-mode entry point. Flow (per spec):
//!   1. Calibrate baseline (one connection, N random probes; records reply
//!      shape + RTT mean/σ).
//!   2. Run built-in probes:
//!      - error triad  → engine id on first match
//!      - boolean pair → connection-affine on the baseline socket
//!      - union canary → fresh connection
//!      - time channel → fallback only, serialised, per dialect
//!
//!      Precedence when multiple fire: error > union > boolean > time.
//!   3. Filter-fingerprint from a known-good wrapper (attached to that
//!      wrapper's verdict).
//!   4. Fire wordlist entries as PAYLOADS and classify by observed effect.
//!   5. Write the report.
//!
//! OWNER: skeleton (Phase 0).

use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::common::Framing;
use crate::wordlist::Wordlist;

use super::baseline;
use super::boolean;
use super::errors as err_ch;
use super::fingerprint;
use super::output;
use super::time as time_ch;
use super::types::{parse_wordlist_payload, Channel, Dialect, SqliConfig, Verdict};

#[derive(Clone, Debug)]
pub struct RunArgs {
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
    pub wordlist: PathBuf,
    pub report: Option<PathBuf>,
    pub json: bool,
    pub verbose: u8,
    pub framing: Framing,
    pub cfg: SqliConfig,
    /// Number of baseline probes.
    pub baseline_samples: u32,
    /// `-z`: also learn a reply-shape baseline and add it as a fifth
    /// ("shape") hit channel alongside the four sqli channels.
    pub zero_knowledge: bool,
}

pub async fn run(args: RunArgs) -> Result<()> {
    if args.cfg.confirm < 1 {
        bail!("--sqli-confirm must be ≥ 1");
    }

    // 1. Baseline calibration.
    let (baseline, mut baseline_conn) = baseline::calibrate(
        &args.host,
        args.port,
        args.timeout_secs,
        &args.framing,
        args.baseline_samples,
    )
    .await?;
    eprintln!(
        "sqli: baseline reply={:?} rtt_mean={:?} rtt_σ={:?} ({} samples)",
        baseline.reply_shape, baseline.rtt_mean, baseline.rtt_stddev, baseline.samples,
    );

    // -z: additional shape baseline. Non-fatal on bail — the 4 sqli channels
    // keep running either way.
    let zk_shape = if args.zero_knowledge {
        match crate::oracle::zk_baseline(&args.host, args.port, args.timeout_secs, &args.framing)
            .await
        {
            Ok(Some(shape)) => Some(shape),
            Ok(None) => {
                eprintln!(
                    "zero-knowledge: service returns inconsistent replies, can't establish a baseline — skipping"
                );
                None
            }
            Err(e) => {
                eprintln!("zero-knowledge: baseline probe failed ({e}); skipping shape channel");
                None
            }
        }
    } else {
        None
    };

    let mut verdicts: Vec<Verdict> = Vec::new();
    let mut engine_hint: Option<Dialect> = None;

    // 2a. Error channel (also fixes engine id).
    let errs = err_ch::run(
        &mut baseline_conn,
        &args.framing,
        args.timeout_secs,
        &args.cfg,
        &baseline,
    )
    .await?;
    for v in &errs {
        if engine_hint.is_none() {
            engine_hint = v.engine;
        }
    }
    verdicts.extend(errs);

    // 2b. Boolean (connection-affine — reuse baseline socket). On confirm,
    // decorate the first boolean verdict with filter-bypass classes.
    let mut bools = boolean::run_boolean(
        &mut baseline_conn,
        &args.framing,
        args.timeout_secs,
        &args.cfg,
        &baseline,
    )
    .await?;
    if let Some(v) = bools.first_mut() {
        if let Some(wrapper) = v.wrapper.clone() {
            let classes = fingerprint::run(
                &mut baseline_conn,
                &args.framing,
                args.timeout_secs,
                &args.cfg,
                &baseline,
                &wrapper,
            )
            .await
            .unwrap_or_default();
            for c in classes {
                if !v.allows.contains(&c) {
                    v.allows.push(c);
                }
            }
        }
    }
    verdicts.extend(bools);

    // 2c. Union canary (can share the socket).
    let unions = boolean::run_union(
        &mut baseline_conn,
        &args.framing,
        args.timeout_secs,
        &args.cfg,
        &baseline,
    )
    .await?;
    verdicts.extend(unions);

    // Engine id is settled by now (only the error channel sets it); reused
    // for the time channel fallback below and the wordlist pass in step 3.
    let dialects: Vec<Dialect> = engine_hint.map_or_else(|| Dialect::all().to_vec(), |d| vec![d]);

    // 2d. Time channel — fallback only (no error/union/boolean fired yet).
    if verdicts.is_empty() {
        let times = time_ch::run(
            &args.host,
            args.port,
            &args.framing,
            args.timeout_secs,
            &args.cfg,
            &baseline,
            &dialects,
        )
        .await?;
        verdicts.extend(times);
    }

    // 3. Wordlist pass — classify by observed effect.
    // sqli can run probes-only if the caller explicitly omits -w; in practice
    // main enforces -w, so the check below is defensive.
    if !args.wordlist.as_os_str().is_empty() {
        let wl = Wordlist::open(&args.wordlist)?;
        while let Some(line) = wl.next() {
            let (payload, class_tag) = parse_wordlist_payload(&line);

            if payload.contains("{SLEEP}") {
                let hits = time_ch::fire_wordlist_sleep(
                    &args.host,
                    args.port,
                    &args.framing,
                    args.timeout_secs,
                    &args.cfg,
                    &baseline,
                    &dialects,
                    &payload,
                )
                .await?;
                for mut v in hits {
                    if let Some(c) = class_tag {
                        if !v.allows.contains(&c) {
                            v.allows.push(c);
                        }
                    }
                    verdicts.push(v);
                }
                continue;
            }

            // Non-{SLEEP} wordlist line: fire raw on a fresh connection, judge
            // reply by error-signature / marker-reflection / baseline-diff.
            let mut fresh = crate::net::connect_and_sync(
                &args.host,
                args.port,
                args.timeout_secs,
                &args.framing,
            )
            .await?;
            let templated = args.framing.send_template.replace("FUZZ", &payload);
            let Ok(raw) =
                crate::net::attempt(&mut fresh, &args.framing, &templated, args.timeout_secs).await
            else {
                continue; // socket drop or oracle crash — skip this line
            };
            let normalised = crate::oracle::normalise(&raw, &args.framing, &templated);

            let channel = if let Some(d) = err_ch::classify_reply(&normalised) {
                // engine-id upgrade for free
                if engine_hint.is_none() {
                    engine_hint = Some(d);
                }
                Some((Channel::Error, Some(d)))
            } else if let Some(_marker) = boolean::union_marker_reflected(&payload, &normalised) {
                Some((Channel::Union, None))
            } else if boolean::boolean_shape_diverged(&normalised, &baseline) {
                Some((Channel::Raw, None))
            } else {
                None
            };

            // -z: additional hit signal, independent of the 4 channels above.
            if let Some(shape) = &zk_shape {
                if crate::oracle::shape_signature(&normalised) != *shape {
                    verdicts.push(Verdict {
                        channel: Channel::Shape,
                        wrapper: None,
                        payload: templated.clone(),
                        proof: short_proof(&normalised),
                        engine: None,
                        allows: class_tag.into_iter().collect(),
                    });
                }
            }

            if let Some((ch, engine)) = channel {
                verdicts.push(Verdict {
                    channel: ch,
                    wrapper: None,
                    payload: templated,
                    proof: short_proof(&normalised),
                    engine,
                    allows: class_tag.into_iter().collect(),
                });
            }
        }
    }

    // Warn on no sleep-token case — user set -S but no wordlist line uses it.
    if args.cfg.sleep_secs != 0
        && verdicts.iter().all(|v| v.channel != Channel::Time)
        && !any_sleep_token_fired(&args.wordlist)
    {
        eprintln!(
            "sqli: note — --sqli-sleep set but no `{{SLEEP}}` token fired (built-in time probes skipped because another channel confirmed, and no wordlist line contained the token)"
        );
    }

    output::write(&verdicts, args.report.as_deref(), args.json, args.verbose).await?;
    Ok(())
}

fn short_proof(normalised: &str) -> String {
    let max = 120usize;
    if normalised.chars().count() <= max {
        format!("reply differed from baseline: {normalised:?}")
    } else {
        let trimmed: String = normalised.chars().take(max).collect();
        format!("reply differed from baseline: {trimmed:?}…")
    }
}

/// Re-opens the wordlist (the main-loop `Wordlist` is already exhausted by
/// the time this runs) and checks whether any line's payload contains the
/// literal `{SLEEP}` token — mirrors the gate at the main loop's `{SLEEP}` check.
fn any_sleep_token_fired(wordlist_path: &std::path::Path) -> bool {
    let Ok(wl) = Wordlist::open(wordlist_path) else {
        return false;
    };
    while let Some(line) = wl.next() {
        if parse_wordlist_payload(&line).0.contains("{SLEEP}") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_proof_handles_multibyte_at_boundary() {
        // Long utf-8 reply whose byte-120 lands inside a multi-byte char.
        // Byte-indexed truncation would panic; char-indexed must not.
        let s: String = std::iter::repeat_n('é', 200).collect();
        let _ = short_proof(&s);
    }

    fn wordlist_file(contents: &str) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), contents).unwrap();
        f
    }

    #[test]
    fn any_sleep_token_fired_true_when_line_has_token() {
        let f = wordlist_file("' OR 1=1\n'; SELECT {SLEEP}--\nadmin\n");
        assert!(any_sleep_token_fired(f.path()));
    }

    #[test]
    fn any_sleep_token_fired_false_when_no_line_has_token() {
        let f = wordlist_file("' OR 1=1\nadmin\n' AND 'x'='x\n");
        assert!(!any_sleep_token_fired(f.path()));
    }
}
