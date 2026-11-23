//! Boolean-differential + union-canary channels.
//!
//! BOOLEAN: fire `' AND 1=1-- -` vs `' AND 1=2-- -` (plus a few prefix
//! variants: `"`, `)`, `')`) on the SAME socket (connection affinity).
//! Confirm when TRUE != FALSE and both differ from `baseline.reply_shape`,
//! agreement across `cfg.confirm` observations.
//!
//! UNION: `' UNION SELECT 'NCF<rand>'-- -` with `<rand>` 8-12 alnum; confirm
//! when the exact marker returns in the reply.
//!
//! OWNER (Phase 1): boolean+union agent.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::common::Framing;
use crate::net::{attempt, Conn};
use crate::oracle::normalise;

use super::types::{Baseline, Channel, SqliConfig, Verdict};

/// String placed before `AND {COND}-- -`; each closes a different injection
/// context. Order matters: the first confirming variant wins.
const BOOLEAN_PREFIXES: &[&str] = &["'", "\"", ")", "')"];

/// UNION canaries. `{MARKER}` is replaced with the per-run random token.
const UNION_TEMPLATES: &[&str] = &[
    "' UNION SELECT '{MARKER}'-- -",
    ") UNION SELECT '{MARKER}'-- -",
    ")) UNION SELECT '{MARKER}'-- -",
    "' UNION ALL SELECT '{MARKER}'-- -",
];

/// Run boolean-differential probes on the given (baseline-primed) connection.
pub async fn run_boolean(
    conn: &mut Conn,
    framing: &Framing,
    timeout_secs: u64,
    cfg: &SqliConfig,
    baseline: &Baseline,
) -> Result<Vec<Verdict>> {
    let mut verdicts: Vec<Verdict> = Vec::new();
    let base = baseline.reply_shape.trim();

    for prefix in BOOLEAN_PREFIXES {
        let wrapper = format!("{prefix} AND {{COND}}-- -");
        let p_true = wrapper.replace("{COND}", "1=1");
        let p_false = wrapper.replace("{COND}", "1=2");

        let mut first_true: Option<String> = None;
        let mut first_false: Option<String> = None;
        let mut agreed = true;

        for _ in 0..cfg.confirm {
            // shortcut: reconnect would need host/port, which this signature
            // doesn't carry; one broken socket ends the boolean run.
            let Ok((t_norm, f_norm)) =
                fire_pair(conn, framing, &p_true, &p_false, timeout_secs).await
            else {
                return Ok(verdicts);
            };

            if t_norm == f_norm || t_norm.trim() == base || f_norm.trim() == base {
                agreed = false;
                break;
            }
            match (&first_true, &first_false) {
                (None, None) => {
                    first_true = Some(t_norm);
                    first_false = Some(f_norm);
                }
                (Some(t0), Some(f0)) => {
                    if t0 != &t_norm || f0 != &f_norm {
                        agreed = false;
                        break;
                    }
                }
                _ => unreachable!(),
            }
        }

        if agreed {
            if let (Some(t_sample), Some(f_sample)) = (first_true, first_false) {
                let proof = format!(
                    "{prefix} AND 1=1 vs {prefix} AND 1=2 (replies differed, {n}/{n}); true={t} false={f}",
                    prefix = prefix,
                    n = cfg.confirm,
                    t = short80(&t_sample),
                    f = short80(&f_sample),
                );
                verdicts.push(Verdict {
                    channel: Channel::Boolean,
                    wrapper: Some(wrapper),
                    payload: framing.send_template.replace("FUZZ", &p_true),
                    proof,
                    engine: None,
                    allows: vec![],
                });
                return Ok(verdicts);
            }
        }
    }

    Ok(verdicts)
}

/// Fire the UNION canary. `conn` can be fresh or the baseline one.
pub async fn run_union(
    conn: &mut Conn,
    framing: &Framing,
    timeout_secs: u64,
    cfg: &SqliConfig,
    _baseline: &Baseline,
) -> Result<Vec<Verdict>> {
    let marker = generate_marker();
    let mut verdicts: Vec<Verdict> = Vec::new();

    for template in UNION_TEMPLATES {
        let payload = template.replace("{MARKER}", &marker);
        let wrapper = payload.clone();
        let mut hit_all = true;

        for _ in 0..cfg.confirm {
            let sent = framing.send_template.replace("FUZZ", &payload);
            // Marker reflection is a raw-byte signal; normalising would just
            // trim, which doesn't matter for `contains`, so skip it.
            let Ok(raw) = attempt(conn, framing, &sent, timeout_secs).await else {
                hit_all = false;
                break;
            };
            if !raw.contains(&marker) {
                hit_all = false;
                break;
            }
        }

        if hit_all {
            verdicts.push(Verdict {
                channel: Channel::Union,
                wrapper: Some(wrapper),
                payload: framing.send_template.replace("FUZZ", &payload),
                proof: format!("marker \"{marker}\" reflected"),
                engine: None,
                allows: vec![],
            });
            return Ok(verdicts);
        }
    }

    Ok(verdicts)
}

/// Classify a raw wordlist-line reply: does any quoted literal in `payload`
/// surface in `reply`? Returns the longest matching literal of length >= 4,
/// else None. Pairs adjacent `'` (and `"`) rather than using a regex, so a
/// payload like `' UNION SELECT 'NCF...'-- -` exposes both ` UNION SELECT `
/// and `NCF...` as candidates, not only the greedy outer pair.
pub fn union_marker_reflected(payload: &str, reply: &str) -> Option<String> {
    let mut best: Option<&str> = None;
    for &quote in &['\'', '"'] {
        let positions: Vec<usize> = payload.match_indices(quote).map(|(i, _)| i).collect();
        for pair in positions.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            let s = &payload[a + quote.len_utf8()..b];
            if s.len() < 4 {
                continue;
            }
            if reply.contains(s) && best.is_none_or(|x| s.len() > x.len()) {
                best = Some(s);
            }
        }
    }
    best.map(str::to_string)
}

/// True iff the trimmed reply differs from the trimmed baseline shape.
/// The baseline is already normalised, so a plain compare is enough.
pub fn boolean_shape_diverged(reply: &str, baseline: &Baseline) -> bool {
    reply.trim() != baseline.reply_shape.trim()
}

async fn fire_pair(
    conn: &mut Conn,
    framing: &Framing,
    p_true: &str,
    p_false: &str,
    timeout_secs: u64,
) -> Result<(String, String)> {
    let sent_true = framing.send_template.replace("FUZZ", p_true);
    let raw_true = attempt(conn, framing, &sent_true, timeout_secs).await?;
    let n_true = normalise(&raw_true, framing, &sent_true);

    let sent_false = framing.send_template.replace("FUZZ", p_false);
    let raw_false = attempt(conn, framing, &sent_false, timeout_secs).await?;
    let n_false = normalise(&raw_false, framing, &sent_false);

    Ok((n_true, n_false))
}

/// Debug-escaped preview, cut at 80 chars (char boundary, not bytes).
fn short80(s: &str) -> String {
    let max = 80usize;
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{:?}...", &s[..i]),
        None => format!("{:?}", s),
    }
}

/// `NCF` + 8..=12 alnum chars. Seeded from wall-clock nanos via xorshift64 —
/// we need per-run uniqueness, not cryptographic strength.
fn generate_marker() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0xcafe_f00d, |d| d.as_nanos() as u64);
    let mut state = nanos ^ 0xdead_beef_cafe_f00d;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let len = 8 + (next() % 5) as usize; // 8..=12
    let mut s = String::with_capacity(3 + len);
    s.push_str("NCF");
    for _ in 0..len {
        s.push(ALPHA[(next() as usize) % ALPHA.len()] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{BannerSync, Framing};
    use crate::net::connect_and_sync;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    fn test_framing() -> Framing {
        Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: None,
            banner: BannerSync::SkipLines(0),
        }
    }

    fn test_baseline(shape: &str) -> Baseline {
        Baseline {
            reply_shape: shape.into(),
            rtt_mean: Duration::from_millis(0),
            rtt_stddev: Duration::from_millis(0),
            samples: 3,
        }
    }

    #[tokio::test]
    async fn boolean_pair_confirms_on_diverging_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            loop {
                let mut line = String::new();
                let n = r.read_line(&mut line).await.unwrap();
                if n == 0 {
                    break;
                }
                let reply: &[u8] = if line.contains("AND 1=1") {
                    b"rows:alice,bob\n"
                } else if line.contains("AND 1=2") {
                    b"rows:empty\n"
                } else {
                    b"rows:default\n"
                };
                w.write_all(reply).await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let framing = test_framing();
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let baseline = test_baseline("rows:default");
        let cfg = SqliConfig {
            sleep_secs: 0,
            confirm: 2,
        };

        let v = run_boolean(&mut conn, &framing, 5, &cfg, &baseline)
            .await
            .unwrap();
        assert!(!v.is_empty(), "expected at least one boolean verdict");
        assert_eq!(v[0].channel, Channel::Boolean);
        assert!(v[0].proof.contains("1=1"));
        assert!(v[0].proof.contains("1=2"));
        assert!(v[0].wrapper.as_deref().unwrap().contains("{COND}"));
    }

    #[tokio::test]
    async fn union_canary_confirms_on_echo_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            loop {
                let mut line = String::new();
                let n = r.read_line(&mut line).await.unwrap();
                if n == 0 {
                    break;
                }
                // Echo back — the marker inside the payload reflects verbatim.
                w.write_all(line.as_bytes()).await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let framing = test_framing();
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let baseline = test_baseline("unused");
        let cfg = SqliConfig {
            sleep_secs: 0,
            confirm: 2,
        };

        let v = run_union(&mut conn, &framing, 5, &cfg, &baseline)
            .await
            .unwrap();
        assert!(!v.is_empty(), "expected at least one union verdict");
        assert_eq!(v[0].channel, Channel::Union);
        assert!(v[0].proof.contains("NCF"));
        assert!(v[0].proof.starts_with("marker \""));
    }

    #[test]
    fn union_marker_reflected_finds_longest_quoted_literal() {
        let payload = "' UNION SELECT 'NCFabcd1234'-- -";
        let reply = "rows: NCFabcd1234 only";
        let got = union_marker_reflected(payload, reply);
        assert_eq!(got.as_deref(), Some("NCFabcd1234"));

        // No reflection -> None.
        assert!(union_marker_reflected(payload, "rows:empty").is_none());

        // Literal shorter than 4 chars is ignored.
        assert!(union_marker_reflected("SELECT 'ab'", "ab").is_none());

        // Longest wins when several reflect.
        let got2 = union_marker_reflected("'short' and 'longerlit'", "x longerlit x short y");
        assert_eq!(got2.as_deref(), Some("longerlit"));
    }

    #[test]
    fn boolean_shape_diverged_trims_before_compare() {
        let base = test_baseline("rows:default");
        assert!(!boolean_shape_diverged("rows:default", &base));
        assert!(!boolean_shape_diverged("  rows:default  ", &base));
        assert!(boolean_shape_diverged("rows:alice,bob", &base));
    }
}
