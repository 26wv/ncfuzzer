use crate::common::Framing;
use anyhow::{anyhow, bail, Result};
use regex::Regex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub enum Positive {
    /// Hit iff normalised response != miss baseline.
    MissEquals(String),
    /// Hit iff normalised response contains the substring.
    Contains(String),
    /// Hit iff the regex matches the normalised response.
    Regex(Regex),
    /// Zero-knowledge mode: hit iff the response's shape differs from the
    /// learned baseline shape.
    ShapeDiffers(Shape),
}

#[derive(Clone, Debug)]
pub enum Filter {
    Contains(String),
    Regex(Regex),
}

#[derive(Clone, Debug)]
pub struct Matcher {
    pub positive: Positive,
    pub filters: Vec<Filter>,
}

impl Matcher {
    /// Hit iff positive matches AND no filter matches.
    pub fn is_hit(&self, normalised: &str) -> bool {
        let positive = match &self.positive {
            Positive::MissEquals(m) => normalised != m,
            Positive::Contains(s) => normalised.contains(s),
            Positive::Regex(r) => r.is_match(normalised),
            Positive::ShapeDiffers(baseline) => shape_signature(normalised) != *baseline,
        };
        if !positive {
            return false;
        }
        !self.filters.iter().any(|f| filter_matches(f, normalised))
    }
}

fn filter_matches(f: &Filter, s: &str) -> bool {
    match f {
        Filter::Contains(sub) => s.contains(sub),
        Filter::Regex(r) => r.is_match(s),
    }
}

/// Strip the echoed payload prefix (if the server echoes the request back at
/// the start of its reply) and trailing whitespace. The ready-prompt is
/// already cut off by `read_until` in `src/net.rs` via `truncate`, so the
/// response never starts with the prompt and no prompt-prefix strip is needed.
pub fn normalise(response: &str, _framing: &Framing, payload: &str) -> String {
    let mut s = response;
    if let Some(rest) = s.strip_prefix(payload) {
        s = rest;
    }
    s.trim_end().to_string()
}

/// Send `samples` high-entropy probes through one connection; return a
/// `Matcher` whose `Positive::MissEquals` holds the baseline response.
/// If the probes disagree, return Err with a clear message instructing the
/// user to set an explicit matcher.
///
/// Limitation: probes share a single connection, so per-connection state
/// (lockouts, per-session nonces, sticky server-side counters) can let probes
/// agree while the live multi-connection run diverges. If the run still
/// misclassifies afterwards, pin the matcher explicitly with `-m/--miss` or
/// `-M/--match`.
pub async fn calibrate(
    host: &str,
    port: u16,
    timeout_secs: u64,
    framing: &Framing,
    samples: u32,
    filters: Vec<Filter>,
) -> Result<Matcher> {
    use crate::net::{attempt, connect_and_sync};

    if samples < 2 {
        bail!("auto-calibrate needs at least 2 samples, got {samples}");
    }

    let mut conn = connect_and_sync(host, port, timeout_secs, framing).await?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());

    let mut baseline: Option<String> = None;
    for i in 0..samples {
        let probe = format!("ncfuzzer_probe_{i:x}_{nanos:x}");
        let templated = framing.send_template.replace("FUZZ", &probe);
        let raw = attempt(&mut conn, framing, &templated, timeout_secs).await?;
        let residue = conn.0.buffer();
        if !residue.is_empty() {
            let residue_len = residue.len();
            let residue_preview = &residue[..residue_len.min(80)];
            return Err(anyhow!(
                "auto-calibration: server left {residue_len} unread bytes after probe ({residue:?}); the server likely emits multiple lines per request — pass `-P PATTERN` to use prompt-bounded framing, or `-b N` / `-b REGEX` to consume more banner lines.",
                residue = residue_preview,
            ));
        }
        let n = normalise(&raw, framing, &templated);
        match &baseline {
            None => baseline = Some(n),
            Some(first) if first != &n => {
                return Err(anyhow!(
                    "auto-calibration failed: probes gave different responses ({first:?} vs {n:?}); pass one of `--miss` / `--match` (use the `re:` prefix for a regex) and rerun"
                ));
            }
            _ => {}
        }
    }

    let baseline = baseline.ok_or_else(|| anyhow!("auto-calibrate produced no samples"))?;
    eprintln!(
        "auto-calibrate: miss baseline = {:?} ({} samples agreed)",
        baseline, samples
    );
    Ok(Matcher {
        positive: Positive::MissEquals(baseline),
        filters,
    })
}

/// Zero-knowledge "shape" signature: line count, compact label-token set, and
/// a power-of-two byte-length bucket. Two replies with equal shapes are
/// considered indistinguishable; the raw content is never compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    pub lines: usize,
    pub tokens: Vec<String>,
    pub bucket: u32,
}

/// Fixed, compact vocabulary of UI/prompt labels — keeps the token set from
/// picking up arbitrary echoed/attacker-controlled capitalised words.
const LABEL_VOCAB: &[&str] = &[
    "Login", "Password", "Username", "Menu", "Option", "Choice", "Select", "Welcome", "Error",
    "Failed", "Invalid", "Success",
];

fn is_label_token(tok: &str) -> bool {
    fn cap_word_regex() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| Regex::new(r"^[A-Z][A-Za-z]{2,}$").unwrap())
    }
    tok.ends_with(':') || LABEL_VOCAB.contains(&tok) || cap_word_regex().is_match(tok)
}

/// Compute the shape signature of one (already-normalised) reply.
pub fn shape_signature(reply: &str) -> Shape {
    let lines = reply.matches('\n').count();
    let bucket = (reply.len().max(1) as f64).log2().floor() as u32;
    let mut tokens: Vec<String> = reply
        .split_whitespace()
        .filter(|t| is_label_token(t))
        .map(|t| t.to_string())
        .collect();
    tokens.sort();
    tokens.dedup();
    Shape {
        lines,
        tokens,
        bucket,
    }
}

/// Tiny xorshift64 PRNG — plenty for "random-looking" baseline probes,
/// no RNG dependency needed for a handful of 8-16 char alnum strings.
fn next_rand(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn random_alnum(state: &mut u64, min_len: usize, max_len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let span = (max_len - min_len + 1) as u64;
    let len = min_len + (next_rand(state) % span) as usize;
    (0..len)
        .map(|_| CHARS[(next_rand(state) % CHARS.len() as u64) as usize] as char)
        .collect()
}

/// If every shape in `shapes` is equal, return that shape.
fn shapes_agree(shapes: &[Shape]) -> Option<Shape> {
    let first = shapes.first()?.clone();
    shapes.iter().all(|s| *s == first).then_some(first)
}

/// Zero-knowledge baseline learner (`-z`). Sends 3 random probes over one
/// connection; if their shapes agree, that's the baseline. Otherwise sends
/// another 3 probes; if those also disagree, returns `Ok(None)` (bail — the
/// caller prints the user-facing message and decides whether to keep going).
pub async fn zk_baseline(
    host: &str,
    port: u16,
    timeout_secs: u64,
    framing: &Framing,
) -> Result<Option<Shape>> {
    use crate::net::{attempt, connect_and_sync};

    let mut conn = connect_and_sync(host, port, timeout_secs, framing).await?;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |d| d.as_nanos() as u64)
        | 1;

    for _ in 0..2 {
        let mut shapes = Vec::with_capacity(3);
        for _ in 0..3 {
            let probe = random_alnum(&mut seed, 8, 16);
            let templated = framing.send_template.replace("FUZZ", &probe);
            let raw = attempt(&mut conn, framing, &templated, timeout_secs).await?;
            shapes.push(shape_signature(&normalise(&raw, framing, &templated)));
        }
        if let Some(shape) = shapes_agree(&shapes) {
            return Ok(Some(shape));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{BannerSync, Framing, Prompt};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    fn framing_bare() -> Framing {
        Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: None,
            banner: BannerSync::SkipLines(0),
        }
    }
    fn framing_prompt(p: &str) -> Framing {
        Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: Some(Prompt::Literal(p.into())),
            banner: BannerSync::SkipLines(0),
        }
    }

    #[test]
    fn normalise_strips_payload_then_trailing() {
        // `read_until` already truncates the prompt off, so `normalise` only
        // sees the pre-prompt bytes; it must not re-strip the prompt itself.
        let n = normalise("alice: ok\r\n", &framing_prompt("> "), "alice");
        assert_eq!(n, ": ok");
    }
    #[test]
    fn normalise_no_prompt_passes_through() {
        let n = normalise("alice: ok\n", &framing_bare(), "alice");
        assert_eq!(n, ": ok");
    }
    #[test]
    fn is_hit_miss_equals() {
        let m = Matcher {
            positive: Positive::MissEquals("no such entry".into()),
            filters: vec![],
        };
        assert!(!m.is_hit("no such entry"));
        assert!(m.is_hit("ok: abc"));
    }
    #[test]
    fn is_hit_contains_with_filter() {
        let m = Matcher {
            positive: Positive::Contains("ok".into()),
            filters: vec![Filter::Contains("stub".into())],
        };
        assert!(m.is_hit("ok: real"));
        assert!(!m.is_hit("ok: stub_token")); // positive hits, filter vetoes
        assert!(!m.is_hit("nope"));
    }
    #[test]
    fn is_hit_regex_variants() {
        let m = Matcher {
            positive: Positive::Regex(Regex::new(r"^ok:\s+\S+$").unwrap()),
            filters: vec![],
        };
        assert!(m.is_hit("ok: aaa"));
        assert!(!m.is_hit("fail"));
    }

    #[tokio::test]
    async fn calibrate_adopts_baseline_when_probes_agree() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                // Same reply regardless of probe content: probes agree.
                w.write_all(b"no such user\n").await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let matcher = calibrate(
            &addr.ip().to_string(),
            addr.port(),
            5,
            &framing_bare(),
            2,
            vec![],
        )
        .await
        .unwrap();
        match matcher.positive {
            Positive::MissEquals(s) => assert_eq!(s, "no such user"),
            other => panic!("expected MissEquals, got {other:?}"),
        }
        assert!(matcher.filters.is_empty());
    }

    #[tokio::test]
    async fn calibrate_errors_when_probes_disagree() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            let mut n = 0u32;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                // A different reply every time, regardless of probe content.
                let resp = format!("reply:{n}\n");
                n += 1;
                w.write_all(resp.as_bytes()).await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let err = calibrate(
            &addr.ip().to_string(),
            addr.port(),
            5,
            &framing_bare(),
            2,
            vec![],
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--miss") && msg.contains("--match"), "{msg}");
    }

    #[test]
    fn shape_signature_equal_on_equivalent_replies() {
        let a = shape_signature("Welcome\nLogin: ");
        let b = shape_signature("Welcome\nLogin: ");
        assert_eq!(a, b);
    }

    #[test]
    fn shape_signature_differs_on_line_count() {
        let a = shape_signature("ok");
        let b = shape_signature("ok\nok");
        assert_ne!(a, b);
        assert_eq!(a.lines, 0);
        assert_eq!(b.lines, 1);
    }

    #[test]
    fn shape_signature_differs_on_length_bucket() {
        let short = shape_signature("x");
        let long = shape_signature(&"x".repeat(100));
        assert_ne!(short.bucket, long.bucket);
    }

    #[test]
    fn shape_signature_differs_on_token_set() {
        let plain = shape_signature("nope");
        let labelled = shape_signature("Error: Invalid login");
        assert_ne!(plain.tokens, labelled.tokens);
        assert!(labelled.tokens.contains(&"Error:".to_string()));
        assert!(labelled.tokens.contains(&"Invalid".to_string()));
        // lowercase, non-vocab word is not swept in as noise.
        assert!(!labelled.tokens.contains(&"login".to_string()));
    }

    /// Mock server for the baseline-establisher tests: replies are generated
    /// by a closure fed the attempt index (0-based across the whole run).
    fn spawn_shape_server<F>(listener: TcpListener, mut reply_for: F)
    where
        F: FnMut(u32) -> &'static str + Send + 'static,
    {
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            let mut n = 0u32;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let resp = reply_for(n);
                n += 1;
                w.write_all(resp.as_bytes()).await.unwrap();
                w.flush().await.unwrap();
            }
        });
    }

    #[tokio::test]
    async fn zk_baseline_adopts_shape_when_first_three_agree() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_shape_server(listener, |_| "ok\n");

        let shape = zk_baseline(&addr.ip().to_string(), addr.port(), 5, &framing_bare())
            .await
            .unwrap()
            .expect("baseline should be established");
        assert_eq!(shape, shape_signature("ok"));
    }

    #[tokio::test]
    async fn zk_baseline_adopts_shape_after_one_inconsistent_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // First 3 replies all different shapes; last 3 agree on "ok\n".
        spawn_shape_server(listener, |n| match n {
            0 => "a\n",
            1 => "bb\n",
            2 => "ccc\n",
            _ => "ok\n",
        });

        let shape = zk_baseline(&addr.ip().to_string(), addr.port(), 5, &framing_bare())
            .await
            .unwrap()
            .expect("baseline should be established on the second batch");
        assert_eq!(shape, shape_signature("ok"));
    }

    #[tokio::test]
    async fn zk_baseline_bails_when_both_batches_disagree() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Three distinct byte-length buckets, cycling — no 3 consecutive
        // replies ever share a shape.
        spawn_shape_server(listener, |n| match n % 3 {
            0 => "a\n",
            1 => "bb\n",
            _ => "dddd\n",
        });

        let result = zk_baseline(&addr.ip().to_string(), addr.port(), 5, &framing_bare())
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
