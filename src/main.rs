mod common;
mod net;
mod oracle;
mod sqli;
mod ui;
mod wordlist;

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use governor::{Quota, RateLimiter};
use oracle::{Filter, Matcher, Positive};
use regex::Regex;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Configurable TCP line-oracle fuzzer. Authorised use only.
///
/// Pattern convention: for `--match`, `--filter`, and `--prompt`, the argument is a
/// literal substring by default; prefix it with `re:` to make it a regex, or `lit:`
/// to force literal interpretation (needed when your literal would otherwise look
/// like `re:...`). For `--banner`, a decimal integer is a line count, anything
/// else is a regex — to match a regex that is only digits, anchor it (`-b '^42$'`).
#[derive(Parser, Debug)]
#[command(name = "ncfuzzer", version, disable_help_flag = true)]
struct Cli {
    /// Target host (this is HOST, not help — help is `--help`).
    #[arg(short = 'h', long = "host")]
    host: String,
    /// Target port.
    #[arg(short = 'p', long = "port")]
    port: u16,
    /// Wordlist path (one candidate per line).
    #[arg(short = 'w', long = "wordlist")]
    wordlist: PathBuf,
    /// Number of persistent connections.
    #[arg(short = 'c', long = "concurrency", default_value_t = 64)]
    concurrency: usize,
    /// Max attempts/sec across all workers; 0 = unlimited.
    #[arg(short = 'r', long = "rate", default_value_t = 0)]
    rate: u64,
    /// Socket connect+read timeout in seconds (also bounds reconnect).
    #[arg(short = 't', long = "timeout", default_value_t = 5)]
    timeout: u64,
    /// Write a formatted hits report to PATH (plain text). Additive — the
    /// plain hit stream on stdout is unchanged, so `> file` still works.
    /// Report layout: a `HITS:` header followed by one
    /// `entry - printf '...' | nc HOST PORT` line per hit.
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Emit hits as JSON Lines on stdout instead of `word\tresponse`.
    #[arg(short = 'j', long = "json")]
    json: bool,
    /// Verbose stderr output. `-v` prints the reproducible command and
    /// server response for every HIT. `-vv` prints that for every attempt
    /// (hit or miss) — debugging / small wordlists only; enormous on a 10M
    /// list. `-v` never touches stdout or the `-o` file, but in sqli mode
    /// `-vv` also emits the payload into the stdout block and the `-o` report.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    // ---- oracle ----
    /// Explicit miss signature. Any response NOT **exactly equal** to this
    /// (after normalisation: ready-prompt and echoed payload stripped,
    /// trailing whitespace trimmed) is reported as a hit. Supply the error
    /// string exactly as the server returns it.
    #[arg(
        short = 'm',
        long = "miss",
        visible_alias = "invert-match",
        conflicts_with = "match_pat"
    )]
    miss: Option<String>,
    /// Positive hit matcher. Literal substring by default; prefix with
    /// `re:` for a regex (e.g. `-M 're:^ok: \S+$'`) or `lit:` to force
    /// literal when the literal starts with `re:`.
    #[arg(
        short = 'M',
        long = "match",
        value_name = "PATTERN",
        conflicts_with = "miss"
    )]
    match_pat: Option<String>,
    /// Force-miss filter (repeatable). Literal substring by default;
    /// prefix with `re:` for a regex, or `lit:` to force literal.
    #[arg(short = 'F', long = "filter", value_name = "PATTERN")]
    filter: Vec<String>,
    /// Disable startup auto-calibration (then a matcher is required).
    #[arg(short = 'G', long = "no-calibrate")]
    no_calibrate: bool,
    /// Number of probes sent during auto-calibration.
    #[arg(short = 'g', long = "calibrate-samples", default_value_t = 3)]
    calibrate_samples: u32,

    // ---- payload & framing ----
    /// Payload template; `FUZZ` is replaced by each wordlist entry.
    #[arg(short = 'd', long = "send", default_value = "FUZZ")]
    send: String,
    /// Line terminator sent after each payload. Accepts `\r`, `\n`, `\t`.
    #[arg(short = 'e', long = "eol", default_value = "\n")]
    eol: String,
    /// Ready prompt that bounds each response. Literal by default; prefix
    /// with `re:` for a regex, or `lit:` to force literal.
    #[arg(short = 'P', long = "prompt", value_name = "PATTERN")]
    prompt: Option<String>,
    /// Banner sync. A decimal integer is a line count to skip; anything
    /// else is a regex consumed until matched. To match a regex that is
    /// only digits, anchor it (e.g. `-b '^42$'`).
    #[arg(short = 'b', long = "banner", value_name = "N|REGEX")]
    banner: Option<String>,

    // ---- sqli mode ----
    /// Enable SQL-injection scan mode. In this mode `-w` is read as PAYLOADS
    /// (not usernames): built-in probes run first to confirm injectability and
    /// identify the engine, then each wordlist line fires raw and is
    /// classified by observed effect (error / union / boolean / time).
    #[arg(short = 's', long = "sqli")]
    sqli: bool,
    /// Seconds for the `{SLEEP}` token (rendered per dialect: `SLEEP(N)` for
    /// MySQL, `pg_sleep(N)` for PostgreSQL, `WAITFOR DELAY '00:MM:SS'` for MSSQL).
    /// Must be ≥ 1 — a zero delay collapses the time-channel threshold.
    #[arg(
        short = 'S',
        long = "sqli-sleep",
        default_value_t = 5,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    sqli_sleep: u32,
    /// Agreeing observations required before a sqli verdict is reported.
    #[arg(short = 'C', long = "sqli-confirm", default_value_t = 2)]
    sqli_confirm: u32,

    // ---- zero-knowledge mode ----
    /// Zero-knowledge hit detection. Learns a reply "shape" baseline (line
    /// count + compact label-token set + byte-length bucket) from random
    /// probes, with no knowledge of what a hit looks like; any payload whose
    /// reply shape differs from the baseline is reported as a hit. Standalone,
    /// it replaces -m/-M/-G/auto-calibrate. Combined with `-s`, it adds
    /// "shape" as a fifth sqli channel alongside error/union/boolean/time. If
    /// the service's replies are too inconsistent to learn a baseline, prints
    /// a warning and (standalone) skips the run, or (with `-s`) keeps running
    /// on the 4 sqli channels alone.
    #[arg(short = 'z', long = "zero-knowledge")]
    zero_knowledge: bool,

    /// Print this help.
    #[arg(long = "help", action = clap::ArgAction::Help)]
    help: Option<bool>,
}

fn decode_eol(s: &str) -> String {
    s.replace("\\r", "\r")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
}

/// `re:<regex>` → regex, `lit:<literal>` → literal (escape hatch), otherwise literal.
enum RawPattern {
    Regex(Regex),
    Literal(String),
}

fn parse_raw_pattern(p: &str) -> Result<RawPattern> {
    if let Some(r) = p.strip_prefix("re:") {
        return Ok(RawPattern::Regex(Regex::new(r)?));
    }
    let l = p.strip_prefix("lit:").unwrap_or(p);
    Ok(RawPattern::Literal(l.to_string()))
}

fn parse_pattern_positive(p: &str) -> Result<Positive> {
    Ok(match parse_raw_pattern(p)? {
        RawPattern::Regex(r) => Positive::Regex(r),
        RawPattern::Literal(s) => Positive::Contains(s),
    })
}

fn parse_pattern_filter(p: &str) -> Result<Filter> {
    Ok(match parse_raw_pattern(p)? {
        RawPattern::Regex(r) => Filter::Regex(r),
        RawPattern::Literal(s) => Filter::Contains(s),
    })
}

fn parse_prompt(p: &str) -> Result<common::Prompt> {
    Ok(match parse_raw_pattern(p)? {
        RawPattern::Regex(r) => common::Prompt::Regex(r),
        RawPattern::Literal(s) => common::Prompt::Literal(s),
    })
}

/// Pure digits → SkipLines(N); anything else → MatchRegex.
fn parse_banner(b: &str) -> Result<common::BannerSync> {
    match b.parse::<u32>() {
        Ok(n) => Ok(common::BannerSync::SkipLines(n)),
        Err(_) => Ok(common::BannerSync::MatchRegex(Regex::new(b)?)),
    }
}

fn build_framing(cli: &Cli) -> Result<common::Framing> {
    let prompt = cli.prompt.as_deref().map(parse_prompt).transpose()?;
    let banner = match &cli.banner {
        Some(b) => parse_banner(b)?,
        None => common::BannerSync::SkipLines(0),
    };
    if !cli.send.contains("FUZZ") {
        // Silently allow (users may want a fixed payload) — but warn once.
        eprintln!(
            "warning: --send template does not contain FUZZ; every attempt sends the same payload"
        );
    }
    Ok(common::Framing {
        send_template: cli.send.clone(),
        eol: decode_eol(&cli.eol),
        prompt,
        banner,
    })
}

fn build_filters(cli: &Cli) -> Result<Vec<Filter>> {
    cli.filter.iter().map(|p| parse_pattern_filter(p)).collect()
}

async fn build_matcher(
    cli: &Cli,
    framing: &common::Framing,
    filters: Vec<Filter>,
) -> Result<Matcher> {
    if let Some(m) = &cli.miss {
        return Ok(Matcher {
            positive: Positive::MissEquals(m.clone()),
            filters,
        });
    }
    if let Some(p) = &cli.match_pat {
        return Ok(Matcher {
            positive: parse_pattern_positive(p)?,
            filters,
        });
    }
    if cli.no_calibrate {
        bail!("no matcher given and --no-calibrate set; pass one of --miss / --match (use the re: prefix for a regex), or remove --no-calibrate");
    }
    oracle::calibrate(
        &cli.host,
        cli.port,
        cli.timeout,
        framing,
        cli.calibrate_samples,
        filters,
    )
    .await
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let framing = build_framing(&cli)?;

    if cli.sqli {
        return sqli::run(sqli::RunArgs {
            host: cli.host.clone(),
            port: cli.port,
            timeout_secs: cli.timeout,
            wordlist: cli.wordlist.clone(),
            report: cli.output.clone(),
            json: cli.json,
            verbose: cli.verbose,
            framing,
            cfg: sqli::SqliConfig {
                sleep_secs: cli.sqli_sleep,
                confirm: cli.sqli_confirm,
            },
            baseline_samples: cli.calibrate_samples.max(2),
            zero_knowledge: cli.zero_knowledge,
        })
        .await;
    }

    let filters = build_filters(&cli)?;
    let matcher = if cli.zero_knowledge {
        match oracle::zk_baseline(&cli.host, cli.port, cli.timeout, &framing).await? {
            Some(shape) => Arc::new(Matcher {
                positive: Positive::ShapeDiffers(shape),
                filters,
            }),
            None => {
                eprintln!(
                    "zero-knowledge: service returns inconsistent replies, can't establish a baseline — skipping"
                );
                return Ok(());
            }
        }
    } else {
        Arc::new(build_matcher(&cli, &framing, filters).await?)
    };

    let cfg = common::Config {
        host: cli.host.clone(),
        port: cli.port,
        wordlist: cli.wordlist.clone(),
        concurrency: cli.concurrency,
        rate: cli.rate,
        timeout_secs: cli.timeout,
        report: cli.output.clone(),
        json: cli.json,
        verbose: cli.verbose,
        framing,
    };

    let wl = Arc::new(wordlist::Wordlist::open(&cfg.wordlist)?);
    let total = wl.total();

    // shortcut: hard-coded fd-pressure heuristic, upgrade to a real RLIMIT_NOFILE
    // read if operators report false positives / negatives.
    if cfg.concurrency > 500 {
        eprintln!(
            "note: -c {} is high; raise `ulimit -n` if you see mid-run connect failures",
            cfg.concurrency
        );
    }

    let attempts = Arc::new(AtomicU64::new(0));
    let hit_count = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(AtomicBool::new(false));
    let connects_ok = Arc::new(AtomicU64::new(0));

    let (ev_tx, ev_rx) = tokio::sync::mpsc::channel::<common::Event>(1024);

    let limiter = if cfg.rate > 0 {
        let r = u32::try_from(cfg.rate)
            .map_err(|_| anyhow!("--rate {} too large (max {})", cfg.rate, u32::MAX))?;
        let q = NonZeroU32::new(r).ok_or_else(|| anyhow!("--rate must be nonzero"))?;
        Some(Arc::new(RateLimiter::direct(Quota::per_second(q))))
    } else {
        None
    };

    let bar = ui::make_bar(total);
    let progress = tokio::spawn(ui::progress_updater(
        bar.clone(),
        wl.clone(),
        attempts.clone(),
        hit_count.clone(),
        done.clone(),
    ));
    let writer_ctx = ui::WriterCtx {
        report: cfg.report.clone(),
        json: cfg.json,
        verbose: cfg.verbose,
        host: cfg.host.clone(),
        port: cfg.port,
        bar: bar.clone(),
    };
    let writer = tokio::spawn(ui::event_writer(ev_rx, writer_ctx));

    // Ctrl+C flips shutdown; workers notice on their next loop iteration (or
    // after their current in-flight attempt completes, bounded by --timeout).
    {
        let shutdown = shutdown.clone();
        let bar = bar.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                bar.println("received Ctrl+C, finishing in-flight attempts then flushing");
                shutdown.store(true, Ordering::Relaxed);
            }
        });
    }

    let mut handles = Vec::with_capacity(cfg.concurrency);
    for _ in 0..cfg.concurrency {
        let cfg = cfg.clone();
        let matcher = matcher.clone();
        let wl = wl.clone();
        let events = ev_tx.clone();
        let att = attempts.clone();
        let hc = hit_count.clone();
        let lim = limiter.clone();
        let bar = bar.clone();
        let shutdown = shutdown.clone();
        let connects_ok = connects_ok.clone();
        handles.push(tokio::spawn(async move {
            let _ = net::worker(
                cfg,
                matcher,
                wl,
                events,
                att,
                hc,
                lim,
                bar,
                shutdown,
                connects_ok,
            )
            .await;
        }));
    }
    drop(ev_tx);

    for h in handles {
        let _ = h.await;
    }
    done.store(true, Ordering::Relaxed);
    let _ = progress.await;
    writer.await??;

    if connects_ok.load(Ordering::Relaxed) == 0 && cfg.concurrency > 0 {
        bail!(
            "all {} workers failed to connect to {}:{} — check host, port, and firewall",
            cfg.concurrency,
            cfg.host,
            cfg.port
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{BannerSync, Prompt};

    #[test]
    fn parse_pattern_positive_forms() {
        // literal (default)
        match parse_pattern_positive("admin").unwrap() {
            Positive::Contains(s) => assert_eq!(s, "admin"),
            other => panic!("expected Contains, got {other:?}"),
        }
        // re: regex
        match parse_pattern_positive(r"re:^ok: \S+$").unwrap() {
            Positive::Regex(r) => {
                assert!(r.is_match("ok: abc"));
                assert!(!r.is_match("fail"));
            }
            other => panic!("expected Regex, got {other:?}"),
        }
        // lit: forced literal — would otherwise look like a regex spec
        match parse_pattern_positive("lit:re:not_a_regex").unwrap() {
            Positive::Contains(s) => assert_eq!(s, "re:not_a_regex"),
            other => panic!("expected Contains, got {other:?}"),
        }
    }

    #[test]
    fn parse_pattern_filter_forms() {
        match parse_pattern_filter("stub").unwrap() {
            Filter::Contains(s) => assert_eq!(s, "stub"),
            other => panic!("expected Contains, got {other:?}"),
        }
        match parse_pattern_filter(r"re:^stub\d+$").unwrap() {
            Filter::Regex(r) => {
                assert!(r.is_match("stub123"));
                assert!(!r.is_match("real"));
            }
            other => panic!("expected Regex, got {other:?}"),
        }
        match parse_pattern_filter("lit:re:literal").unwrap() {
            Filter::Contains(s) => assert_eq!(s, "re:literal"),
            other => panic!("expected Contains, got {other:?}"),
        }
    }

    #[test]
    fn parse_prompt_forms() {
        match parse_prompt("> ").unwrap() {
            Prompt::Literal(s) => assert_eq!(s, "> "),
            other => panic!("expected Literal, got {other:?}"),
        }
        match parse_prompt(r"re:>\s*$").unwrap() {
            Prompt::Regex(r) => assert!(r.is_match("ftp> ")),
            other => panic!("expected Regex, got {other:?}"),
        }
        match parse_prompt("lit:re:literal> ").unwrap() {
            Prompt::Literal(s) => assert_eq!(s, "re:literal> "),
            other => panic!("expected Literal, got {other:?}"),
        }
    }

    #[test]
    fn parse_banner_integer_vs_regex() {
        match parse_banner("3").unwrap() {
            BannerSync::SkipLines(n) => assert_eq!(n, 3),
            other => panic!("expected SkipLines, got {other:?}"),
        }
        match parse_banner("^Welcome").unwrap() {
            BannerSync::MatchRegex(r) => assert!(r.is_match("Welcome to the service")),
            other => panic!("expected MatchRegex, got {other:?}"),
        }
    }

    #[test]
    fn decode_eol_escapes() {
        assert_eq!(decode_eol("\\r\\n\\t"), "\r\n\t");
        assert_eq!(decode_eol("\\n"), "\n");
    }
}
