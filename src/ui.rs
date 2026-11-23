use crate::common::EventReceiver;
use crate::wordlist::Wordlist;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufWriter};

const TEMPLATE: &str =
    "{spinner} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({per_sec}, hits: {msg}, ETA {eta})";

/// Write `msg` above the bar, or straight to stderr when the bar is hidden
/// (piped stderr: indicatif's own `println` is a no-op there).
fn write_above_bar(bar: &ProgressBar, msg: impl AsRef<str>) {
    if bar.is_hidden() {
        eprintln!("{}", msg.as_ref());
    } else {
        bar.println(msg.as_ref());
    }
}

/// Rewrite control bytes (except \t) into \xNN escapes so a hostile server
/// cannot inject terminal escapes into the operator's shell.
fn sanitize(s: &str) -> std::borrow::Cow<'_, str> {
    if s.chars().all(|c| c == '\t' || !c.is_control()) {
        std::borrow::Cow::Borrowed(s)
    } else {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if c == '\t' || !c.is_control() {
                out.push(c);
            } else if (c as u32) <= 0xFF {
                out.push_str(&format!("\\x{:02x}", c as u32));
            } else {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
        }
        std::borrow::Cow::Owned(out)
    }
}

/// Build the stderr progress bar for `total` attempts.
pub fn make_bar(total: u64) -> ProgressBar {
    let bar = ProgressBar::new(total);
    // Fall back to indicatif's default style if template is malformed.
    if let Ok(style) = ProgressStyle::with_template(TEMPLATE) {
        bar.set_style(style.progress_chars("##-"));
    }
    bar.set_message("0");
    bar
}

/// Periodic updater that reads the atomic counters and ticks the bar.
/// Finishes when `done` is set. The bar length tracks `wl.total() - wl.skipped()`
/// so skipped (empty / non-UTF-8) lines don't leave the bar short.
pub async fn progress_updater(
    bar: ProgressBar,
    wl: Arc<Wordlist>,
    attempts: Arc<AtomicU64>,
    hits: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
) {
    loop {
        let hit_count = hits.load(Relaxed);
        bar.set_length(wl.total().saturating_sub(wl.skipped()));
        bar.set_position(attempts.load(Relaxed));
        bar.set_message(hit_count.to_string());
        if done.load(Relaxed) {
            bar.finish_with_message(format!("done; hits: {hit_count}"));
            eprintln!("Total hits: {hit_count}");
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Everything the writer task needs besides the event channel.
pub struct WriterCtx {
    pub report: Option<PathBuf>,
    pub json: bool,
    pub verbose: u8,
    pub host: String,
    pub port: u16,
    pub bar: ProgressBar,
}

/// Consume events: stream hits to stdout, optionally append the formatted
/// hits report to `-o PATH`, and emit verbose lines on stderr (above the bar).
pub async fn event_writer(mut rx: EventReceiver, ctx: WriterCtx) -> Result<()> {
    let mut stdout = BufWriter::with_capacity(64 * 1024, tokio::io::stdout());
    let mut report = match &ctx.report {
        Some(path) => {
            let f = tokio::fs::File::create(path).await?;
            let mut w = BufWriter::with_capacity(64 * 1024, f);
            w.write_all(b"HITS:\n").await?;
            w.flush().await?;
            Some(w)
        }
        None => None,
    };

    while let Some(ev) = rx.recv().await {
        if ev.is_hit {
            // stdout: plain (or JSON) hit line — unchanged legacy format.
            let line = if ctx.json {
                format!(
                    "{}\n",
                    serde_json::json!({ "word": &ev.payload, "response": &ev.response })
                )
            } else {
                format!("{}\t{}\n", ev.payload, sanitize(&ev.response))
            };
            stdout.write_all(line.as_bytes()).await?;
            stdout.flush().await?;

            if let Some(rf) = report.as_mut() {
                let cmd = nc_command(&ev.sent, &ctx.host, ctx.port);
                let entry = format!("{} - {}\n", shell_quote(&ev.word), cmd);
                rf.write_all(entry.as_bytes()).await?;
                rf.flush().await?;
            }
        }

        if ctx.verbose >= 1 && (ev.is_hit || ctx.verbose >= 2) {
            let tag = if ev.is_hit { "HIT " } else { "miss" };
            let cmd = nc_command(&ev.sent, &ctx.host, ctx.port);
            write_above_bar(
                &ctx.bar,
                format!("[{tag}] {} -> {}", ev.word, sanitize(&ev.response)),
            );
            write_above_bar(&ctx.bar, format!("        {cmd}"));
        }
    }
    stdout.flush().await?;
    if let Some(mut rf) = report {
        rf.flush().await?;
    }
    Ok(())
}

/// Build a reproducible `printf '...' | nc HOST PORT` one-liner.
fn nc_command(sent: &str, host: &str, port: u16) -> String {
    format!(
        "printf '{}' | nc {} {}",
        printf_escape(sent.as_bytes()),
        shell_quote(host),
        port,
    )
}

/// Make `bytes` safe inside a single-quoted POSIX `printf` format string.
fn printf_escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("'\\''"),
            b'%' => out.push_str("%%"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{:03o}", b)),
        }
    }
    out
}

/// Single-quote-wrap a shell word; pass alnum/._-+/:@ through untouched.
fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "_.-+/:@".contains(c))
    {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printf_escape_basics() {
        assert_eq!(printf_escape(b"admin\n"), "admin\\n");
        assert_eq!(printf_escape(b"a b"), "a b");
        assert_eq!(printf_escape(b"he's"), "he'\\''s");
        assert_eq!(printf_escape(b"100%"), "100%%");
        assert_eq!(printf_escape(&[0x01, b'x']), "\\001x");
        assert_eq!(printf_escape(b"\\n"), "\\\\n");
    }

    #[test]
    fn shell_quote_basics() {
        assert_eq!(shell_quote("admin"), "admin");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("he's"), "'he'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn nc_command_shape() {
        assert_eq!(
            nc_command("admin\n", "127.0.0.1", 9999),
            "printf 'admin\\n' | nc 127.0.0.1 9999"
        );
    }

    #[test]
    fn printf_escape_eol_variants() {
        // --eol \r and \t, not just \n.
        assert_eq!(printf_escape(b"a\tb"), "a\\tb");
        assert_eq!(printf_escape(b"a\rb"), "a\\rb");
    }

    /// The paired one-liner honours a custom `--send` template (FUZZ already
    /// substituted into it) and a non-`\n` `--eol` (here `\r\n`).
    #[test]
    fn nc_command_renders_custom_send_template_with_eol() {
        let sent = "GET /?q=' OR 1=1 HTTP/1.0\r\n";
        assert_eq!(
            nc_command(sent, "target.local", 1234),
            "printf 'GET /?q='\\'' OR 1=1 HTTP/1.0\\r\\n' | nc target.local 1234"
        );
    }

    #[test]
    fn sanitize_passes_through_plain_ascii() {
        let out = sanitize("ok:1234");
        assert_eq!(out, "ok:1234");
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn sanitize_keeps_tab() {
        assert_eq!(sanitize("a\tb"), "a\tb");
    }

    #[test]
    fn sanitize_escapes_esc() {
        assert_eq!(sanitize("\x1b[31m"), "\\x1b[31m");
    }

    #[test]
    fn sanitize_escapes_bell_and_cr() {
        let out = sanitize("ok\x07\r");
        assert!(out.contains("\\x07"));
        assert!(out.contains("\\x0d"));
    }
}
