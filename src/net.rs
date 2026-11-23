use crate::common::{BannerSync, Config, Event, EventSender, Framing, Prompt};
use crate::oracle::{normalise, Matcher};
use crate::wordlist::Wordlist;
use anyhow::{anyhow, Result};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    RateLimiter,
};
use indicatif::ProgressBar;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_RESP_BYTES: usize = 1 << 20; // 1 MiB per response/banner before we bail

pub type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;
pub type Conn = (BufReader<OwnedReadHalf>, OwnedWriteHalf);

/// Side of the attempt that failed. Write-side failures must NOT trigger a
/// payload retry: bytes may already be on the wire and a resend would double
/// anti-replay / lockout counters.
enum AttemptError {
    Write(anyhow::Error),
    Read(anyhow::Error),
}

/// Open a connection and consume the banner per `framing.banner`.
pub async fn connect_and_sync(
    host: &str,
    port: u16,
    timeout_secs: u64,
    framing: &Framing,
) -> Result<Conn> {
    let to = Duration::from_secs(timeout_secs);
    let stream = timeout(to, TcpStream::connect((host, port))).await??;
    let (r, w) = stream.into_split();
    let mut reader = BufReader::new(r);
    consume_banner(&mut reader, &framing.banner, framing.prompt.as_ref(), to).await?;
    Ok((reader, w))
}

async fn consume_banner(
    reader: &mut BufReader<OwnedReadHalf>,
    banner: &BannerSync,
    prompt: Option<&Prompt>,
    to: Duration,
) -> Result<()> {
    match banner {
        BannerSync::SkipLines(n) => {
            for _ in 0..*n {
                let mut line = String::new();
                let read = timeout(to, read_line_capped(reader, &mut line)).await??;
                if read == 0 {
                    return Err(anyhow!("eof during banner skip"));
                }
            }
            // A banner ending with a same-line prompt (e.g. "> ") leaves that
            // prompt in the reader; without this it would be mis-read as the
            // first attempt's empty response, shifting word↔response pairing.
            if *n > 0 && prompt.is_some() {
                read_response(reader, prompt, to).await?;
            }
            Ok(())
        }
        // Byte-level: a banner that ends in a non-newline prompt (e.g. "> ")
        // never completes under read_line. Leave any bytes past the match in
        // the reader for the first real response.
        BannerSync::MatchRegex(re) => {
            timeout(to, async {
                let mut acc: Vec<u8> = Vec::new();
                loop {
                    let chunk = reader.fill_buf().await?;
                    if chunk.is_empty() {
                        return Err(anyhow!("eof before banner matched"));
                    }
                    let chunk_len = chunk.len();
                    let before_len = acc.len();
                    acc.extend_from_slice(chunk);
                    if acc.len() > MAX_RESP_BYTES {
                        return Err(anyhow!("response exceeded {MAX_RESP_BYTES} bytes"));
                    }
                    if let Ok(s) = std::str::from_utf8(&acc) {
                        if let Some(m) = re.find(s) {
                            reader.consume(m.end() - before_len);
                            return Ok(());
                        }
                    }
                    reader.consume(chunk_len);
                }
            })
            .await?
        }
    }
}

/// Send one payload, read one response bounded by `framing.prompt`.
/// Returns the raw (un-normalised) response.
pub async fn attempt(
    conn: &mut Conn,
    framing: &Framing,
    payload: &str,
    timeout_secs: u64,
) -> Result<String> {
    attempt_inner(conn, framing, payload, timeout_secs)
        .await
        .map_err(|e| match e {
            AttemptError::Write(x) | AttemptError::Read(x) => x,
        })
}

async fn attempt_inner(
    conn: &mut Conn,
    framing: &Framing,
    payload: &str,
    timeout_secs: u64,
) -> Result<String, AttemptError> {
    let to = Duration::from_secs(timeout_secs);
    let (reader, writer) = conn;
    let mut line = String::with_capacity(payload.len() + framing.eol.len());
    line.push_str(payload);
    line.push_str(&framing.eol);
    timeout(to, writer.write_all(line.as_bytes()))
        .await
        .map_err(|e| AttemptError::Write(e.into()))?
        .map_err(|e| AttemptError::Write(e.into()))?;
    timeout(to, writer.flush())
        .await
        .map_err(|e| AttemptError::Write(e.into()))?
        .map_err(|e| AttemptError::Write(e.into()))?;
    read_response(reader, framing.prompt.as_ref(), to)
        .await
        .map_err(AttemptError::Read)
}

async fn read_response(
    reader: &mut BufReader<OwnedReadHalf>,
    prompt: Option<&Prompt>,
    to: Duration,
) -> Result<String> {
    match prompt {
        None => {
            let mut buf = String::new();
            let n = timeout(to, read_line_capped(reader, &mut buf)).await??;
            if n == 0 {
                return Err(anyhow!("eof reading response"));
            }
            while buf.ends_with('\n') || buf.ends_with('\r') {
                buf.pop();
            }
            Ok(buf)
        }
        Some(Prompt::Literal(p)) => {
            let pb = p.as_bytes();
            read_until_prompt(reader, to, |b| {
                b.windows(pb.len())
                    .position(|w| w == pb)
                    .map(|s| (s, s + pb.len()))
            })
            .await
        }
        Some(Prompt::Regex(re)) => {
            read_until_prompt(reader, to, |b| {
                let s = std::str::from_utf8(b).ok()?;
                re.find(s).map(|m| (m.start(), m.end()))
            })
            .await
        }
    }
}

/// `read_line` that bails instead of buffering past `MAX_RESP_BYTES` with no `\n`.
async fn read_line_capped(
    reader: &mut BufReader<OwnedReadHalf>,
    buf: &mut String,
) -> Result<usize> {
    let n = reader.take(MAX_RESP_BYTES as u64).read_line(buf).await?;
    if n == MAX_RESP_BYTES && !buf.ends_with('\n') {
        return Err(anyhow!("response exceeded {MAX_RESP_BYTES} bytes"));
    }
    Ok(n)
}

/// Byte-level read: accumulate bytes until `find` returns `(start, end)`,
/// return bytes `0..start`, and leave bytes after `end` in the reader for
/// the next request. One `timeout` wraps the whole loop so a prompt that
/// arrives in trickles still fails on a single deadline.
async fn read_until_prompt<F>(
    reader: &mut BufReader<OwnedReadHalf>,
    to: Duration,
    find: F,
) -> Result<String>
where
    F: Fn(&[u8]) -> Option<(usize, usize)>,
{
    timeout(to, async {
        let mut acc: Vec<u8> = Vec::new();
        loop {
            let chunk = reader.fill_buf().await?;
            if chunk.is_empty() {
                return Err(anyhow!("eof before prompt"));
            }
            let chunk_len = chunk.len();
            let before_len = acc.len();
            acc.extend_from_slice(chunk);
            if acc.len() > MAX_RESP_BYTES {
                return Err(anyhow!("response exceeded {MAX_RESP_BYTES} bytes"));
            }
            match find(&acc) {
                Some((start, end)) => {
                    reader.consume(end - before_len);
                    acc.truncate(start);
                    return Ok(String::from_utf8_lossy(&acc).into_owned());
                }
                None => {
                    reader.consume(chunk_len);
                }
            }
        }
    })
    .await?
}

/// One persistent-connection worker. Reconnects on drop/timeout and resumes.
///
/// Diagnostics go through `bar.println` (never raw `eprintln!`) so the status
/// bar doesn't tear. `shutdown` lets `main` break the loop on Ctrl+C.
/// `connects_ok` is incremented on every successful connect so `main` can
/// detect an all-workers-failed-to-connect run and exit non-zero.
#[allow(clippy::too_many_arguments)]
pub async fn worker(
    cfg: Config,
    matcher: Arc<Matcher>,
    wl: Arc<Wordlist>,
    events: EventSender,
    attempts: Arc<AtomicU64>,
    hit_count: Arc<AtomicU64>,
    limiter: Option<Arc<Limiter>>,
    bar: ProgressBar,
    shutdown: Arc<AtomicBool>,
    connects_ok: Arc<AtomicU64>,
) -> Result<()> {
    let to_secs = cfg.timeout_secs;
    async fn reconnect(
        cfg: &Config,
        connects_ok: &Arc<AtomicU64>,
        bar: &ProgressBar,
        label: &str,
    ) -> Option<Conn> {
        match connect_and_sync(&cfg.host, cfg.port, cfg.timeout_secs, &cfg.framing).await {
            Ok(c) => {
                connects_ok.fetch_add(1, Ordering::Relaxed);
                Some(c)
            }
            Err(e) => {
                bar.println(format!("worker: {label} failed: {e}"));
                None
            }
        }
    }
    let Some(mut conn) = reconnect(&cfg, &connects_ok, &bar, "connect").await else {
        return Ok(());
    };
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        let Some(word) = wl.next() else { return Ok(()) };
        if let Some(l) = limiter.as_ref() {
            l.until_ready().await;
        }
        let payload = cfg.framing.send_template.replace("FUZZ", &word);
        // Both Write- and Read-side failures must skip (not resend) this word:
        // a write timeout may still have landed partially, and a read timeout
        // means the write already succeeded — either way a resend could
        // double-fire (e.g. counted twice toward a server-side lockout).
        let raw = match attempt_inner(&mut conn, &cfg.framing, &payload, to_secs).await {
            Ok(r) => r,
            Err(err) => {
                let msg = match err {
                    AttemptError::Write(_) => format!(
                        "worker: write timeout, skipping entry {word:?} (possible partial send)"
                    ),
                    AttemptError::Read(_) => format!(
                        "worker: read timeout, skipping entry {word:?} (payload already delivered)"
                    ),
                };
                bar.println(msg);
                let Some(c) = reconnect(&cfg, &connects_ok, &bar, "reconnect").await else {
                    return Ok(());
                };
                conn = c;
                continue;
            }
        };
        attempts.fetch_add(1, Ordering::Relaxed);
        let response = normalise(&raw, &cfg.framing, &payload);
        let is_hit = matcher.is_hit(&response);
        if is_hit {
            hit_count.fetch_add(1, Ordering::Relaxed);
        }
        if is_hit || cfg.verbose >= 2 {
            let sent = format!("{}{}", payload, cfg.framing.eol);
            let ev = Event {
                is_hit,
                word,
                payload,
                sent,
                response,
            };
            if events.send(ev).await.is_err() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{BannerSync, Framing, Prompt};
    use crate::oracle::Positive;
    use regex::Regex;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn prompt_without_trailing_newline_roundtrips() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            // Banner ends in "> " with no newline.
            w.write_all(b"> ").await.unwrap();
            w.flush().await.unwrap();
            let mut n = 0u32;
            loop {
                let mut line = String::new();
                let read = r.read_line(&mut line).await.unwrap();
                if read == 0 {
                    break;
                }
                n += 1;
                let resp = format!("response_{n}\n> ");
                w.write_all(resp.as_bytes()).await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let framing = Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: Some(Prompt::Literal("> ".into())),
            banner: BannerSync::MatchRegex(Regex::new(r"> $").unwrap()),
        };

        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();

        for i in 1..=3u32 {
            let resp = attempt(&mut conn, &framing, "w", 5).await.unwrap();
            assert_eq!(resp.trim_end(), format!("response_{i}"));
        }
    }

    /// Default framing (no `-P`): one newline-terminated line, and the
    /// default `FUZZ`-alone template is substituted before it ever reaches
    /// `attempt` (substitution is the caller's job, mirrored here).
    #[tokio::test]
    async fn default_framing_reads_one_newline_terminated_line() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            let resp = format!("echo:{}\n", line.trim_end());
            w.write_all(resp.as_bytes()).await.unwrap();
            w.flush().await.unwrap();
        });

        let framing = Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: None,
            banner: BannerSync::SkipLines(0),
        };
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let payload = framing.send_template.replace("FUZZ", "admin");
        let resp = attempt(&mut conn, &framing, &payload, 5).await.unwrap();
        assert_eq!(resp, "echo:admin");
    }

    /// FUZZ substitution inside a custom `--send` template, plus a non-`\n`
    /// `--eol` (`\t`): the server detects end-of-request by the eol byte
    /// itself, proving both the substitution and the exact terminator sent.
    #[tokio::test]
    async fn custom_send_template_and_eol_are_sent_verbatim() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            let mut acc: Vec<u8> = Vec::new();
            loop {
                let chunk = r.fill_buf().await.unwrap();
                if chunk.is_empty() {
                    panic!("eof before eol marker");
                }
                let len = chunk.len();
                acc.extend_from_slice(chunk);
                r.consume(len);
                if acc.ends_with(b"\t") {
                    break;
                }
            }
            acc.pop(); // drop the eol byte
            let resp = format!("got:{}\n", String::from_utf8_lossy(&acc));
            w.write_all(resp.as_bytes()).await.unwrap();
            w.flush().await.unwrap();
        });

        let framing = Framing {
            send_template: "GET /?q=FUZZ HTTP/1.0".into(),
            eol: "\t".into(),
            prompt: None,
            banner: BannerSync::SkipLines(0),
        };
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let payload = framing.send_template.replace("FUZZ", "' OR 1=1");
        let resp = attempt(&mut conn, &framing, &payload, 5).await.unwrap();
        assert_eq!(resp, "got:GET /?q=' OR 1=1 HTTP/1.0");
    }

    /// Prompt-bounded framing with a `re:` regex prompt (not just a literal).
    #[tokio::test]
    async fn prompt_regex_bounds_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            w.write_all(b"ftp> ").await.unwrap();
            w.flush().await.unwrap();
            loop {
                let mut line = String::new();
                let read = r.read_line(&mut line).await.unwrap();
                if read == 0 {
                    break;
                }
                w.write_all(b"230 ok\nftp> ").await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let framing = Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: Some(Prompt::Regex(Regex::new(r"\w+>\s$").unwrap())),
            banner: BannerSync::MatchRegex(Regex::new(r"\w+>\s$").unwrap()),
        };
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let resp = attempt(&mut conn, &framing, "login", 5).await.unwrap();
        assert_eq!(resp, "230 ok\n");
    }

    /// Banner sync by integer line count: exactly N lines are skipped before
    /// the first real request/response exchange.
    #[tokio::test]
    async fn banner_skip_lines_consumes_exact_count() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            w.write_all(b"banner1\nbanner2\n").await.unwrap();
            w.flush().await.unwrap();
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            let resp = format!("reply:{}\n", line.trim_end());
            w.write_all(resp.as_bytes()).await.unwrap();
            w.flush().await.unwrap();
        });

        let framing = Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: None,
            banner: BannerSync::SkipLines(2),
        };
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let resp = attempt(&mut conn, &framing, "ping", 5).await.unwrap();
        assert_eq!(resp, "reply:ping");
    }

    /// A banner that ends with a same-line prompt ("> ") must be consumed
    /// through that prompt when `-b N` is combined with `-P`; otherwise the
    /// stale prompt is read as the first attempt's empty response and all
    /// word↔response pairings shift by one for the rest of the run.
    #[tokio::test]
    async fn banner_skip_lines_consumes_trailing_prompt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            w.write_all(b"welcome\n> ").await.unwrap();
            w.flush().await.unwrap();
            for _ in 0..2 {
                let mut line = String::new();
                r.read_line(&mut line).await.unwrap();
                let resp = format!("reply:{}\n> ", line.trim_end());
                w.write_all(resp.as_bytes()).await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let framing = Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: Some(Prompt::Literal("> ".into())),
            banner: BannerSync::SkipLines(1),
        };
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let r1 = attempt(&mut conn, &framing, "ping", 5).await.unwrap();
        let r2 = attempt(&mut conn, &framing, "pong", 5).await.unwrap();
        assert_eq!(r1, "reply:ping\n");
        assert_eq!(r2, "reply:pong\n");
    }

    fn wordlist_file(contents: &str) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), contents).unwrap();
        f
    }

    /// Reproduces the lockout-doubling bug: a read timeout happens only
    /// after the write already landed, so the reconnect must move on to the
    /// NEXT word rather than resending the one that already went out.
    #[tokio::test]
    async fn read_error_drops_word_instead_of_resending() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

        tokio::spawn(async move {
            // Connection 1: read the first word, then stall well past the
            // client's read timeout without ever replying.
            let (sock1, _) = listener.accept().await.unwrap();
            let (r1, w1) = sock1.into_split();
            let mut r1 = BufReader::new(r1);
            let mut line1 = String::new();
            r1.read_line(&mut line1).await.unwrap();
            seen_tx.send(line1.trim_end().to_string()).unwrap();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            drop(w1);
            drop(r1);

            // Connection 2: the reconnect. A correct worker sends the next
            // word here; the bug would resend the first word's payload.
            let (sock2, _) = listener.accept().await.unwrap();
            let (r2, mut w2) = sock2.into_split();
            let mut r2 = BufReader::new(r2);
            let mut line2 = String::new();
            r2.read_line(&mut line2).await.unwrap();
            seen_tx.send(line2.trim_end().to_string()).unwrap();
            w2.write_all(b"miss\n").await.unwrap();
            w2.flush().await.unwrap();
        });

        let wl_file = wordlist_file("word1\nword2\n");
        let cfg = Config {
            host: addr.ip().to_string(),
            port: addr.port(),
            wordlist: wl_file.path().to_path_buf(),
            concurrency: 1,
            rate: 0,
            timeout_secs: 1,
            report: None,
            json: false,
            verbose: 2, // emit an Event for every attempt, hit or not
            framing: Framing {
                send_template: "FUZZ".into(),
                eol: "\n".into(),
                prompt: None,
                banner: BannerSync::SkipLines(0),
            },
        };
        let matcher = Arc::new(Matcher {
            positive: Positive::MissEquals("miss".into()),
            filters: vec![],
        });
        let wl = Arc::new(Wordlist::open(&cfg.wordlist).unwrap());
        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<Event>(8);
        let attempts = Arc::new(AtomicU64::new(0));

        timeout(
            Duration::from_secs(10),
            worker(
                cfg,
                matcher,
                wl,
                ev_tx,
                attempts.clone(),
                Arc::new(AtomicU64::new(0)),
                None,
                ProgressBar::hidden(),
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicU64::new(0)),
            ),
        )
        .await
        .expect("worker hung")
        .unwrap();

        let first_seen = seen_rx.recv().await.unwrap();
        let second_seen = seen_rx.recv().await.unwrap();
        assert_eq!(first_seen, "word1");
        assert_eq!(
            second_seen, "word2",
            "reconnect must advance to the next word, not resend {first_seen:?}"
        );

        // Only the surviving attempt (word2) is counted; word1 was dropped,
        // not double-fired.
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        let ev = ev_rx.recv().await.unwrap();
        assert_eq!(ev.word, "word2");
    }

    /// Hostile server floods bytes with no `\n` and no prompt: every read
    /// path (read_line, literal prompt, `-b N` skip, regex banner) must bail
    /// at MAX_RESP_BYTES instead of buffering forever.
    #[tokio::test]
    async fn flood_without_newline_or_prompt_is_capped() {
        async fn flood() -> std::net::SocketAddr {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                while sock.write_all(&[b'A'; 8192]).await.is_ok() {}
            });
            addr
        }
        // Generous timeout: the literal scan is quadratic (debug build) and
        // must not hit the deadline before the cap does.
        const T: u64 = 60;
        let framing = |prompt, banner| Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt,
            banner,
        };

        for prompt in [None, Some(Prompt::Literal("> ".into()))] {
            let addr = flood().await;
            let f = framing(prompt, BannerSync::SkipLines(0));
            let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), T, &f)
                .await
                .unwrap();
            let e = attempt(&mut conn, &f, "w", T).await.unwrap_err();
            assert!(e.to_string().contains("response exceeded"), "{e}");
        }
        for banner in [
            BannerSync::SkipLines(1),
            BannerSync::MatchRegex(Regex::new("never$").unwrap()),
        ] {
            let addr = flood().await;
            let f = framing(None, banner);
            let e = connect_and_sync(&addr.ip().to_string(), addr.port(), T, &f)
                .await
                .expect_err("banner must bail");
            assert!(e.to_string().contains("response exceeded"), "{e}");
        }
    }
}
