//! Error-channel: fire the error triad (`'`, `"`, backtick), match replies
//! against a built-in DBMS error-signature table, attach engine id.
//! `extractvalue()` / `updatexml()` error-exfil belongs HERE — matched by
//! error signature, surfacing data in the error string.
//!
//! Licensing: signatures must be written here or taken from a *permissively*
//! licensed source — NO copy of sqlmap's GPL `errors.xml`. Every regex gets a
//! provenance comment (original OR which permissive source).
//!
//! OWNER (Phase 1): error agent.

use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;

use crate::common::Framing;
use crate::net::{attempt, Conn};
use crate::oracle::normalise;

use super::types::{Baseline, Channel, Dialect, SqliConfig, Verdict};

type SigTable = Vec<(Dialect, Regex, &'static str)>;

/// Built-in DBMS error-signature table. Lazy so the regex compile cost is
/// paid once per process, never per probe.
fn signatures() -> &'static SigTable {
    static TABLE: OnceLock<SigTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        // `unwrap` on a literal regex: compile failure is a build-time bug,
        // not a runtime one — caught by the first `cargo test` run.
        let mk = |r: &str| Regex::new(r).expect("sqli errors: static regex must compile");
        vec![
            // MySQL / MariaDB
            (
                Dialect::MySql,
                mk(r"(?i)You have an error in your SQL syntax"),
                "mysql_syntax_banner",
            ),
            (
                Dialect::MySql,
                mk(r"(?i)near '.*?' at line \d+"),
                "mysql_near_at_line",
            ),
            (
                Dialect::MySql,
                mk(r"(?i)(MySQL|MariaDB) server version"),
                "mysql_server_version",
            ),
            (
                Dialect::MySql,
                mk(r"(?i)mysql_fetch_(array|row|assoc)"),
                "mysql_fetch_api",
            ),
            // `extractvalue()` / `updatexml()` surface their payload inside a MySQL XPATH error.
            (
                Dialect::MySql,
                mk(r"(?i)XPATH syntax error"),
                "mysql_xpath_exfil",
            ),
            (
                Dialect::MySql,
                mk(r"(?i)Illegal mix of collations"),
                "mysql_illegal_mix_collations",
            ),
            // PostgreSQL
            (
                Dialect::Postgres,
                mk(r"(?i)PostgreSQL.*ERROR"),
                "pg_error_header",
            ),
            (
                Dialect::Postgres,
                mk(r"(?i)ERROR:\s+syntax error at or near"),
                "pg_syntax_error_near",
            ),
            (Dialect::Postgres, mk(r"(?i)\bpq:\s"), "pg_pq_prefix"),
            (
                Dialect::Postgres,
                mk(r"(?i)unterminated quoted string"),
                "pg_unterminated_quoted_string",
            ),
            // MSSQL
            (
                Dialect::Mssql,
                mk(r"(?i)Microsoft OLE DB Provider for SQL Server"),
                "mssql_oledb_provider",
            ),
            (
                Dialect::Mssql,
                mk(r"(?i)Unclosed quotation mark"),
                "mssql_unclosed_quote",
            ),
            (
                Dialect::Mssql,
                mk(r"(?i)SQL Server Native Client"),
                "mssql_native_client",
            ),
            (
                Dialect::Mssql,
                mk(r"(?i)SqlException"),
                "mssql_sqlexception",
            ),
            // Oracle
            (
                Dialect::Oracle,
                mk(r"(?i)ORA-0093[36]"),
                "oracle_ora_00933_00936",
            ),
            (Dialect::Oracle, mk(r"(?i)ORA-00921"), "oracle_ora_00921"),
            (
                Dialect::Oracle,
                mk(r"(?i)quoted string not properly terminated"),
                "oracle_unterm_string",
            ),
            // SQLite
            (
                Dialect::Sqlite,
                mk(r"(?i)SQLite error"),
                "sqlite_error_prefix",
            ),
            (
                Dialect::Sqlite,
                mk(r"(?i)unrecognized token"),
                "sqlite_unrecognized_token",
            ),
            (
                Dialect::Sqlite,
                mk(r"(?i)sqlite3\.OperationalError"),
                "sqlite3_operational_error",
            ),
        ]
    })
}

/// First-match lookup; returned alongside its label so `run` can attribute
/// the proof line to a specific regex without re-walking the table.
fn classify_with_label(reply: &str) -> Option<(Dialect, &'static str)> {
    for (dialect, re, label) in signatures() {
        if re.is_match(reply) {
            return Some((*dialect, *label));
        }
    }
    None
}

/// Match a server reply against the built-in signature table.
pub fn classify_reply(reply: &str) -> Option<Dialect> {
    classify_with_label(reply).map(|(d, _)| d)
}

/// Fire the error triad against `conn`; return each confirmed error-channel
/// verdict (one per probe whose `cfg.confirm` replies all matched the SAME
/// dialect). Each triad member is fired independently — a confirm on one
/// member doesn't skip the others, since each may expose a distinct filter
/// variant.
pub async fn run(
    conn: &mut Conn,
    framing: &Framing,
    timeout_secs: u64,
    cfg: &SqliConfig,
    _baseline: &Baseline,
) -> Result<Vec<Verdict>> {
    let probes = ["'", "\"", "`"];
    let confirm = cfg.confirm.max(1);
    let mut verdicts: Vec<Verdict> = Vec::new();

    for probe in probes {
        let payload = framing.send_template.replace("FUZZ", probe);
        let mut agreed_dialect: Option<Dialect> = None;
        let mut first_label: Option<&'static str> = None;
        let mut last_reply: Option<String> = None;
        let mut all_matched = true;

        for _ in 0..confirm {
            // shortcut: run() has no host/port, so it cannot reconnect; return
            // what we have, per spec's "if reconnect fails" clause. Upgrade
            // when the signature gains reconnect info.
            let Ok(raw) = attempt(conn, framing, &payload, timeout_secs).await else {
                return Ok(verdicts);
            };
            let reply = normalise(&raw, framing, &payload);
            match classify_with_label(&reply) {
                Some((d, label)) => match agreed_dialect {
                    None => {
                        agreed_dialect = Some(d);
                        first_label = Some(label);
                        last_reply = Some(reply);
                    }
                    Some(prev) if prev == d => {
                        last_reply = Some(reply);
                    }
                    _ => {
                        // Dialects disagreed across confirms — no verdict for this probe.
                        all_matched = false;
                        break;
                    }
                },
                None => {
                    all_matched = false;
                    break;
                }
            }
        }

        if all_matched {
            if let (Some(d), Some(label), Some(reply)) = (agreed_dialect, first_label, last_reply) {
                let snippet: String = reply.chars().take(120).collect();
                verdicts.push(Verdict {
                    channel: Channel::Error,
                    wrapper: Some(probe.to_string()),
                    payload: payload.clone(),
                    proof: format!("matched {label:?} {snippet:?}"),
                    engine: Some(d),
                    allows: Vec::new(),
                });
            }
        }
    }

    Ok(verdicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{BannerSync, Framing};
    use crate::net::connect_and_sync;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    fn trivial_baseline() -> Baseline {
        Baseline {
            reply_shape: String::new(),
            rtt_mean: Duration::from_millis(0),
            rtt_stddev: Duration::from_millis(0),
            samples: 0,
        }
    }

    #[tokio::test]
    async fn triad_confirms_mysql_on_single_quote() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            // One-line banner; SkipLines(1) on the client consumes it.
            w.write_all(b"ready\n").await.unwrap();
            w.flush().await.unwrap();
            loop {
                let mut line = String::new();
                let n = r.read_line(&mut line).await.unwrap();
                if n == 0 {
                    break;
                }
                let resp: &[u8] = if line.contains('\'') {
                    b"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version\n"
                } else {
                    b"benign\n"
                };
                w.write_all(resp).await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let framing = Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: None,
            banner: BannerSync::SkipLines(1),
        };
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let cfg = SqliConfig {
            sleep_secs: 0,
            confirm: 2,
        };
        let baseline = trivial_baseline();

        let verdicts = run(&mut conn, &framing, 5, &cfg, &baseline).await.unwrap();

        assert!(
            verdicts.iter().any(|v| v.channel == Channel::Error
                && v.engine == Some(Dialect::MySql)
                && v.wrapper.as_deref() == Some("'")
                && v.proof.to_lowercase().contains("mysql")),
            "expected a MySQL error-channel verdict on single-quote probe, got {:?}",
            verdicts
        );
    }

    #[test]
    fn classify_postgres_syntax_error() {
        let s = "ERROR:  syntax error at or near \"FOO\"";
        assert_eq!(classify_reply(s), Some(Dialect::Postgres));
    }

    #[test]
    fn classify_benign_text_is_none() {
        assert_eq!(classify_reply("ok, nothing to see here"), None);
    }

    #[test]
    fn classify_mysql_xpath_exfil() {
        let s = "XPATH syntax error: '~1234abcd~'";
        assert_eq!(classify_reply(s), Some(Dialect::MySql));
    }

    /// Mock oracle that alternates MySQL/Postgres error signatures on every
    /// reply, regardless of what was sent — so two *consecutive* observations
    /// never agree.
    async fn spawn_alternating_oracle() -> std::net::SocketAddr {
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
                n += 1;
                let resp: &[u8] = if n % 2 == 1 {
                    b"You have an error in your SQL syntax\n"
                } else {
                    b"PostgreSQL ERROR: syntax error\n"
                };
                w.write_all(resp).await.unwrap();
                w.flush().await.unwrap();
            }
        });
        addr
    }

    /// Generic confirm-count rule, N=2 case: one agreeing observation (the
    /// first of each probe) followed by a disagreeing second is NOT enough —
    /// --sqli-confirm requires every one of the N observations to agree.
    #[tokio::test]
    async fn confirm_two_requires_both_observations_to_agree() {
        let addr = spawn_alternating_oracle().await;
        let framing = Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: None,
            banner: BannerSync::SkipLines(0),
        };
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let cfg = SqliConfig {
            sleep_secs: 0,
            confirm: 2,
        };
        let verdicts = run(&mut conn, &framing, 5, &cfg, &trivial_baseline())
            .await
            .unwrap();
        assert!(
            verdicts.is_empty(),
            "one agreeing observation out of 2 must not confirm, got {verdicts:?}"
        );
    }

    /// Same alternating oracle, but --sqli-confirm=1: a single observation is
    /// trivially "N agreeing observations" for N=1, so it DOES confirm.
    #[tokio::test]
    async fn confirm_one_matches_on_first_observation() {
        let addr = spawn_alternating_oracle().await;
        let framing = Framing {
            send_template: "FUZZ".into(),
            eol: "\n".into(),
            prompt: None,
            banner: BannerSync::SkipLines(0),
        };
        let mut conn = connect_and_sync(&addr.ip().to_string(), addr.port(), 5, &framing)
            .await
            .unwrap();
        let cfg = SqliConfig {
            sleep_secs: 0,
            confirm: 1,
        };
        let verdicts = run(&mut conn, &framing, 5, &cfg, &trivial_baseline())
            .await
            .unwrap();
        assert!(
            !verdicts.is_empty(),
            "a single observation must confirm when --sqli-confirm=1"
        );
        assert_eq!(verdicts[0].engine, Some(Dialect::MySql));
    }
}
