use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dialect {
    MySql,
    Postgres,
    Mssql,
    Sqlite,
    Oracle,
}

impl Dialect {
    pub fn name(&self) -> &'static str {
        match self {
            Dialect::MySql => "MySQL/MariaDB",
            Dialect::Postgres => "PostgreSQL",
            Dialect::Mssql => "MSSQL",
            Dialect::Sqlite => "SQLite",
            Dialect::Oracle => "Oracle",
        }
    }

    /// Render `{SLEEP}` as a whole dialect-specific sleep *expression*.
    /// `None` when no safe form exists (SQLite / Oracle without privs).
    pub fn render_sleep(&self, secs: u32) -> Option<String> {
        match self {
            Dialect::MySql => Some(format!("SLEEP({secs})")),
            Dialect::Postgres => Some(format!("pg_sleep({secs})")),
            Dialect::Mssql => {
                // WAITFOR DELAY's upper bound is 24h; SQL Server rejects '24:00:00'.
                if secs >= 86_400 {
                    return None;
                }
                let h = secs / 3600;
                let m = (secs % 3600) / 60;
                let s = secs % 60;
                Some(format!("WAITFOR DELAY '{h:02}:{m:02}:{s:02}'"))
            }
            Dialect::Sqlite | Dialect::Oracle => None,
        }
    }

    pub fn all() -> &'static [Dialect] {
        &[
            Dialect::MySql,
            Dialect::Postgres,
            Dialect::Mssql,
            Dialect::Sqlite,
            Dialect::Oracle,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Error,
    Boolean,
    Union,
    Time,
    Raw,
    /// `-z`: reply shape diverged from the learned zero-knowledge baseline.
    Shape,
}

impl Channel {
    pub fn tag(&self) -> &'static str {
        match self {
            Channel::Error => "error",
            Channel::Boolean => "boolean",
            Channel::Union => "union",
            Channel::Time => "time",
            Channel::Raw => "raw",
            Channel::Shape => "shape",
        }
    }
}

/// Filter-fingerprint classes reported under "appears to allow: ...".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Allows {
    MixedCase,
    InlineComments,
    AltWhitespace,
    KeywordDoubling,
    ConcatSplit,
    OperatorSwap,
    BooleanKeywordSwap,
    CommentTerminatorSwap,
    QuoteCharSwap,
    NoQuoteNumeric,
}

impl Allows {
    pub fn label(&self) -> &'static str {
        match self {
            Allows::MixedCase => "mixed-case keywords",
            Allows::InlineComments => "inline comments",
            Allows::AltWhitespace => "alt whitespace",
            Allows::KeywordDoubling => "keyword doubling",
            Allows::ConcatSplit => "concat-split",
            Allows::OperatorSwap => "operator swap",
            Allows::BooleanKeywordSwap => "boolean-keyword swap (||/&&)",
            Allows::CommentTerminatorSwap => "comment-terminator swap",
            Allows::QuoteCharSwap => "quote-char swap",
            Allows::NoQuoteNumeric => "no-quote numeric context",
        }
    }

    pub fn parse_tag(s: &str) -> Option<Allows> {
        match s {
            "mixed-case" | "mixed_case" => Some(Allows::MixedCase),
            "inline-comments" | "inline_comments" => Some(Allows::InlineComments),
            "alt-whitespace" | "alt_whitespace" => Some(Allows::AltWhitespace),
            "keyword-doubling" | "keyword_doubling" => Some(Allows::KeywordDoubling),
            "concat-split" | "concat_split" => Some(Allows::ConcatSplit),
            "operator-swap" | "operator_swap" => Some(Allows::OperatorSwap),
            "boolean-keyword-swap" | "boolean_keyword_swap" => Some(Allows::BooleanKeywordSwap),
            "comment-terminator-swap" | "comment_terminator_swap" => {
                Some(Allows::CommentTerminatorSwap)
            }
            "quote-char-swap" | "quote_char_swap" => Some(Allows::QuoteCharSwap),
            "no-quote-numeric" | "no_quote_numeric" => Some(Allows::NoQuoteNumeric),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Verdict {
    pub channel: Channel,
    /// Reusable injection wrapper when the injection point is known:
    /// built-in probes always carry one; wordlist lines carry one only when
    /// they contain `{SLEEP}` (the token marks the hole). Else None — the
    /// output layer prints the raw `payload` + `proof`.
    pub wrapper: Option<String>,
    /// The post-templating payload that fired (`{SLEEP}` already rendered).
    pub payload: String,
    /// One-line, operator-readable evidence (regex that matched, TRUE/FALSE
    /// response fragments, measured vs. baseline RTT, etc.).
    pub proof: String,
    pub engine: Option<Dialect>,
    pub allows: Vec<Allows>,
}

#[derive(Clone, Debug)]
pub struct Baseline {
    pub reply_shape: String,
    pub rtt_mean: Duration,
    pub rtt_stddev: Duration,
    pub samples: u32,
}

impl Baseline {
    /// Upper bound used by the time channel: baseline mean + N seconds + k·σ.
    pub fn time_hit_threshold(&self, sleep_secs: u32, k: f64) -> Duration {
        let margin = Duration::from_secs(sleep_secs as u64);
        let jitter = Duration::from_secs_f64(self.rtt_stddev.as_secs_f64() * k);
        self.rtt_mean + margin + jitter
    }
}

#[derive(Clone, Debug)]
pub struct SqliConfig {
    pub sleep_secs: u32,
    /// Number of agreeing observations required before a verdict is reported.
    pub confirm: u32,
}

/// Parse a wordlist line into (payload, optional class tag).
/// Separator is the literal two-space-then-`#class:` sequence, which keeps
/// in-SQL `#` comments intact. Returns `(payload, None)` when absent.
pub fn parse_wordlist_payload(line: &str) -> (String, Option<Allows>) {
    const SEP: &str = "  #class:";
    if let Some(ix) = line.find(SEP) {
        let payload = line[..ix].to_string();
        let tag = line[ix + SEP.len()..].trim();
        return (payload, Allows::parse_tag(tag));
    }
    (line.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mssql_sleep_renders_hhmmss_zero_padded() {
        assert_eq!(
            Dialect::Mssql.render_sleep(5).unwrap(),
            "WAITFOR DELAY '00:00:05'"
        );
        assert_eq!(
            Dialect::Mssql.render_sleep(75).unwrap(),
            "WAITFOR DELAY '00:01:15'"
        );
        assert_eq!(
            Dialect::Mssql.render_sleep(3600).unwrap(),
            "WAITFOR DELAY '01:00:00'"
        );
        // 24h+ rejected by SQL Server → None so the time channel skips it.
        assert!(Dialect::Mssql.render_sleep(86_400).is_none());
    }

    #[test]
    fn sqlite_has_no_safe_sleep() {
        assert!(Dialect::Sqlite.render_sleep(5).is_none());
    }

    #[test]
    fn oracle_has_no_safe_sleep() {
        assert!(Dialect::Oracle.render_sleep(5).is_none());
    }

    #[test]
    fn mysql_sleep_renders_plain_call() {
        assert_eq!(Dialect::MySql.render_sleep(5).unwrap(), "SLEEP(5)");
    }

    #[test]
    fn postgres_sleep_renders_plain_call() {
        assert_eq!(Dialect::Postgres.render_sleep(5).unwrap(), "pg_sleep(5)");
    }

    #[test]
    fn wordlist_tag_separator_is_two_spaces() {
        let (p, c) = parse_wordlist_payload("' OR 1=1-- -  #class:inline-comments");
        assert_eq!(p, "' OR 1=1-- -");
        assert_eq!(c, Some(Allows::InlineComments));
    }

    #[test]
    fn wordlist_in_sql_hash_not_a_tag() {
        let (p, c) = parse_wordlist_payload("' OR 1=1#");
        assert_eq!(p, "' OR 1=1#");
        assert_eq!(c, None);
    }

    #[test]
    fn baseline_threshold_includes_mean_sleep_and_stddev() {
        let b = Baseline {
            reply_shape: String::new(),
            rtt_mean: Duration::from_millis(300),
            rtt_stddev: Duration::from_millis(100),
            samples: 3,
        };
        // 0.3 + 5 + 3·0.1 = 5.6s
        let t = b.time_hit_threshold(5, 3.0);
        assert!((t.as_secs_f64() - 5.6).abs() < 1e-6);
    }
}
