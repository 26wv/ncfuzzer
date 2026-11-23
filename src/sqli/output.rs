//! Output formatter for sqli-mode hits. Obeys the existing stream split:
//!   - stdout: grouped `HITS:` block (pretty) or one JSON line per hit (`-j`)
//!   - -o PATH: the full pretty report, prefixed with `HITS:\n`
//!
//! Output shape — per spec, built-in probes and `{SLEEP}` wordlist lines emit
//! a wrapper-form hit; arbitrary wordlist lines print the raw line fired +
//! its channel + proof, NO fabricated wrapper.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use tokio::io::{AsyncWriteExt, BufWriter};

use super::types::{Channel, Verdict};

/// Render verdicts to stdout (and the report file if given). `verbose` is the
/// same 0/1/2 scale the engine uses.
pub async fn write(
    verdicts: &[Verdict],
    report: Option<&Path>,
    json: bool,
    verbose: u8,
) -> Result<()> {
    let stdout_body = if json {
        render_json_lines(verdicts)
    } else {
        render_pretty(verdicts, verbose)
    };

    // Write stdout first, but keep going on broken-pipe so -o still lands.
    let stdout_err = {
        let mut out = tokio::io::stdout();
        match out.write_all(stdout_body.as_bytes()).await {
            Ok(()) => out.flush().await,
            Err(e) => Err(e),
        }
    };

    if let Some(path) = report {
        let f = tokio::fs::File::create(path).await?;
        let mut w = BufWriter::new(f);
        w.write_all(render_report(verdicts, verbose).as_bytes())
            .await?;
        w.flush().await?;
    }

    if let Err(e) = stdout_err {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }
    Ok(())
}

/// Channel precedence for stable grouping: Error, Union, Boolean, Time, Raw.
fn channel_rank(c: Channel) -> u8 {
    match c {
        Channel::Error => 0,
        Channel::Union => 1,
        Channel::Boolean => 2,
        Channel::Time => 3,
        Channel::Raw => 4,
        Channel::Shape => 5,
    }
}

fn sorted_refs(verdicts: &[Verdict]) -> Vec<&Verdict> {
    let mut v: Vec<&Verdict> = verdicts.iter().collect();
    v.sort_by_key(|x| channel_rank(x.channel));
    v
}

/// Continuation-line indent: 2-space block indent + 10-char tag field + 1 space.
const CONT: &str = "             ";

fn push_entry(out: &mut String, v: &Verdict, verbose: u8) {
    let tag_field = format!("[{}]", v.channel.tag());
    // First line: tag + either `engine:` (if present) or wrapper/payload.
    let (label, value) = match &v.wrapper {
        Some(w) => ("wrapper", w.as_str()),
        None => ("payload", v.payload.as_str()),
    };
    match v.engine {
        Some(engine) => {
            let _ = writeln!(out, "  {:<10} engine: {}", tag_field, engine.name());
            let _ = writeln!(out, "{CONT}{label}: {value}");
        }
        None => {
            let _ = writeln!(out, "  {:<10} {label}: {value}", tag_field);
        }
    }
    // proof: padded 3 spaces so its value aligns with wrapper:/payload: values.
    let _ = writeln!(out, "{CONT}proof:   {}", v.proof);
    if !v.allows.is_empty() {
        let labels: Vec<&str> = v.allows.iter().map(|a| a.label()).collect();
        let _ = writeln!(out, "{CONT}appears to allow: {}", labels.join(", "));
    }
    // -vv shows the rendered payload only when the first line used `wrapper:`
    // (raw verdicts already printed `payload:` and would double-print).
    if verbose >= 2 && v.wrapper.is_some() {
        let _ = writeln!(out, "  payload: {}", v.payload);
    }
}

/// Pretty-form stdout block. Empty-verdict case still prints a single line so
/// a quiet exit isn't ambiguous.
pub(crate) fn render_pretty(verdicts: &[Verdict], verbose: u8) -> String {
    if verdicts.is_empty() {
        return "No injection points detected.\n".to_string();
    }
    let mut s = String::from("HITS:\n");
    for v in sorted_refs(verdicts) {
        push_entry(&mut s, v, verbose);
    }
    s
}

/// Same pretty form as stdout but with the file-report header.
fn render_report(verdicts: &[Verdict], verbose: u8) -> String {
    let mut s = String::from("HITS:\n");
    if !verdicts.is_empty() {
        for v in sorted_refs(verdicts) {
            push_entry(&mut s, v, verbose);
        }
    }
    s
}

/// One JSON object per verdict, newline-terminated. Empty → empty string.
pub(crate) fn render_json_lines(verdicts: &[Verdict]) -> String {
    let mut s = String::new();
    for v in sorted_refs(verdicts) {
        let allows: Vec<&str> = v.allows.iter().map(|a| a.label()).collect();
        let obj = serde_json::json!({
            "channel": v.channel.tag(),
            "engine": v.engine.map(|d| d.name()),
            "wrapper": v.wrapper,
            "payload": v.payload,
            "proof": v.proof,
            "allows": allows,
        });
        let _ = writeln!(s, "{obj}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqli::types::{Allows, Dialect};

    fn v_error() -> Verdict {
        Verdict {
            channel: Channel::Error,
            wrapper: Some("'<payload>".into()),
            payload: "'".into(),
            proof: "'                 (matched \"SQL syntax\" error)".into(),
            engine: Some(Dialect::MySql),
            allows: vec![Allows::MixedCase, Allows::InlineComments],
        }
    }

    fn v_boolean() -> Verdict {
        Verdict {
            channel: Channel::Boolean,
            wrapper: Some("' OR <payload>-- -".into()),
            payload: "' OR 1=1-- -".into(),
            proof: "' AND 1=1 vs ' AND 1=2   (replies differed, 2/2)".into(),
            engine: None,
            allows: vec![],
        }
    }

    fn v_time() -> Verdict {
        Verdict {
            channel: Channel::Time,
            wrapper: Some("' OR {SLEEP}-- -".into()),
            payload: "' OR SLEEP(5)-- -".into(),
            proof: "' OR SLEEP(5)-- -  (6.1s vs 0.3s baseline, 2/2)".into(),
            engine: None,
            allows: vec![],
        }
    }

    fn v_union() -> Verdict {
        Verdict {
            channel: Channel::Union,
            wrapper: Some("' UNION SELECT <payload>-- -".into()),
            payload: "' UNION SELECT NULL,NULL-- -".into(),
            proof: "canary echoed in column 2".into(),
            engine: None,
            allows: vec![],
        }
    }

    fn v_raw() -> Verdict {
        Verdict {
            channel: Channel::Raw,
            wrapper: None,
            payload: "admin') or ('1'='1".into(),
            proof: "reply differed from baseline".into(),
            engine: None,
            allows: vec![],
        }
    }

    #[test]
    fn pretty_contains_expected_lines() {
        let out = render_pretty(&[v_error(), v_boolean(), v_time(), v_raw()], 0);
        assert!(out.starts_with("HITS:\n"));
        assert!(out.contains("[error]"));
        assert!(out.contains("engine: MySQL/MariaDB"));
        assert!(out.contains("wrapper: '<payload>"));
        assert!(out.contains("proof:   '"));
        assert!(out.contains("appears to allow: mixed-case keywords, inline comments"));
        assert!(out.contains("[boolean]"));
        assert!(out.contains("[time]"));
        assert!(out.contains("[raw]"));
        assert!(out.contains("payload: admin') or ('1'='1"));
    }

    #[test]
    fn json_lines_parse_and_have_expected_keys() {
        let s = render_json_lines(&[v_error(), v_raw()]);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let obj: serde_json::Value = serde_json::from_str(line).unwrap();
            for key in ["channel", "engine", "wrapper", "payload", "proof", "allows"] {
                assert!(obj.get(key).is_some(), "missing key {key} in {line}");
            }
        }
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["channel"], "error");
        assert_eq!(first["engine"], "MySQL/MariaDB");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert!(second["wrapper"].is_null());
        assert!(second["engine"].is_null());
    }

    #[test]
    fn empty_pretty_is_fixed_string_and_empty_json_is_empty() {
        assert_eq!(render_pretty(&[], 0), "No injection points detected.\n");
        assert_eq!(render_json_lines(&[]), "");
    }

    #[test]
    fn channels_group_in_precedence_order() {
        // Feed in reverse to prove sorting, not input order, drives output.
        let out = render_pretty(&[v_raw(), v_time(), v_boolean(), v_union(), v_error()], 0);
        let ie = out.find("[error]").unwrap();
        let iu = out.find("[union]").unwrap();
        let ib = out.find("[boolean]").unwrap();
        let it = out.find("[time]").unwrap();
        let ir = out.find("[raw]").unwrap();
        assert!(ie < iu && iu < ib && ib < it && it < ir);
    }

    #[test]
    fn verbose_two_appends_payload_line() {
        let out = render_pretty(&[v_boolean()], 2);
        // The extra -vv payload line, with its documented 2-space prefix.
        assert!(out.contains("\n  payload: ' OR 1=1-- -\n"));
    }
}
