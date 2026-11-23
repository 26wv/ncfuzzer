use regex::Regex;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum Prompt {
    Literal(String),
    Regex(Regex),
}

#[derive(Clone, Debug)]
pub enum BannerSync {
    SkipLines(u32),
    MatchRegex(Regex),
}

#[derive(Clone, Debug)]
pub struct Framing {
    /// Payload template sent per attempt. Contains the keyword `FUZZ`,
    /// replaced by each wordlist entry. Default: just `FUZZ`.
    pub send_template: String,
    /// Line terminator appended to the sent payload.
    pub eol: String,
    /// Response boundary. None => read one line (until `\n`).
    /// Some => read until the prompt reappears.
    pub prompt: Option<Prompt>,
    /// How to consume the initial banner before the first attempt.
    pub banner: BannerSync,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub wordlist: PathBuf,
    pub concurrency: usize,
    pub rate: u64,
    pub timeout_secs: u64,
    /// Formatted hits-report file (`-o`). Additive — stdout still gets the plain stream.
    pub report: Option<PathBuf>,
    pub json: bool,
    /// 0 silent, 1 = log hits, 2 = log every attempt (stderr only).
    pub verbose: u8,
    pub framing: Framing,
}

/// One classified attempt. `word` is the raw wordlist entry; `payload`
/// is the templated line (FUZZ substituted); `sent` is exactly the bytes
/// written to the socket (payload + eol); `response` is the normalised
/// server answer.
#[derive(Debug, Clone)]
pub struct Event {
    pub is_hit: bool,
    pub word: String,
    pub payload: String,
    pub sent: String,
    pub response: String,
}

pub type EventSender = tokio::sync::mpsc::Sender<Event>;
pub type EventReceiver = tokio::sync::mpsc::Receiver<Event>;
