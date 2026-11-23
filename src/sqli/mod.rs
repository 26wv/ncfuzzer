//! SQL-injection scan mode. Reuses `net::connect_and_sync` / `net::attempt`
//! for socket work; does not go through the standard matcher path.
//!
//! Ownership:
//!   mod.rs, types.rs, baseline.rs, runner.rs  — skeleton (Phase 0)
//!   errors.rs                                 — error channel
//!   boolean.rs                                — boolean-diff + union canary
//!   time.rs, fingerprint.rs                   — time channel + filter-bypass classes
//!   output.rs                                 — hits formatter
//!
//! Framing / response-boundary / reconnect are the engine's existing concern;
//! we take `Framing` as-is from `main`.

pub mod baseline;
pub mod boolean;
pub mod errors;
pub mod fingerprint;
pub mod output;
pub mod runner;
pub mod time;
pub mod types;

pub use runner::{run, RunArgs};
pub use types::SqliConfig;
