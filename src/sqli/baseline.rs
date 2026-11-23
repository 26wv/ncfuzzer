use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::common::Framing;
use crate::net::{attempt, connect_and_sync, Conn};
use crate::oracle::normalise;

use super::types::Baseline;

/// Open one connection, send `samples` neutral random tokens, record the
/// normalised reply shape and per-attempt RTT. Returns the baseline plus the
/// still-open connection so the caller (e.g. the boolean channel needing
/// connection affinity) can reuse this exact socket.
pub async fn calibrate(
    host: &str,
    port: u16,
    timeout_secs: u64,
    framing: &Framing,
    samples: u32,
) -> Result<(Baseline, Conn)> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());

    let mut conn = connect_and_sync(host, port, timeout_secs, framing).await?;
    let mut shape: Option<String> = None;
    let mut rtts: Vec<Duration> = Vec::with_capacity(samples as usize);

    for i in 0..samples {
        let probe = format!("ncf_sqli_baseline_{i:x}_{nanos:x}");
        let templated = framing.send_template.replace("FUZZ", &probe);
        let t0 = Instant::now();
        let raw = attempt(&mut conn, framing, &templated, timeout_secs).await?;
        rtts.push(t0.elapsed());
        let n = normalise(&raw, framing, &templated);
        if shape.is_none() {
            shape = Some(n);
        }
    }

    let n = samples.max(1) as f64;
    let mean_s: f64 = rtts.iter().map(|d| d.as_secs_f64()).sum::<f64>() / n;
    let var_s: f64 = rtts
        .iter()
        .map(|d| {
            let x = d.as_secs_f64() - mean_s;
            x * x
        })
        .sum::<f64>()
        / n;
    let stddev_s = var_s.sqrt();

    Ok((
        Baseline {
            reply_shape: shape.unwrap_or_default(),
            rtt_mean: Duration::from_secs_f64(mean_s.max(0.0)),
            rtt_stddev: Duration::from_secs_f64(stddev_s.max(0.0)),
            samples,
        },
        conn,
    ))
}
