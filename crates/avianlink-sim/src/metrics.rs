//! Run metrics.

use std::fmt;

use avianlink_core::Stats;

use crate::impair::ChannelStats;
use crate::sim::total_channel_stats;

/// Nearest-rank percentile of sorted data; 0 if empty.
pub fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * sorted.len()).div_ceil(100).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// Outcome of one simulation run. Everything except `wall_ms` is a pure
/// function of the scenario.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    /// Scenario name.
    pub name: String,
    /// Master seed.
    pub seed: u64,
    /// Messages in the workload.
    pub messages: usize,
    /// Messages received by their recipient.
    pub delivered: usize,
    /// Messages whose sender saw the delivery ACK.
    pub acked: usize,
    /// Time from `send_text` to receipt, percentiles.
    pub latency_p50_ms: u64,
    /// See `latency_p50_ms`.
    pub latency_p95_ms: u64,
    /// See `latency_p50_ms`.
    pub latency_p99_ms: u64,
    /// Worst case.
    pub latency_max_ms: u64,
    /// Time from `send_text` to the sender's delivery event.
    pub ack_p50_ms: u64,
    /// See `ack_p50_ms`.
    pub ack_p95_ms: u64,
    /// UTF-8 bytes of delivered messages.
    pub payload_bytes: u64,
    /// Bytes both engines handed to the link.
    pub wire_bytes: u64,
    /// Packets both engines handed to the link.
    pub packets: u64,
    /// Simulated time until completion or deadline.
    pub sim_duration_ms: u64,
    /// Simulated link downtime within the run.
    pub downtime_ms: u64,
    /// Wall-clock time of the run.
    pub wall_ms: f64,
    /// Times an engine reported a due timeout yet sent nothing (bug).
    pub stalls: u64,
    /// `send_text` calls refused with `OutboxFull` and retried.
    pub outbox_full_retries: u64,
    /// Messages surfaced to the application more than once (bug).
    pub duplicate_deliveries: u64,
    /// Events with unknown IDs, wrong text, or wrong direction (bug).
    pub integrity_violations: u64,
    /// Messages that arrived before an earlier one from the same sender.
    pub out_of_order: u64,
    /// Simulated process crashes.
    pub crashes: u64,
    /// Packets injected or tampered with by the adversary.
    pub injected: u64,
    /// Bytes engines sent while a scheduled outage was in progress.
    pub outage_wire_bytes: u64,
    /// Packets engines sent while a scheduled outage was in progress.
    pub outage_packets: u64,
    /// Time from the end of the last scheduled outage until every message
    /// sent before then was delivered.
    pub converge_ms: Option<u64>,
    /// `MessagesSkipped` / `SyncDiverged` events (bug: no scenario loses or
    /// rolls back state).
    pub sync_anomalies: u64,
    /// Largest committed storage footprint of either node, in bytes.
    pub max_storage_bytes: usize,
    /// Per-direction channel counters (0: peer A → B).
    pub channels: [ChannelStats; 2],
    /// Per-peer engine counters.
    pub engines: [Stats; 2],
}

impl Report {
    /// Delivered / sent.
    pub fn delivery_ratio(&self) -> f64 {
        if self.messages == 0 {
            1.0
        } else {
            self.delivered as f64 / self.messages as f64
        }
    }

    /// Bytes on the wire per delivered payload byte.
    pub fn wire_per_payload(&self) -> f64 {
        self.wire_bytes as f64 / self.payload_bytes.max(1) as f64
    }

    /// Packets sent per message.
    pub fn packets_per_message(&self) -> f64 {
        self.packets as f64 / self.messages.max(1) as f64
    }

    /// Simulated hours per wall-clock minute.
    pub fn speed_hours_per_minute(&self) -> f64 {
        (self.sim_duration_ms as f64 / 3_600_000.0) / (self.wall_ms.max(0.001) / 60_000.0)
    }

    /// Whether any engine-correctness counter is non-zero.
    pub fn bugs(&self) -> u64 {
        let ch = total_channel_stats(&self.channels);
        let tx_stalls: u64 = self.engines.iter().map(|s| s.transmit_stalls).sum();
        tx_stalls
            + self.stalls
            + self.duplicate_deliveries
            + self.integrity_violations
            + self.sync_anomalies
            + ch.oversize
            + ch.duty_violations
    }

    /// The report with wall-clock time zeroed, for determinism checks.
    pub fn deterministic(&self) -> Self {
        Self {
            wall_ms: 0.0,
            ..self.clone()
        }
    }

    /// Markdown table header matching [`Report::table_row`].
    pub fn table_header() -> &'static str {
        "| scenario | seed | delivered | p50 | p95 | p99 | max | wire/payload | pkts/msg | sim time | sim h/wall min |\n\
         |---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|"
    }

    /// CSV header matching [`Report::csv_row`].
    pub fn csv_header() -> &'static str {
        "scenario,seed,messages,delivered,p50_ms,p95_ms,p99_ms,max_ms,payload_bytes,wire_bytes,packets,sim_ms"
    }

    /// One CSV row of raw values.
    pub fn csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            self.name,
            self.seed,
            self.messages,
            self.delivered,
            self.latency_p50_ms,
            self.latency_p95_ms,
            self.latency_p99_ms,
            self.latency_max_ms,
            self.payload_bytes,
            self.wire_bytes,
            self.packets,
            self.sim_duration_ms
        )
    }

    /// One Markdown table row.
    pub fn table_row(&self) -> String {
        format!(
            "| {} | {} | {}/{} | {} | {} | {} | {} | {:.2} | {:.2} | {} | {:.0} |",
            self.name,
            self.seed,
            self.delivered,
            self.messages,
            fmt_ms(self.latency_p50_ms),
            fmt_ms(self.latency_p95_ms),
            fmt_ms(self.latency_p99_ms),
            fmt_ms(self.latency_max_ms),
            self.wire_per_payload(),
            self.packets_per_message(),
            fmt_ms(self.sim_duration_ms),
            self.speed_hours_per_minute(),
        )
    }
}

/// Human-readable duration.
pub fn fmt_ms(ms: u64) -> String {
    match ms {
        0..=999 => format!("{ms}ms"),
        1_000..=59_999 => format!("{:.1}s", ms as f64 / 1e3),
        60_000..=3_599_999 => format!("{:.1}m", ms as f64 / 6e4),
        3_600_000..=86_399_999 => format!("{:.1}h", ms as f64 / 3.6e6),
        _ => format!("{:.1}d", ms as f64 / 8.64e7),
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ch = total_channel_stats(&self.channels);
        let e = |g: fn(&Stats) -> u64| g(&self.engines[0]) + g(&self.engines[1]);
        writeln!(f, "scenario {} (seed {})", self.name, self.seed)?;
        writeln!(
            f,
            "  delivered       {}/{} ({:.2}%), acked {}",
            self.delivered,
            self.messages,
            self.delivery_ratio() * 100.0,
            self.acked
        )?;
        writeln!(
            f,
            "  latency         p50 {}  p95 {}  p99 {}  max {}",
            fmt_ms(self.latency_p50_ms),
            fmt_ms(self.latency_p95_ms),
            fmt_ms(self.latency_p99_ms),
            fmt_ms(self.latency_max_ms)
        )?;
        writeln!(
            f,
            "  ack latency     p50 {}  p95 {}",
            fmt_ms(self.ack_p50_ms),
            fmt_ms(self.ack_p95_ms)
        )?;
        writeln!(
            f,
            "  efficiency      {:.2} wire bytes/payload byte, {:.2} packets/message",
            self.wire_per_payload(),
            self.packets_per_message()
        )?;
        writeln!(
            f,
            "  link            sent {} lost {} outage {} queue {} corrupted {} dup {}",
            ch.sent, ch.lost, ch.lost_outage, ch.lost_queue, ch.corrupted, ch.duplicated
        )?;
        writeln!(
            f,
            "  engine          retx {} probes {} acks {} frag-acks {} rtt-samples {} unauth-drops {} replay-drops {} dup-msgs {} reasm-full {} storage-errors {}",
            e(|s| s.retransmissions),
            e(|s| s.probes_sent),
            e(|s| s.acks_sent),
            e(|s| s.frag_acks_sent),
            e(|s| s.rtt_samples),
            e(|s| s.packets_dropped_unauthenticated),
            e(|s| s.packets_dropped_replay),
            e(|s| s.messages_duplicate),
            e(|s| s.fragments_dropped_reassembly_full),
            e(|s| s.storage_errors)
        )?;
        writeln!(
            f,
            "  fec             sources {} repairs-sent {} repairs-dropped {} repairs-received {} recovered {} loss-reports {}",
            e(|s| s.fec_sources),
            e(|s| s.fec_repairs_sent),
            e(|s| s.fec_repairs_dropped),
            e(|s| s.fec_repairs_received),
            e(|s| s.fec_recovered),
            e(|s| s.loss_reports_sent)
        )?;
        writeln!(
            f,
            "  host            crashes {}, adversary packets {}, out-of-order arrivals {}, max storage {} B, outbox-full retries {}",
            self.crashes, self.injected, self.out_of_order, self.max_storage_bytes, self.outbox_full_retries
        )?;
        if let Some(c) = self.converge_ms {
            writeln!(
                f,
                "  long outage     {} packets / {} B sent while down; converged {} after it ended; syncs sent {}",
                self.outage_packets,
                self.outage_wire_bytes,
                fmt_ms(c),
                e(|s| s.syncs_sent)
            )?;
        }
        writeln!(
            f,
            "  time            sim {} (down {}), wall {:.0} ms, {:.0} sim-hours/wall-minute",
            fmt_ms(self.sim_duration_ms),
            fmt_ms(self.downtime_ms),
            self.wall_ms,
            self.speed_hours_per_minute()
        )?;
        write!(
            f,
            "  bugs            {} (stalls {}, oversize {}, duty {}, dup-deliveries {}, integrity {})",
            self.bugs(),
            self.stalls,
            ch.oversize,
            ch.duty_violations,
            self.duplicate_deliveries,
            self.integrity_violations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&v, 50), 50);
        assert_eq!(percentile(&v, 99), 99);
        assert_eq!(percentile(&[7], 99), 7);
        assert_eq!(percentile(&[], 50), 0);
    }
}
