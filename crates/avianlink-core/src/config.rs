use crate::wire::{frame_space, plan_fragments};
use crate::{Error, MIN_MTU};

/// Engine-wide limits and timers. Every queue and table in the engine is
/// bounded by one of these; each field documents what happens at the limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Maximum registered links. Beyond: `add_link` returns
    /// [`Error::TooManyLinks`].
    pub max_links: u16,
    /// Maximum contacts. Beyond: `add_contact` returns
    /// [`Error::TooManyContacts`].
    pub max_contacts: u32,
    /// Maximum undelivered outgoing messages, across all conversations.
    /// Beyond: `send_text` returns [`Error::OutboxFull`].
    pub max_outbox_messages: u32,
    /// Maximum queued events. When full, inbound messages are dropped
    /// unacknowledged (the peer retransmits) and incoming ACKs are left
    /// unprocessed until the host drains events.
    pub max_pending_events: u32,
    /// Maximum UTF-8 bytes in one message. Beyond: `send_text` returns
    /// [`Error::TextTooLong`]; inbound records with longer text are dropped.
    pub max_text_len: u32,
    /// Maximum fragments per message, both sent and accepted.
    pub max_fragments: u32,
    /// Memory budget for partially reassembled messages. When full, the
    /// least recently updated partials are evicted (wire-format §3.1).
    pub max_reassembly_bytes: u32,
    /// Receive window: seqs at or beyond `cum + window` are dropped
    /// unacknowledged.
    pub max_reorder_window: u32,
    /// Largest ACK bitmap sent, in bytes (8 seqs per byte).
    pub max_ack_bitmap_bytes: u16,
    /// Duty-cycle log entries per link. When full, the link is out of
    /// budget until the oldest entry ages out.
    pub max_duty_log_entries: u32,
    /// Retransmission timeout before the first RTT sample.
    pub initial_rto_ms: u64,
    /// Lower bound on the adaptive retransmission timeout.
    pub min_rto_ms: u64,
    /// Upper bound on the retransmission timeout and on the backoff probe
    /// interval: an unreachable peer is probed at least this often, forever,
    /// unless the link's budget demands slower probing
    /// (`docs/reliability.md` §3).
    pub max_rto_ms: u64,
    /// RTO = SRTT + this × RTTVAR. RFC 6298 uses 4; the default 2 suits
    /// heavy-tailed delay, where 4 inflates the RTO toward its cap (D-028).
    pub rttvar_multiplier: u8,
    /// Probes to an unreachable peer sent at the plain RTO before the
    /// interval starts doubling.
    pub backoff_grace: u8,
    /// Packet send times remembered per contact for RTT sampling. ACKs for
    /// older packets yield no sample.
    pub max_sent_log: u16,
    /// FRAG_ACK frames per packet, at most.
    pub max_frag_acks_per_packet: u8,
    /// Packet counters reserved in storage per write; a restored engine
    /// skips to the reservation, so counters never repeat.
    pub counter_reservation: u32,
    /// How long an ACK may wait for a data packet to piggyback on.
    pub ack_delay_ms: u64,
    /// Whether `now` is Unix-epoch wall-clock time. If false, messages carry
    /// no timestamp.
    pub wall_clock: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_links: 8,
            max_contacts: 256,
            max_outbox_messages: 1024,
            max_pending_events: 256,
            max_text_len: 4096,
            max_fragments: 256,
            max_reassembly_bytes: 64 * 1024,
            max_reorder_window: 4096,
            max_ack_bitmap_bytes: 32,
            max_duty_log_entries: 1024,
            initial_rto_ms: 3_000,
            min_rto_ms: 1_000,
            max_rto_ms: 30_000,
            rttvar_multiplier: 2,
            backoff_grace: 2,
            max_sent_log: 256,
            max_frag_acks_per_packet: 2,
            counter_reservation: 1024,
            ack_delay_ms: 100,
            wall_clock: true,
        }
    }
}

/// Room for record fields other than the text: flags, Lamport, timestamp,
/// and modest extension blocks from future peers.
pub(crate) const RECORD_OVERHEAD: u32 = 256;

impl Config {
    /// Checks the limits are usable together: in particular that a
    /// maximum-length message fits in `max_fragments` at [`MIN_MTU`].
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_links == 0
            || self.max_contacts == 0
            || self.max_pending_events == 0
            || self.max_fragments == 0
            || self.max_reorder_window == 0
            || self.max_duty_log_entries == 0
            || self.min_rto_ms == 0
            || self.min_rto_ms > self.max_rto_ms
            || self.initial_rto_ms == 0
            || self.max_sent_log == 0
            || self.counter_reservation == 0
        {
            return Err(Error::InvalidConfig);
        }
        let worst_record =
            usize::try_from(self.max_record_len()).map_err(|_| Error::InvalidConfig)?;
        let plan = plan_fragments(frame_space(usize::from(MIN_MTU)), u64::MAX, worst_record)
            .ok_or(Error::InvalidConfig)?;
        if plan.count > u64::from(self.max_fragments) {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }

    pub(crate) fn max_record_len(&self) -> u32 {
        self.max_text_len.saturating_add(RECORD_OVERHEAD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert_eq!(Config::default().validate(), Ok(()));
    }

    #[test]
    fn rejects_unfragmentable_text() {
        let c = Config {
            max_fragments: 4,
            ..Config::default()
        };
        assert_eq!(c.validate(), Err(Error::InvalidConfig));
    }
}
