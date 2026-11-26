//! Delivery of pushes from a relay to the push service (`docs/push.md` §5):
//! NOTIFY datagrams, re-sent until acknowledged or out of tries.

use std::collections::BTreeMap;

use avianlink_core::push::{encode_service, parse_service, AckCode, ServiceMsg};
use avianlink_core::wire::PushHandle;
use avianlink_core::Timestamp;

use crate::PushDue;

/// A NOTIFY not acknowledged in this long is sent again…
const RESEND_MS: u64 = 2_000;
/// …up to this many times in all. A lost push is only a delay.
const TRIES: u32 = 3;
/// NOTIFYs awaiting an ACK; beyond this the oldest is given up.
const MAX_IN_FLIGHT: usize = 4096;

#[derive(Debug)]
struct InFlight {
    handle: PushHandle,
    bytes: Vec<u8>,
    sent_at: Timestamp,
    tries: u32,
}

/// What the push service said about a push.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acked {
    /// The registration pushed to.
    pub handle: PushHandle,
    /// The outcome. On [`AckCode::Gone`], call [`crate::Relay::push_gone`].
    pub code: AckCode,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotifierStats {
    /// NOTIFYs sent, re-sends included.
    pub sent: u64,
    /// Acknowledged `OK`.
    pub ok: u64,
    /// Acknowledged with another code.
    pub refused: u64,
    /// Given up after every try.
    pub lost: u64,
}

/// Sends a relay's pushes to its push service, sans-IO.
#[derive(Debug, Default)]
pub struct Notifier {
    in_flight: BTreeMap<u64, InFlight>,
    out: Vec<Vec<u8>>,
    stats: NotifierStats,
}

impl Notifier {
    /// An idle notifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends `push`. `id` must be random: the ACK names the push by it, so
    /// it is all that stops a forged ACK deleting a handle.
    pub fn push(&mut self, push: PushDue, id: u64, now: Timestamp) {
        if self.in_flight.len() >= MAX_IN_FLIGHT {
            if let Some((&old, _)) = self.in_flight.iter().min_by_key(|(_, f)| f.sent_at) {
                self.in_flight.remove(&old);
                self.stats.lost += 1;
            }
        }
        let bytes = encode_service(&ServiceMsg::Notify {
            id,
            kind: push.kind,
            blob: push.blob,
        });
        self.out.push(bytes.clone());
        self.stats.sent += 1;
        self.in_flight.insert(
            id,
            InFlight {
                handle: push.handle,
                bytes,
                sent_at: now,
                tries: 1,
            },
        );
    }

    /// A datagram from the push service. `None` if it isn't an ACK of a
    /// push in flight.
    pub fn handle(&mut self, bytes: &[u8]) -> Option<Acked> {
        let Some(ServiceMsg::Ack { id, code }) = parse_service(bytes) else {
            return None;
        };
        let f = self.in_flight.remove(&id)?;
        if code == AckCode::Ok {
            self.stats.ok += 1;
        } else {
            self.stats.refused += 1;
        }
        Some(Acked {
            handle: f.handle,
            code,
        })
    }

    /// Re-sends what is overdue and gives up on what is out of tries.
    pub fn handle_timeout(&mut self, now: Timestamp) {
        let mut gone = Vec::new();
        for (id, f) in &mut self.in_flight {
            if f.sent_at.saturating_add_millis(RESEND_MS) > now {
                continue;
            }
            if f.tries >= TRIES {
                gone.push(*id);
            } else {
                f.tries += 1;
                f.sent_at = now;
                self.out.push(f.bytes.clone());
                self.stats.sent += 1;
            }
        }
        for id in gone {
            self.in_flight.remove(&id);
            self.stats.lost += 1;
        }
    }

    /// When [`Notifier::handle_timeout`] next has work.
    pub fn next_timeout(&self) -> Option<Timestamp> {
        self.in_flight
            .values()
            .map(|f| f.sent_at.saturating_add_millis(RESEND_MS))
            .min()
    }

    /// The next NOTIFY to send to the push service.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        (!self.out.is_empty()).then(|| self.out.remove(0))
    }

    /// Counters.
    pub fn stats(&self) -> NotifierStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use avianlink_core::push::PushKind;

    fn due() -> PushDue {
        PushDue {
            handle: [1; 8],
            kind: PushKind::Message,
            blob: vec![2; 40],
        }
    }

    fn ack(id: u64, code: AckCode) -> Vec<u8> {
        encode_service(&ServiceMsg::Ack { id, code })
    }

    #[test]
    fn resends_until_acked_or_out_of_tries() {
        let t = Timestamp::from_millis;
        let mut n = Notifier::new();
        n.push(due(), 7, t(0));
        let first = n.poll_transmit().unwrap();
        assert!(matches!(
            parse_service(&first),
            Some(ServiceMsg::Notify { id: 7, .. })
        ));
        n.handle_timeout(t(1_999));
        assert!(n.poll_transmit().is_none());
        n.handle_timeout(t(2_000));
        assert_eq!(n.poll_transmit(), Some(first.clone()));
        // A forged ACK (wrong id) changes nothing; the real one ends it.
        assert_eq!(n.handle(&ack(8, AckCode::Gone)), None);
        assert_eq!(
            n.handle(&ack(7, AckCode::Gone)),
            Some(Acked {
                handle: [1; 8],
                code: AckCode::Gone
            })
        );
        assert_eq!(n.next_timeout(), None);
        // Unanswered: three tries, then given up.
        n.push(due(), 9, t(10_000));
        for at in [12_000, 14_000, 16_000] {
            n.handle_timeout(t(at));
        }
        assert_eq!(std::iter::from_fn(|| n.poll_transmit()).count(), 3);
        assert_eq!(n.stats().lost, 1);
        assert_eq!(n.next_timeout(), None);
    }
}
