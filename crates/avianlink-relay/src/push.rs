//! The relay's side of push notifications (`docs/push.md` §4).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use avianlink_core::hashes::hello_hint;
use avianlink_core::push::{self, PushKind};
use avianlink_core::wire::{
    self, ChainRole, PairTag, Proof, PushHandle, Reader, ReceiptHash, RelayCode, PUSH_DETECT_LEN,
    PUSH_SECRET_LEN, RELAY_PUSH_BIND, RELAY_PUSH_BIND_HELLO, RELAY_PUSH_REGISTER,
};
use avianlink_core::{PublicKey, Storage, Timestamp};

use super::{key, Ops, Relay, RelayError};

// Storage keys: "P" handle → registration; "b" mailbox id, handle → ().
const P_HANDLE: &[u8] = b"P";
const P_BINDING: &[u8] = b"b";

/// Notes held for a Hello that hasn't arrived yet.
const MAX_NOTES: usize = 65_536;
const NOTE_MS: u64 = 600_000;

/// A push for the host to hand to the push service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushDue {
    /// The registration's handle; pass it to [`Relay::push_gone`] if the
    /// push service says the token is dead.
    pub handle: PushHandle,
    /// What arrived.
    pub kind: PushKind,
    /// The sealed registration.
    pub blob: Vec<u8>,
}

/// Whether an upload session's packets are worth a push.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SessionPush {
    /// A PUSH_NOTE arrived before any packet it covers.
    noted: bool,
    /// Packets were stored since the last push for this session.
    unpushed: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Handle {
    blob: Vec<u8>,
    active: Timestamp,
    hello_key: Option<PublicKey>,
    last_push: Option<Timestamp>,
    pending: Option<PushKind>,
}

impl Handle {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.blob.len() + 44);
        wire::put_varint(&mut v, self.active.as_millis());
        match &self.hello_key {
            Some(k) => {
                v.push(1);
                v.extend_from_slice(&k.0);
            }
            None => v.push(0),
        }
        v.extend_from_slice(&self.blob);
        v
    }

    fn decode(v: &[u8]) -> Option<Self> {
        let mut r = Reader::new(v);
        let active = Timestamp::from_millis(r.varint().ok()?);
        let hello_key = match r.u8().ok()? {
            0 => None,
            1 => Some(PublicKey(r.array().ok()?)),
            _ => return None,
        };
        Some(Self {
            blob: r.rest().to_vec(),
            active,
            hello_key,
            last_push: None,
            pending: None,
        })
    }
}

/// Push state, part of [`Relay`].
#[derive(Debug, Default)]
pub(crate) struct PushState {
    handles: BTreeMap<PushHandle, Handle>,
    /// Mailbox id → handles bound to it.
    by_mailbox: BTreeMap<u64, BTreeSet<PushHandle>>,
    /// Handle → mailbox ids it is bound to.
    by_handle: BTreeMap<PushHandle, BTreeSet<u64>>,
    /// Recipient hash → handles whose Hellos are bound.
    by_detect: BTreeMap<[u8; PUSH_DETECT_LEN], BTreeSet<PushHandle>>,
    /// HELLO_NOTEs waiting for their Hello: hash → recipient hash.
    notes: BTreeMap<ReceiptHash, [u8; PUSH_DETECT_LEN]>,
    notes_order: VecDeque<(ReceiptHash, Timestamp)>,
    out: VecDeque<PushDue>,
}

fn handle_key(h: &PushHandle) -> Vec<u8> {
    key(P_HANDLE, &[h])
}

fn binding_key(id: u64, h: &PushHandle) -> Vec<u8> {
    key(P_BINDING, &[&id.to_be_bytes(), h])
}

fn reply_key(h: &PushHandle) -> PairTag {
    [h[0], h[1], h[2]]
}

impl<S: Storage, A: Ord + Copy> Relay<S, A> {
    /// Loads handles and bindings (part of [`Relay::open`]).
    pub(crate) fn load_push(&mut self) -> Result<(), RelayError> {
        let mut bad = false;
        let mut handles = Vec::new();
        self.storage
            .scan_prefix(P_HANDLE, &mut |k, v| {
                let h = k.get(1..).and_then(|b| PushHandle::try_from(b).ok());
                match (h, Handle::decode(v)) {
                    (Some(h), Some(r)) => handles.push((h, r)),
                    _ => bad = true,
                }
            })
            .map_err(|_| RelayError::Storage)?;
        let mut bindings = Vec::new();
        self.storage
            .scan_prefix(P_BINDING, &mut |k, _| {
                let id = k.get(1..9).and_then(|b| <[u8; 8]>::try_from(b).ok());
                let h = k.get(9..).and_then(|b| PushHandle::try_from(b).ok());
                match (id, h) {
                    (Some(id), Some(h)) => bindings.push((u64::from_be_bytes(id), h)),
                    _ => bad = true,
                }
            })
            .map_err(|_| RelayError::Storage)?;
        if bad {
            return Err(RelayError::Storage);
        }
        for (h, r) in handles {
            if let Some(k) = &r.hello_key {
                self.push
                    .by_detect
                    .entry(push::detect(k))
                    .or_default()
                    .insert(h);
            }
            self.push.handles.insert(h, r);
        }
        for (id, h) in bindings {
            if !self.push.handles.contains_key(&h) || !self.mailboxes.contains_key(&id) {
                return Err(RelayError::Storage);
            }
            self.push.by_mailbox.entry(id).or_default().insert(h);
            self.push.by_handle.entry(h).or_default().insert(id);
        }
        Ok(())
    }

    /// The next push for the push service.
    pub fn poll_push(&mut self) -> Option<PushDue> {
        self.push.out.pop_front()
    }

    /// The push service says `handle`'s token is dead: forget it.
    pub fn push_gone(&mut self, handle: &PushHandle) {
        self.delete_handle(handle);
    }

    /// Push registrations held.
    pub fn push_handle_count(&self) -> usize {
        self.push.handles.len()
    }

    pub(crate) fn push_register(&mut self, from: A, secret: [u8; PUSH_SECRET_LEN], blob: Vec<u8>) {
        let h = push::handle(&secret);
        let rk = reply_key(&h);
        if !self.config.push {
            return self.reply(from, RELAY_PUSH_REGISTER, RelayCode::Full, rk, 0);
        }
        if !self.allow(from) {
            return self.reply(from, RELAY_PUSH_REGISTER, RelayCode::RateLimited, rk, 0);
        }
        if blob.is_empty() {
            self.delete_handle(&h);
            return self.reply(from, RELAY_PUSH_REGISTER, RelayCode::Ok, rk, 0);
        }
        let existed = self.push.handles.contains_key(&h);
        if !existed && self.push.handles.len() >= self.config.max_push_handles as usize {
            return self.reply(from, RELAY_PUSH_REGISTER, RelayCode::Full, rk, 0);
        }
        let now = self.now;
        let mut r = self.push.handles.get(&h).cloned().unwrap_or(Handle {
            blob: Vec::new(),
            active: now,
            hello_key: None,
            last_push: None,
            pending: None,
        });
        r.blob = blob;
        r.active = now;
        if !self.commit(vec![(handle_key(&h), Some(r.encode()))]) {
            return self.reply(from, RELAY_PUSH_REGISTER, RelayCode::Full, rk, 0);
        }
        self.push.handles.insert(h, r);
        self.stats.push_registrations += 1;
        self.reply(
            from,
            RELAY_PUSH_REGISTER,
            RelayCode::Ok,
            rk,
            u64::from(existed),
        );
    }

    pub(crate) fn push_bind(&mut self, from: A, tag: PairTag, proof: Proof, h: PushHandle) {
        if !self.config.push {
            return self.reply(from, RELAY_PUSH_BIND, RelayCode::Full, tag, 0);
        }
        if !self.allow(from) {
            return self.reply(from, RELAY_PUSH_BIND, RelayCode::RateLimited, tag, 0);
        }
        if !self.push.handles.contains_key(&h) {
            return self.reply(from, RELAY_PUSH_BIND, RelayCode::UnknownMailbox, tag, 0);
        }
        let id = match self.prove(tag, ChainRole::Down, &proof) {
            Ok(id) => id,
            Err(code) => return self.reply(from, RELAY_PUSH_BIND, code, tag, 0),
        };
        let bound = self.push.by_handle.get(&h);
        if bound.is_some_and(|b| b.contains(&id)) {
            return self.reply(from, RELAY_PUSH_BIND, RelayCode::Ok, tag, 0);
        }
        if bound.map_or(0, BTreeSet::len) >= self.config.max_push_bindings as usize {
            return self.reply(from, RELAY_PUSH_BIND, RelayCode::Full, tag, 0);
        }
        if !self.commit(vec![(binding_key(id, &h), Some(Vec::new()))]) {
            return self.reply(from, RELAY_PUSH_BIND, RelayCode::Full, tag, 0);
        }
        self.push.by_mailbox.entry(id).or_default().insert(h);
        self.push.by_handle.entry(h).or_default().insert(id);
        self.reply(from, RELAY_PUSH_BIND, RelayCode::Ok, tag, 0);
    }

    pub(crate) fn push_bind_hello(
        &mut self,
        from: A,
        key_bytes: [u8; 32],
        h: PushHandle,
        on: bool,
        sig: [u8; 64],
    ) {
        let rk = reply_key(&h);
        if !self.config.push {
            return self.reply(from, RELAY_PUSH_BIND_HELLO, RelayCode::Full, rk, 0);
        }
        // A signature check costs more than a proof: two tokens.
        if !self.allow(from) || !self.allow(from) {
            return self.reply(from, RELAY_PUSH_BIND_HELLO, RelayCode::RateLimited, rk, 0);
        }
        let Some(mut r) = self.push.handles.get(&h).cloned() else {
            return self.reply(
                from,
                RELAY_PUSH_BIND_HELLO,
                RelayCode::UnknownMailbox,
                rk,
                0,
            );
        };
        let pk = PublicKey(key_bytes);
        if !push::verify_hello_binding(&pk, &h, on, &sig) {
            self.stats.bad_proofs += 1;
            return self.reply(from, RELAY_PUSH_BIND_HELLO, RelayCode::BadProof, rk, 0);
        }
        let old = r.hello_key.take();
        r.hello_key = on.then_some(pk);
        if !self.commit(vec![(handle_key(&h), Some(r.encode()))]) {
            return self.reply(from, RELAY_PUSH_BIND_HELLO, RelayCode::Full, rk, 0);
        }
        if let Some(old) = old {
            self.unindex_detect(&push::detect(&old), &h);
        }
        if on {
            self.push
                .by_detect
                .entry(push::detect(&pk))
                .or_default()
                .insert(h);
        }
        self.push.handles.insert(h, r);
        self.reply(from, RELAY_PUSH_BIND_HELLO, RelayCode::Ok, rk, 0);
    }

    pub(crate) fn hello_note(&mut self, hash: ReceiptHash, detect: [u8; PUSH_DETECT_LEN]) {
        if !self.push.by_detect.contains_key(&detect) {
            return; // Nobody here wants pushes for this recipient.
        }
        if self.match_hello(&hash, &detect) {
            return;
        }
        if self.push.notes.len() >= MAX_NOTES {
            if let Some((old, _)) = self.push.notes_order.pop_front() {
                self.push.notes.remove(&old);
            }
        }
        if self.push.notes.insert(hash, detect).is_none() {
            self.push.notes_order.push_back((hash, self.now));
        }
    }

    /// A Hello was stored: push if a note for it already arrived.
    pub(crate) fn hello_stored(&mut self, hash: &ReceiptHash) {
        if let Some(detect) = self.push.notes.get(hash).copied() {
            if self.match_hello(hash, &detect) {
                self.push.notes.remove(hash);
            }
        }
    }

    /// A packet from `from` was stored in mailbox `id` through the
    /// session for `tag`. It pushes only if a PUSH_NOTE says the session
    /// carries a message: ACKs alone never wake anyone.
    pub(crate) fn packet_stored(&mut self, from: A, tag: PairTag, id: u64, live: bool) {
        if !self.push.by_mailbox.contains_key(&id) {
            return;
        }
        let s = self.session_push.entry((from, tag)).or_default();
        if s.noted {
            *s = SessionPush::default();
            self.push_mailbox(id, live);
        } else {
            s.unpushed = true;
        }
    }

    /// PUSH_NOTE: the uploads in `from`'s session for `tag` carry a
    /// message. Pushes for what is already stored, or for the next packet.
    pub(crate) fn push_note(&mut self, from: A, tag: PairTag) {
        let now = self.now;
        let Some(id) = self
            .sessions
            .get(&(from, tag))
            .filter(|(_, until)| *until > now)
            .map(|(id, _)| *id)
        else {
            return;
        };
        if !self.push.by_mailbox.contains_key(&id) {
            return;
        }
        let s = self.session_push.entry((from, tag)).or_default();
        if s.unpushed {
            *s = SessionPush::default();
            let live = self.leases.get(&id).is_some_and(|(_, until)| *until > now);
            self.push_mailbox(id, live);
        } else {
            s.noted = true;
        }
    }

    fn push_mailbox(&mut self, id: u64, live: bool) {
        if live {
            return; // Its owner is fetching, and got it at once.
        }
        let handles: Vec<PushHandle> = self
            .push
            .by_mailbox
            .get(&id)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        for h in handles {
            self.push_due(h, PushKind::Message);
        }
    }

    /// Pushes to every handle bound to the Hello's recipient whose hint
    /// matches a stored Hello with this hash. Whether one matched.
    fn match_hello(&mut self, hash: &ReceiptHash, detect: &[u8; PUSH_DETECT_LEN]) -> bool {
        let Some(handles) = self.push.by_detect.get(detect).cloned() else {
            return false;
        };
        let mut matched = false;
        for h in handles {
            let Some(hint) = self
                .push
                .handles
                .get(&h)
                .and_then(|r| r.hello_key.as_ref())
                .map(hello_hint)
            else {
                continue;
            };
            if !self
                .hellos
                .get(&hint)
                .is_some_and(|b| b.hashes.contains(hash))
            {
                continue;
            }
            matched = true;
            // Online and fetching: the Hello was forwarded to it at once.
            if !self.hello_lease_live(&hint) {
                self.push_due(h, PushKind::Hello);
            }
        }
        matched
    }

    /// Pushes now, or once the handle's interval ends (coalesced).
    fn push_due(&mut self, h: PushHandle, kind: PushKind) {
        let now = self.now;
        let interval = self.config.push_interval_ms;
        let Some(r) = self.push.handles.get_mut(&h) else {
            return;
        };
        if r.last_push
            .is_none_or(|t| t.saturating_add_millis(interval) <= now)
        {
            r.last_push = Some(now);
            r.pending = None;
            self.push.out.push_back(PushDue {
                handle: h,
                kind,
                blob: r.blob.clone(),
            });
            self.stats.pushes += 1;
        } else {
            // Messages win: the app fetches everything on any push.
            r.pending = Some(r.pending.map_or(kind, |p| p.min(kind)));
            self.stats.pushes_coalesced += 1;
        }
    }

    /// When a coalesced push is next due, or a handle expires.
    pub(crate) fn push_next_timeout(&self) -> Option<Timestamp> {
        let interval = self.config.push_interval_ms;
        let ret = self.config.retention_ms;
        self.push
            .handles
            .values()
            .map(|r| {
                let expiry = r.active.saturating_add_millis(ret);
                match (r.pending, r.last_push) {
                    (Some(_), Some(t)) => expiry.min(t.saturating_add_millis(interval)),
                    _ => expiry,
                }
            })
            .min()
    }

    /// Sends coalesced pushes that are due, and expires handles, notes and
    /// bindings (part of [`Relay::handle_timeout`]).
    pub(crate) fn push_tick(&mut self) {
        let now = self.now;
        let interval = self.config.push_interval_ms;
        let due: Vec<(PushHandle, PushKind)> = self
            .push
            .handles
            .iter()
            .filter(|(_, r)| {
                r.last_push
                    .is_some_and(|t| t.saturating_add_millis(interval) <= now)
            })
            .filter_map(|(h, r)| r.pending.map(|k| (*h, k)))
            .collect();
        for (h, kind) in due {
            self.push_due(h, kind);
        }
        let ret = self.config.retention_ms;
        let dead: Vec<PushHandle> = self
            .push
            .handles
            .iter()
            .filter(|(_, r)| r.active.saturating_add_millis(ret) <= now)
            .map(|(h, _)| *h)
            .collect();
        for h in dead {
            self.delete_handle(&h);
        }
        while let Some(&(hash, at)) = self.push.notes_order.front() {
            if at.saturating_add_millis(NOTE_MS) > now {
                break;
            }
            self.push.notes_order.pop_front();
            self.push.notes.remove(&hash);
        }
    }

    /// Storage removals for mailbox `id`'s bindings, as it expires.
    pub(crate) fn unbind_mailbox_ops(&self, id: u64, ops: &mut Ops) {
        if let Some(hs) = self.push.by_mailbox.get(&id) {
            ops.extend(hs.iter().map(|h| (binding_key(id, h), None)));
        }
    }

    /// Mailbox `id` expired: drop its bindings (already removed from
    /// storage by [`Relay::unbind_mailbox_ops`]).
    pub(crate) fn mailbox_gone(&mut self, id: u64) {
        for h in self.push.by_mailbox.remove(&id).unwrap_or_default() {
            if let Some(ids) = self.push.by_handle.get_mut(&h) {
                ids.remove(&id);
            }
        }
    }

    fn unindex_detect(&mut self, detect: &[u8; PUSH_DETECT_LEN], h: &PushHandle) {
        if let Some(s) = self.push.by_detect.get_mut(detect) {
            s.remove(h);
            if s.is_empty() {
                self.push.by_detect.remove(detect);
            }
        }
    }

    fn delete_handle(&mut self, h: &PushHandle) {
        let Some(r) = self.push.handles.get(h) else {
            return;
        };
        let hello = r.hello_key;
        let ids = self.push.by_handle.get(h).cloned().unwrap_or_default();
        let mut ops: Ops = vec![(handle_key(h), None)];
        ops.extend(ids.iter().map(|id| (binding_key(*id, h), None)));
        if !self.commit(ops) {
            return;
        }
        self.push.handles.remove(h);
        self.push.by_handle.remove(h);
        for id in ids {
            if let Some(s) = self.push.by_mailbox.get_mut(&id) {
                s.remove(h);
                if s.is_empty() {
                    self.push.by_mailbox.remove(&id);
                }
            }
        }
        if let Some(k) = hello {
            self.unindex_detect(&push::detect(&k), h);
        }
    }
}
