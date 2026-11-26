//! Push notifications (`docs/push.md`): sealed registrations, handles,
//! Hello bindings, and the relay ↔ push service messages.

use alloc::vec::Vec;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::wire::{
    PushHandle, Reader, AEAD_TAG_LEN, MAX_PUSH_BLOB, PUSH_DETECT_LEN, PUSH_SECRET_LEN,
};
use crate::{Identity, PublicKey};

/// The sealed-blob format version.
pub const BLOB_VERSION: u8 = 1;
const SEAL_INFO: &[u8] = b"avianlink-push-seal-v1";
const SERVICE_LABEL: &[u8] = b"avianlink-push-v1";
const SERVICE_CHECK_LEN: usize = 4;
/// Bytes a blob adds to the token: version, ephemeral key, provider, app
/// and AEAD tag.
pub const BLOB_OVERHEAD: usize = 1 + 32 + 2 + AEAD_TAG_LEN;
/// Longest token that can be sealed.
pub const MAX_TOKEN: usize = MAX_PUSH_BLOB - BLOB_OVERHEAD;

/// NOTIFY kind (`push.md` §5).
pub const NOTIFY: u8 = 0x20;
/// NOTIFY_ACK kind.
pub const NOTIFY_ACK: u8 = 0x21;

/// Who delivers the push.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    /// Apple Push Notification service, production.
    Apns,
    /// APNs sandbox, for development builds.
    ApnsSandbox,
    /// Firebase Cloud Messaging.
    Fcm,
    /// A provider this version doesn't know.
    Unknown(u8),
}

impl Provider {
    /// Its byte in a blob.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Apns => 1,
            Self::ApnsSandbox => 2,
            Self::Fcm => 3,
            Self::Unknown(p) => p,
        }
    }

    /// The provider for a blob byte.
    pub fn from_u8(p: u8) -> Self {
        match p {
            1 => Self::Apns,
            2 => Self::ApnsSandbox,
            3 => Self::Fcm,
            p => Self::Unknown(p),
        }
    }
}

/// What a blob holds: where to push.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The provider.
    pub provider: Provider,
    /// Which of the push service's configured apps.
    pub app: u8,
    /// The token the OS gave the app (APNs: the raw device token bytes;
    /// FCM: the registration token's UTF-8).
    pub token: Vec<u8>,
}

fn seal_key(shared: &[u8; 32], eph: &PublicKey, service: &PublicKey) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt.iter_mut()
        .zip(eph.0.iter().chain(service.0.iter()))
        .for_each(|(o, b)| *o = *b);
    let mut k = Zeroizing::new([0u8; 32]);
    // 32 bytes is always a valid HKDF-SHA256 output length.
    let _ = Hkdf::<Sha256>::new(Some(&salt), shared).expand(SEAL_INFO, k.as_mut());
    k
}

/// Seals `reg` to the push service `service` (`push.md` §2). `None` if the
/// token is longer than [`MAX_TOKEN`] or `service` is not a valid key.
pub fn seal<R: CryptoRng>(service: &PublicKey, reg: &Registration, rng: &mut R) -> Option<Vec<u8>> {
    if reg.token.len() > MAX_TOKEN {
        return None;
    }
    let eph = Identity::generate(rng);
    let eph_pk = eph.public_key();
    let shared = eph.shared_secret(service)?;
    let k = seal_key(&shared, &eph_pk, service);
    let mut blob = Vec::with_capacity(BLOB_OVERHEAD.saturating_add(reg.token.len()));
    blob.push(BLOB_VERSION);
    blob.extend_from_slice(&eph_pk.0);
    let body = blob.len();
    blob.push(reg.provider.to_u8());
    blob.push(reg.app);
    blob.extend_from_slice(&reg.token);
    let (aad, pt) = blob.split_at_mut_checked(body)?;
    let tag = ChaCha20Poly1305::new(&Key::from(*k))
        .encrypt_inout_detached(&Nonce::default(), aad, pt.into())
        .ok()?;
    blob.extend_from_slice(&tag);
    Some(blob)
}

/// Opens a blob sealed to `service`. `None` if it wasn't, or was altered.
pub fn open(service: &Identity, blob: &[u8]) -> Option<Registration> {
    if blob.len() > MAX_PUSH_BLOB || blob.first() != Some(&BLOB_VERSION) {
        return None;
    }
    let body_end = blob.len().checked_sub(AEAD_TAG_LEN)?;
    let (sealed, tag) = blob.split_at_checked(body_end)?;
    let (aad, ct) = sealed.split_at_checked(33)?;
    let eph = PublicKey(aad.get(1..)?.try_into().ok()?);
    let shared = service.shared_secret(&eph)?;
    let k = seal_key(&shared, &eph, &service.public_key());
    let tag: [u8; AEAD_TAG_LEN] = tag.try_into().ok()?;
    let mut pt = ct.to_vec();
    ChaCha20Poly1305::new(&Key::from(*k))
        .decrypt_inout_detached(
            &Nonce::default(),
            aad,
            pt.as_mut_slice().into(),
            &Tag::from(tag),
        )
        .ok()?;
    let mut r = Reader::new(&pt);
    Some(Registration {
        provider: Provider::from_u8(r.u8().ok()?),
        app: r.u8().ok()?,
        token: r.rest().to_vec(),
    })
}

fn digest(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    parts.iter().for_each(|p| h.update(p));
    h.finalize().into()
}

/// The handle a relay names a registration by (`push.md` §3).
pub fn handle(secret: &[u8; PUSH_SECRET_LEN]) -> PushHandle {
    let mut h = [0u8; 8];
    h.iter_mut()
        .zip(digest(b"avianlink-push-handle-v1", &[secret]))
        .for_each(|(o, b)| *o = b);
    h
}

/// The recipient hash in a HELLO_NOTE (`push.md` §4.3).
pub fn detect(recipient: &PublicKey) -> [u8; PUSH_DETECT_LEN] {
    let mut d = [0u8; PUSH_DETECT_LEN];
    d.iter_mut()
        .zip(digest(b"avianlink-hello-push-v1", &[&recipient.0]))
        .for_each(|(o, b)| *o = b);
    d
}

const HELLO_BIND_LABEL: &[u8] = b"avianlink-push-hello-v1";

fn hello_bind_message(handle: &PushHandle, on: bool) -> [u8; HELLO_BIND_LABEL.len() + 9] {
    let mut m = [0u8; HELLO_BIND_LABEL.len() + 9];
    m.iter_mut()
        .zip(
            HELLO_BIND_LABEL
                .iter()
                .chain(handle.iter())
                .chain(core::iter::once(&u8::from(on))),
        )
        .for_each(|(o, b)| *o = *b);
    m
}

/// Signs a PUSH_BIND_HELLO for `identity`.
pub fn sign_hello_binding(identity: &Identity, handle: &PushHandle, on: bool) -> [u8; 64] {
    identity.sign(&hello_bind_message(handle, on))
}

/// Whether `sig` is `key`'s signature binding (or, with `on` false,
/// unbinding) its Hellos to `handle`.
pub fn verify_hello_binding(
    key: &PublicKey,
    handle: &PushHandle,
    on: bool,
    sig: &[u8; 64],
) -> bool {
    VerifyingKey::from_bytes(&key.0).is_ok_and(|vk| {
        !vk.is_weak()
            && vk
                .verify_strict(&hello_bind_message(handle, on), &Signature::from_bytes(sig))
                .is_ok()
    })
}

/// What arrived, so the app knows what to fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PushKind {
    /// Packets in a mailbox.
    Message,
    /// A contact request.
    Hello,
}

/// The push service's answer to a NOTIFY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckCode {
    /// Handed to the provider.
    Ok,
    /// The token is dead: delete the handle.
    Gone,
    /// Not sealed to this push service.
    BadBlob,
    /// Too many pushes to this token.
    RateLimited,
    /// The provider refused or was unreachable.
    Failed,
    /// A code this version doesn't know.
    Unknown(u8),
}

impl AckCode {
    fn to_u8(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Gone => 1,
            Self::BadBlob => 2,
            Self::RateLimited => 3,
            Self::Failed => 4,
            Self::Unknown(c) => c,
        }
    }

    fn from_u8(c: u8) -> Self {
        match c {
            0 => Self::Ok,
            1 => Self::Gone,
            2 => Self::BadBlob,
            3 => Self::RateLimited,
            4 => Self::Failed,
            c => Self::Unknown(c),
        }
    }
}

/// A message between a relay and the push service (`push.md` §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceMsg {
    /// Relay → service: push to the registration in `blob`.
    Notify {
        /// Random; the ACK names it.
        id: u64,
        /// What arrived.
        kind: PushKind,
        /// The sealed registration.
        blob: Vec<u8>,
    },
    /// Service → relay.
    Ack {
        /// The NOTIFY's id.
        id: u64,
        /// The outcome.
        code: AckCode,
    },
}

fn service_check(body: &[u8]) -> [u8; SERVICE_CHECK_LEN] {
    let mut c = [0u8; SERVICE_CHECK_LEN];
    c.iter_mut()
        .zip(digest(SERVICE_LABEL, &[body]))
        .for_each(|(o, b)| *o = b);
    c
}

/// Encodes a relay ↔ push service message, checksum included.
pub fn encode_service(msg: &ServiceMsg) -> Vec<u8> {
    let mut v = Vec::new();
    match msg {
        ServiceMsg::Notify { id, kind, blob } => {
            v.push(NOTIFY);
            v.extend_from_slice(&id.to_be_bytes());
            v.push(match kind {
                PushKind::Message => 0,
                PushKind::Hello => 1,
            });
            v.extend_from_slice(blob.get(..MAX_PUSH_BLOB).unwrap_or(blob));
        }
        ServiceMsg::Ack { id, code } => {
            v.push(NOTIFY_ACK);
            v.extend_from_slice(&id.to_be_bytes());
            v.push(code.to_u8());
        }
    }
    let check = service_check(&v);
    v.extend_from_slice(&check);
    v
}

/// Parses a relay ↔ push service message, verifying its checksum.
pub fn parse_service(bytes: &[u8]) -> Option<ServiceMsg> {
    let body_end = bytes.len().checked_sub(SERVICE_CHECK_LEN)?;
    let (body, check) = bytes.split_at_checked(body_end)?;
    if service_check(body) != check {
        return None;
    }
    let mut r = Reader::new(body);
    let kind = r.u8().ok()?;
    let id = u64::from_be_bytes(r.array().ok()?);
    match kind {
        NOTIFY => {
            let kind = match r.u8().ok()? {
                0 => PushKind::Message,
                1 => PushKind::Hello,
                _ => return None,
            };
            let blob = r.rest();
            (blob.len() <= MAX_PUSH_BLOB).then(|| ServiceMsg::Notify {
                id,
                kind,
                blob: blob.to_vec(),
            })
        }
        NOTIFY_ACK => {
            let code = AckCode::from_u8(r.u8().ok()?);
            r.is_empty().then_some(ServiceMsg::Ack { id, code })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn blobs_open_only_for_their_service_and_unaltered() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let service = Identity::generate(&mut rng);
        let other = Identity::generate(&mut rng);
        let reg = Registration {
            provider: Provider::Apns,
            app: 2,
            token: alloc::vec![7; 32],
        };
        let blob = seal(&service.public_key(), &reg, &mut rng).unwrap();
        assert_eq!(blob.len(), BLOB_OVERHEAD + 32);
        assert_eq!(open(&service, &blob), Some(reg.clone()));
        assert_eq!(open(&other, &blob), None);
        for i in 0..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 1;
            assert_eq!(open(&service, &bad), None, "byte {i}");
        }
        // Two seals of the same token differ (fresh ephemeral key).
        assert_ne!(seal(&service.public_key(), &reg, &mut rng).unwrap(), blob);
        let long = Registration {
            token: alloc::vec![1; MAX_TOKEN + 1],
            ..reg
        };
        assert!(seal(&service.public_key(), &long, &mut rng).is_none());
    }

    #[test]
    fn hello_bindings_verify_only_as_signed() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let id = Identity::generate(&mut rng);
        let pk = id.public_key();
        let h = handle(&[3; 16]);
        let sig = sign_hello_binding(&id, &h, true);
        assert!(verify_hello_binding(&pk, &h, true, &sig));
        assert!(!verify_hello_binding(&pk, &h, false, &sig), "on is signed");
        assert!(!verify_hello_binding(&pk, &handle(&[4; 16]), true, &sig));
        let other = Identity::generate(&mut rng).public_key();
        assert!(!verify_hello_binding(&other, &h, true, &sig));
    }

    #[test]
    fn service_messages_round_trip_and_reject_corruption() {
        for m in [
            ServiceMsg::Notify {
                id: 0x0102_0304_0506_0708,
                kind: PushKind::Hello,
                blob: alloc::vec![9; 80],
            },
            ServiceMsg::Ack {
                id: 42,
                code: AckCode::Gone,
            },
        ] {
            let b = encode_service(&m);
            assert_eq!(parse_service(&b), Some(m));
            for i in 0..b.len() {
                let mut bad = b.clone();
                bad[i] ^= 0x10;
                assert_eq!(parse_service(&bad), None);
            }
        }
    }
}
