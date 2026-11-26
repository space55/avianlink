//! Identities, pairwise keys and packet protection (`docs/security.md`).
//!
//! Every primitive comes from an audited RustCrypto/dalek crate; this module
//! only wires them together as specified in `security.md` §3–4.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::wire::{
    encode_hello, hello_signed, put_varint, ChainRole, Hello, PairTag, Proof, AEAD_TAG_LEN,
    HELLO_LEN, HELLO_MAC_LEN, TAG_LEN,
};
use crate::PublicKey;

const PAIR_SALT: &[u8] = b"avianlink/v1/pair";
const FINGERPRINT_LABEL: &[u8] = b"avianlink-fingerprint-v1";

/// Bytes in a fingerprint (80 bits).
pub const FINGERPRINT_LEN: usize = 10;

/// This node's long-term identity: an Ed25519 keypair, also used in X25519
/// form for key agreement (`security.md` §2). The secret is wiped on drop.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generates a new identity.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut());
        Self::from_secret_bytes(&seed)
    }

    /// Reloads an identity from [`Identity::secret_bytes`].
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte secret seed, for the host's keychain. Never written to
    /// `Storage` by the engine.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Ed25519 signature of `msg`.
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing.sign(msg).to_bytes()
    }

    /// The public key: this identity's address.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key().to_bytes())
    }

    /// X25519 shared secret with `peer`, or `None` for invalid, weak or
    /// low-order peer keys.
    pub(crate) fn shared_secret(&self, peer: &PublicKey) -> Option<Zeroizing<[u8; 32]>> {
        let vk = VerifyingKey::from_bytes(&peer.0).ok()?;
        if vk.is_weak() {
            return None;
        }
        let scalar = Zeroizing::new(self.signing.to_scalar_bytes());
        let shared = Zeroizing::new(vk.to_montgomery().mul_clamped(*scalar).to_bytes());
        // Constant-time comparison is unnecessary: an all-zero result means
        // the peer's key is malicious, not secret.
        if shared.iter().all(|&b| b == 0) {
            return None;
        }
        Some(shared)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl PublicKey {
    /// Whether this is a usable contact key: a valid, non-weak Ed25519
    /// point.
    pub fn is_valid(&self) -> bool {
        VerifyingKey::from_bytes(&self.0).is_ok_and(|vk| !vk.is_weak())
    }

    /// 80-bit fingerprint for out-of-band comparison (`security.md` §2).
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        let digest: [u8; 32] = Sha256::new()
            .chain_update(FINGERPRINT_LABEL)
            .chain_update(self.0)
            .finalize()
            .into();
        let mut out = [0u8; FINGERPRINT_LEN];
        out.iter_mut().zip(digest).for_each(|(o, d)| *o = d);
        out
    }
}

/// Renders a fingerprint as five dash-separated groups of four lowercase hex
/// characters, e.g. `a1b2-c3d4-e5f6-7890-abcd`.
pub fn format_fingerprint(fp: &[u8; FINGERPRINT_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(24);
    for (i, b) in fp.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            s.push('-');
        }
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&c) = HEX.get(usize::from(nibble)) {
                s.push(char::from(c));
            }
        }
    }
    s
}

/// Directional keys and routing tags shared with one contact.
pub struct PairKeys {
    tx_key: Zeroizing<[u8; 32]>,
    rx_key: Zeroizing<[u8; 32]>,
    /// Hello MAC keys (`security.md` §2.1, §3), one per direction.
    hello_tx_key: Zeroizing<[u8; 32]>,
    hello_rx_key: Zeroizing<[u8; 32]>,
    /// The pair's HKDF pseudorandom key, for relay mailbox seeds.
    prk: Zeroizing<[u8; 32]>,
    /// Tag on packets we send to the contact.
    pub tx_tag: PairTag,
    /// Tag on packets the contact sends to us.
    pub rx_tag: PairTag,
}

impl fmt::Debug for PairKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairKeys")
            .field("tx_tag", &self.tx_tag)
            .field("rx_tag", &self.rx_tag)
            .finish_non_exhaustive()
    }
}

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n.iter_mut()
        .zip(counter.to_le_bytes())
        .for_each(|(o, b)| *o = b);
    Nonce::from(n)
}

impl PairKeys {
    /// Derives the keys `local` shares with `peer`; `None` if `peer` is not
    /// a valid key.
    pub fn derive(local: &Identity, peer: &PublicKey) -> Option<Self> {
        let shared = local.shared_secret(peer)?;
        let me = local.public_key();
        let (prk_out, hk) = Hkdf::<Sha256>::extract(Some(PAIR_SALT), shared.as_ref());
        let mut prk = Zeroizing::new([0u8; 32]);
        prk.iter_mut().zip(prk_out).for_each(|(o, b)| *o = b);
        let expand = |label: &[u8], from: &PublicKey, to: &PublicKey, out: &mut [u8]| {
            hk.expand_multi_info(&[label, &from.0, &to.0], out).ok()
        };
        let mut tx_key = Zeroizing::new([0u8; 32]);
        let mut rx_key = Zeroizing::new([0u8; 32]);
        let mut hello_tx_key = Zeroizing::new([0u8; 32]);
        let mut hello_rx_key = Zeroizing::new([0u8; 32]);
        let mut tx_tag = [0u8; TAG_LEN];
        let mut rx_tag = [0u8; TAG_LEN];
        expand(b"key", &me, peer, tx_key.as_mut())?;
        expand(b"key", peer, &me, rx_key.as_mut())?;
        expand(b"hello", &me, peer, hello_tx_key.as_mut())?;
        expand(b"hello", peer, &me, hello_rx_key.as_mut())?;
        expand(b"tag", &me, peer, &mut tx_tag)?;
        expand(b"tag", peer, &me, &mut rx_tag)?;
        Some(Self {
            tx_key,
            rx_key,
            hello_tx_key,
            hello_rx_key,
            prk,
            tx_tag,
            rx_tag,
        })
    }

    /// The Hello introducing `local` to `peer` (`wire-format.md` §2.5). The
    /// same bytes every time.
    pub fn hello(&self, local: &PublicKey, peer: &PublicKey) -> Option<[u8; HELLO_LEN]> {
        let signed = hello_signed(crate::hash::hello_hint(peer), local);
        let mut mac = <Hmac<Sha256>>::new_from_slice(self.hello_tx_key.as_ref()).ok()?;
        mac.update(&signed);
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; HELLO_MAC_LEN];
        tag.iter_mut().zip(full).for_each(|(o, b)| *o = b);
        Some(encode_hello(&signed, &tag))
    }

    /// The seed of the relay mailbox chain for direction `from` → `to`, in
    /// `role`, for mailbox `epoch` (`relay.md` §2.1). Either member of the
    /// pair computes the same seed.
    pub fn mailbox_seed(
        &self,
        from: &PublicKey,
        to: &PublicKey,
        role: ChainRole,
        epoch: u64,
    ) -> Option<Proof> {
        let hk = Hkdf::<Sha256>::from_prk(self.prk.as_ref()).ok()?;
        let r: &[u8] = match role {
            ChainRole::Up => b"up",
            ChainRole::Down => b"down",
        };
        let mut g = Vec::with_capacity(10);
        put_varint(&mut g, epoch);
        let mut seed = [0u8; 16];
        hk.expand_multi_info(&[b"mailbox", r, &g, &from.0, &to.0], &mut seed)
            .ok()?;
        Some(seed)
    }

    /// Whether `hello` was made by the contact for us. Constant time.
    pub fn verify_hello(&self, hello: &Hello<'_>) -> bool {
        let Ok(mut mac) = <Hmac<Sha256>>::new_from_slice(self.hello_rx_key.as_ref()) else {
            return false;
        };
        mac.update(hello.signed);
        mac.verify_truncated_left(&hello.mac).is_ok()
    }

    /// Encrypts `packet[header_len..]` in place and appends the AEAD tag.
    /// The header is authenticated as associated data.
    pub fn seal(&self, packet: &mut Vec<u8>, header_len: usize, counter: u64) -> Option<()> {
        let cipher = ChaCha20Poly1305::new(&Key::from(*self.tx_key));
        let (header, body) = packet.split_at_mut_checked(header_len)?;
        let tag = cipher
            .encrypt_inout_detached(&nonce(counter), header, body.into())
            .ok()?;
        packet.extend_from_slice(&tag);
        Some(())
    }

    /// Authenticates and decrypts a packet from the contact. Returns the
    /// plaintext frames, or `None` if authentication fails.
    pub fn open(&self, packet: &[u8], header_len: usize, counter: u64) -> Option<Vec<u8>> {
        let body_end = packet.len().checked_sub(AEAD_TAG_LEN)?;
        let (sealed, tag) = packet.split_at_checked(body_end)?;
        let (header, ciphertext) = sealed.split_at_checked(header_len)?;
        let tag: [u8; AEAD_TAG_LEN] = tag.try_into().ok()?;
        let mut plain = ciphertext.to_vec();
        ChaCha20Poly1305::new(&Key::from(*self.rx_key))
            .decrypt_inout_detached(
                &nonce(counter),
                header,
                plain.as_mut_slice().into(),
                &Tag::from(tag),
            )
            .ok()?;
        Some(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{begin_packet, parse_header};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn ids() -> (Identity, Identity) {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        (Identity::generate(&mut rng), Identity::generate(&mut rng))
    }

    #[test]
    fn both_sides_derive_matching_keys() {
        let (a, b) = ids();
        let ab = PairKeys::derive(&a, &b.public_key()).unwrap();
        let ba = PairKeys::derive(&b, &a.public_key()).unwrap();
        assert_eq!(ab.tx_tag, ba.rx_tag);
        assert_eq!(ab.rx_tag, ba.tx_tag);
        assert_ne!(ab.tx_tag, ab.rx_tag);
        assert_eq!(*ab.tx_key, *ba.rx_key);
        assert_ne!(*ab.tx_key, *ab.rx_key);
    }

    #[test]
    fn seal_open_round_trip_and_tamper_detection() {
        let (a, b) = ids();
        let ab = PairKeys::derive(&a, &b.public_key()).unwrap();
        let ba = PairKeys::derive(&b, &a.public_key()).unwrap();
        let mut pkt = Vec::new();
        begin_packet(&mut pkt, ab.tx_tag, 300);
        let hl = pkt.len();
        pkt.extend_from_slice(b"frames go here");
        ab.seal(&mut pkt, hl, 300).unwrap();
        assert_eq!(pkt.len(), hl + 14 + AEAD_TAG_LEN);
        assert!(!pkt.windows(6).any(|w| w == b"frames"), "encrypted");
        let (tag, counter, hlen) = parse_header(&pkt).unwrap();
        assert_eq!((tag, counter, hlen), (ab.tx_tag, 300, hl));
        assert_eq!(ba.open(&pkt, hl, 300).unwrap(), b"frames go here");
        // Wrong counter (nonce), wrong direction, any flipped bit, truncation.
        assert!(ba.open(&pkt, hl, 301).is_none());
        assert!(ab.open(&pkt, hl, 300).is_none());
        for i in 0..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 1;
            assert!(ba.open(&bad, hl, 300).is_none(), "bit flip at {i}");
        }
        assert!(ba.open(&pkt[..pkt.len() - 1], hl, 300).is_none());
        assert!(ba.open(&pkt[..10], hl, 300).is_none());
    }

    #[test]
    fn hello_verifies_only_for_its_pair_and_direction() {
        let (a, b) = ids();
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let c = Identity::generate(&mut rng);
        let ab = PairKeys::derive(&a, &b.public_key()).unwrap();
        let ba = PairKeys::derive(&b, &a.public_key()).unwrap();
        let ca = PairKeys::derive(&c, &a.public_key()).unwrap();
        let bytes = ab.hello(&a.public_key(), &b.public_key()).unwrap();
        assert_eq!(bytes.len(), HELLO_LEN);
        assert_eq!(
            bytes,
            ab.hello(&a.public_key(), &b.public_key()).unwrap(),
            "deterministic"
        );
        let h = crate::wire::parse_hello(&bytes).unwrap();
        assert_eq!(h.sender, a.public_key());
        assert_eq!(h.hint, crate::hash::hello_hint(&b.public_key()));
        assert!(ba.verify_hello(&h));
        assert!(!ab.verify_hello(&h), "wrong direction");
        assert!(!ca.verify_hello(&h), "made for b, not c");
        for i in 0..bytes.len() {
            let mut bad = bytes;
            bad[i] ^= 1;
            if let Ok(h) = crate::wire::parse_hello(&bad) {
                assert!(!ba.verify_hello(&h), "bit flip at {i}");
            }
        }
    }

    #[test]
    fn mailbox_seeds_agree_across_the_pair_and_differ_otherwise() {
        let (a, b) = ids();
        let (pa, pb) = (a.public_key(), b.public_key());
        let ab = PairKeys::derive(&a, &pb).unwrap();
        let ba = PairKeys::derive(&b, &pa).unwrap();
        let s = |k: &PairKeys, f, t, r, g| k.mailbox_seed(f, t, r, g).unwrap();
        assert_eq!(
            s(&ab, &pa, &pb, ChainRole::Up, 0),
            s(&ba, &pa, &pb, ChainRole::Up, 0)
        );
        assert_eq!(
            s(&ab, &pb, &pa, ChainRole::Down, 3),
            s(&ba, &pb, &pa, ChainRole::Down, 3)
        );
        let all = [
            s(&ab, &pa, &pb, ChainRole::Up, 0),
            s(&ab, &pa, &pb, ChainRole::Down, 0),
            s(&ab, &pb, &pa, ChainRole::Up, 0),
            s(&ab, &pa, &pb, ChainRole::Up, 1),
        ];
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn rejects_invalid_and_weak_keys() {
        let (a, _) = ids();
        // The identity point (small order) and a non-point.
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        assert!(!PublicKey(identity_point).is_valid());
        assert!(PairKeys::derive(&a, &PublicKey(identity_point)).is_none());
        let not_a_point = (0u8..=255)
            .map(|b| {
                let mut k = [0u8; 32];
                k[0] = b;
                PublicKey(k)
            })
            .find(|k| VerifyingKey::from_bytes(&k.0).is_err())
            .unwrap();
        assert!(!not_a_point.is_valid());
        assert!(PairKeys::derive(&a, &not_a_point).is_none());
        assert!(a.public_key().is_valid());
    }

    #[test]
    fn identity_round_trips_through_secret_bytes() {
        let (a, _) = ids();
        let again = Identity::from_secret_bytes(&a.secret_bytes());
        assert_eq!(again.public_key(), a.public_key());
        assert!(!alloc::format!("{a:?}").contains(&alloc::format!("{:?}", *a.secret_bytes())));
    }

    #[test]
    fn fingerprint_matches_desktop_definition() {
        // Independent recomputation of SHA-256(label || pk)[..10].
        let pk = PublicKey([7; 32]);
        let mut h = Sha256::new();
        h.update(b"avianlink-fingerprint-v1");
        h.update([7u8; 32]);
        let d = h.finalize();
        assert_eq!(pk.fingerprint()[..], d[..10]);
        let s = format_fingerprint(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90, 0xab, 0xcd]);
        assert_eq!(s, "a1b2-c3d4-e5f6-7890-abcd");
    }
}
