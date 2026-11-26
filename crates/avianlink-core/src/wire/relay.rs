//! Relay protocol messages (`docs/relay.md` §4), kinds 0x10–0x19.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use super::{put_varint, DecodeError, PairTag, Reader, HELLO_HINT_LEN, TAG_LEN};

/// Bytes of the checksum ending every relay message.
pub const RELAY_CHECK_LEN: usize = 4;

/// `SHA-256(label ‖ body)[..4]`: every relay message ends with it, because
/// relay messages have no AEAD and these links corrupt bits. It detects
/// corruption, not forgery (`relay.md` §4).
fn relay_check(body: &[u8]) -> [u8; RELAY_CHECK_LEN] {
    let d: [u8; 32] = Sha256::new()
        .chain_update(b"avianlink-relay-v1")
        .chain_update(body)
        .finalize()
        .into();
    let mut c = [0u8; RELAY_CHECK_LEN];
    c.iter_mut().zip(d).for_each(|(o, b)| *o = b);
    c
}

/// Bytes in a chain proof or anchor.
pub const PROOF_LEN: usize = 16;
/// Bytes in a receipt's packet hash.
pub const RECEIPT_HASH_LEN: usize = 4;
/// Most hashes in one RECEIPT (keeps it within 48 bytes).
pub const MAX_RECEIPT_HASHES: usize = 10;
/// Most packets in one fetch page: a REPLY lists their hashes, and stays
/// within 48 bytes while retention < 2²⁸ s and the cursor < 2³⁵.
pub const MAX_PAGE: usize = 6;

/// REGISTER kind.
pub const RELAY_REGISTER: u8 = 0x10;
/// OPEN kind.
pub const RELAY_OPEN: u8 = 0x11;
/// FETCH kind.
pub const RELAY_FETCH: u8 = 0x12;
/// FETCH_HELLO kind.
pub const RELAY_FETCH_HELLO: u8 = 0x13;
/// PUSH_REGISTER kind (`push.md` §4).
pub const RELAY_PUSH_REGISTER: u8 = 0x14;
/// PUSH_BIND kind.
pub const RELAY_PUSH_BIND: u8 = 0x15;
/// PUSH_BIND_HELLO kind.
pub const RELAY_PUSH_BIND_HELLO: u8 = 0x16;
/// HELLO_NOTE kind.
pub const RELAY_HELLO_NOTE: u8 = 0x17;
/// REPLY kind.
pub const RELAY_REPLY: u8 = 0x18;
/// RECEIPT kind.
pub const RELAY_RECEIPT: u8 = 0x19;
/// PUSH_NOTE kind (`push.md` §4.4).
pub const RELAY_PUSH_NOTE: u8 = 0x1a;

/// Bytes in a push secret (`push.md` §3).
pub const PUSH_SECRET_LEN: usize = 16;
/// Bytes in a push handle.
pub const PUSH_HANDLE_LEN: usize = 8;
/// Bytes in a HELLO_NOTE's recipient hash.
pub const PUSH_DETECT_LEN: usize = 8;
/// Largest sealed push registration.
pub const MAX_PUSH_BLOB: usize = 512;

/// A chain proof or anchor.
pub type Proof = [u8; PROOF_LEN];
/// Names a push registration at a relay.
pub type PushHandle = [u8; PUSH_HANDLE_LEN];
/// A receipt's packet hash.
pub type ReceiptHash = [u8; RECEIPT_HASH_LEN];

/// Result codes in REPLY and RECEIPT (`relay.md` §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayCode {
    /// Done.
    Ok,
    /// The proof didn't verify.
    BadProof,
    /// No mailbox matches.
    UnknownMailbox,
    /// Refused for lack of space: retry later or elsewhere.
    Full,
    /// A data packet with no upload session for its tag.
    NoSession,
    /// Too many requests from this address.
    RateLimited,
    /// A fetch page ended; more is waiting.
    More,
    /// A code this version doesn't know.
    Unknown(u8),
}

impl RelayCode {
    fn to_u8(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::BadProof => 1,
            Self::UnknownMailbox => 2,
            Self::Full => 3,
            Self::NoSession => 4,
            Self::RateLimited => 5,
            Self::More => 6,
            Self::Unknown(c) => c,
        }
    }

    fn from_u8(c: u8) -> Self {
        match c {
            0 => Self::Ok,
            1 => Self::BadProof,
            2 => Self::UnknownMailbox,
            3 => Self::Full,
            4 => Self::NoSession,
            5 => Self::RateLimited,
            6 => Self::More,
            c => Self::Unknown(c),
        }
    }
}

/// Which chain of a mailbox (`relay.md` §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainRole {
    /// Opens upload sessions; used by the sender.
    Up,
    /// Fetches; used by the recipient.
    Down,
}

/// A decoded relay message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayMsg {
    /// Create or refresh a mailbox.
    Register {
        /// The direction's routing tag.
        tag: PairTag,
        /// Upload chain anchor.
        up: Proof,
        /// Fetch chain anchor.
        down: Proof,
    },
    /// Open an upload session.
    Open {
        /// Routing tag.
        tag: PairTag,
        /// Up-chain proof.
        proof: Proof,
    },
    /// Fetch a page of a mailbox.
    Fetch {
        /// Routing tag.
        tag: PairTag,
        /// Down-chain proof.
        proof: Proof,
        /// First relay sequence number wanted.
        since: u64,
        /// Every packet below this has been received; the relay may delete
        /// them (`relay.md` §4.3). At most `since`.
        release: u64,
        /// Most packets wanted (0: the relay's page size); a re-read asks
        /// only for the span covering its gaps.
        max: u8,
    },
    /// Create, refresh or (with an empty blob) delete a push handle.
    PushRegister {
        /// The secret the handle is derived from.
        secret: [u8; PUSH_SECRET_LEN],
        /// The registration sealed to the push service (at most
        /// [`MAX_PUSH_BLOB`] bytes).
        blob: Vec<u8>,
    },
    /// Bind a mailbox to a push handle.
    PushBind {
        /// Routing tag.
        tag: PairTag,
        /// Down-chain proof.
        proof: Proof,
        /// The handle.
        handle: PushHandle,
    },
    /// Bind (or unbind) Hellos for a key to a push handle.
    PushBindHello {
        /// The recipient's public key.
        key: [u8; 32],
        /// The handle.
        handle: PushHandle,
        /// Bind, or remove the binding.
        on: bool,
        /// Ed25519 signature by `key` (`push.md` §4.3).
        sig: [u8; 64],
    },
    /// The packets just uploaded in this upload session carry a message,
    /// not only acknowledgements: worth a push.
    PushNote {
        /// Routing tag of the session.
        tag: PairTag,
    },
    /// Names the recipient of an uploaded Hello, for push.
    HelloNote {
        /// The Hello's receipt hash.
        hello_hash: ReceiptHash,
        /// Hash of the recipient's key.
        detect: [u8; PUSH_DETECT_LEN],
    },
    /// Fetch a page of Hellos for a hint.
    FetchHello {
        /// Recipient hint.
        hint: [u8; HELLO_HINT_LEN],
        /// First relay sequence number wanted.
        since: u64,
    },
    /// The relay's answer to a request.
    Reply {
        /// Kind of the request answered.
        request: u8,
        /// Result.
        code: RelayCode,
        /// The request's tag, or its hint followed by a zero byte.
        key: [u8; TAG_LEN],
        /// The relay's retention, in seconds.
        retention_s: u64,
        /// For FETCH and FETCH_HELLO: the sequence number after the page.
        cursor: u64,
        /// For FETCH and FETCH_HELLO: the receipt hashes of the page's
        /// packets in order, which had sequence numbers `cursor - n ..
        /// cursor` (at most [`MAX_PAGE`]). The client learns exactly which
        /// arrived.
        page: Vec<ReceiptHash>,
    },
    /// Acknowledges uploaded packets by hash.
    Receipt {
        /// Result for every listed packet.
        code: RelayCode,
        /// The packets' hashes (at most [`MAX_RECEIPT_HASHES`]).
        hashes: Vec<ReceiptHash>,
    },
}

/// Whether byte 0 belongs to the relay protocol.
pub fn is_relay_kind(kind: u8) -> bool {
    (RELAY_REGISTER..=RELAY_PUSH_NOTE).contains(&kind)
}

/// Encodes `msg`, checksum included. Every encoding fits in 48 bytes (a
/// RECEIPT keeps at most [`MAX_RECEIPT_HASHES`] hashes, a REPLY at most
/// [`MAX_PAGE`]), except PUSH_REGISTER and PUSH_BIND_HELLO, which are sent
/// only over IP (`push.md` §4). A blob is cut at [`MAX_PUSH_BLOB`].
pub fn encode_relay(msg: &RelayMsg) -> Vec<u8> {
    let mut v = Vec::with_capacity(48);
    match msg {
        RelayMsg::Register { tag, up, down } => {
            v.push(RELAY_REGISTER);
            v.extend_from_slice(tag);
            v.extend_from_slice(up);
            v.extend_from_slice(down);
        }
        RelayMsg::Open { tag, proof } => {
            v.push(RELAY_OPEN);
            v.extend_from_slice(tag);
            v.extend_from_slice(proof);
        }
        RelayMsg::Fetch {
            tag,
            proof,
            since,
            release,
            max,
        } => {
            v.push(RELAY_FETCH);
            v.extend_from_slice(tag);
            v.extend_from_slice(proof);
            put_varint(&mut v, *since);
            put_varint(&mut v, *release);
            v.push(*max);
        }
        RelayMsg::PushRegister { secret, blob } => {
            v.push(RELAY_PUSH_REGISTER);
            v.extend_from_slice(secret);
            v.extend_from_slice(blob.get(..MAX_PUSH_BLOB).unwrap_or(blob));
        }
        RelayMsg::PushBind { tag, proof, handle } => {
            v.push(RELAY_PUSH_BIND);
            v.extend_from_slice(tag);
            v.extend_from_slice(proof);
            v.extend_from_slice(handle);
        }
        RelayMsg::PushBindHello {
            key,
            handle,
            on,
            sig,
        } => {
            v.push(RELAY_PUSH_BIND_HELLO);
            v.extend_from_slice(key);
            v.extend_from_slice(handle);
            v.push(u8::from(*on));
            v.extend_from_slice(sig);
        }
        RelayMsg::PushNote { tag } => {
            v.push(RELAY_PUSH_NOTE);
            v.extend_from_slice(tag);
        }
        RelayMsg::HelloNote { hello_hash, detect } => {
            v.push(RELAY_HELLO_NOTE);
            v.extend_from_slice(hello_hash);
            v.extend_from_slice(detect);
        }
        RelayMsg::FetchHello { hint, since } => {
            v.push(RELAY_FETCH_HELLO);
            v.extend_from_slice(hint);
            put_varint(&mut v, *since);
        }
        RelayMsg::Reply {
            request,
            code,
            key,
            retention_s,
            cursor,
            page,
        } => {
            let n = page.len().min(MAX_PAGE);
            v.push(RELAY_REPLY);
            v.push(*request);
            v.push(code.to_u8());
            v.extend_from_slice(key);
            put_varint(&mut v, *retention_s);
            put_varint(&mut v, *cursor);
            v.push(u8::try_from(n).unwrap_or(0));
            for h in page.iter().take(n) {
                v.extend_from_slice(h);
            }
        }
        RelayMsg::Receipt { code, hashes } => {
            let n = hashes.len().min(MAX_RECEIPT_HASHES);
            v.push(RELAY_RECEIPT);
            v.push(code.to_u8());
            v.push(u8::try_from(n).unwrap_or(0));
            for h in hashes.iter().take(n) {
                v.extend_from_slice(h);
            }
        }
    }
    let check = relay_check(&v);
    v.extend_from_slice(&check);
    v
}

/// Parses a relay message, verifying its checksum. Trailing bytes are an
/// error.
pub fn parse_relay(bytes: &[u8]) -> Result<RelayMsg, DecodeError> {
    let body_len = bytes
        .len()
        .checked_sub(RELAY_CHECK_LEN)
        .ok_or(DecodeError::Truncated)?;
    let (body, check) = bytes
        .split_at_checked(body_len)
        .ok_or(DecodeError::Truncated)?;
    if relay_check(body) != check {
        return Err(DecodeError::TooLarge);
    }
    let mut r = Reader::new(body);
    let kind = r.u8()?;
    let msg = match kind {
        RELAY_REGISTER => RelayMsg::Register {
            tag: r.array()?,
            up: r.array()?,
            down: r.array()?,
        },
        RELAY_OPEN => RelayMsg::Open {
            tag: r.array()?,
            proof: r.array()?,
        },
        RELAY_FETCH => RelayMsg::Fetch {
            tag: r.array()?,
            proof: r.array()?,
            since: r.varint()?,
            release: r.varint()?,
            max: r.u8()?,
        },
        RELAY_PUSH_REGISTER => {
            let secret = r.array()?;
            let blob = r.rest();
            if blob.len() > MAX_PUSH_BLOB {
                return Err(DecodeError::TooLarge);
            }
            RelayMsg::PushRegister {
                secret,
                blob: blob.to_vec(),
            }
        }
        RELAY_PUSH_BIND => RelayMsg::PushBind {
            tag: r.array()?,
            proof: r.array()?,
            handle: r.array()?,
        },
        RELAY_PUSH_BIND_HELLO => RelayMsg::PushBindHello {
            key: r.array()?,
            handle: r.array()?,
            on: match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::TooLarge),
            },
            sig: r.array()?,
        },
        RELAY_PUSH_NOTE => RelayMsg::PushNote { tag: r.array()? },
        RELAY_HELLO_NOTE => RelayMsg::HelloNote {
            hello_hash: r.array()?,
            detect: r.array()?,
        },
        RELAY_FETCH_HELLO => RelayMsg::FetchHello {
            hint: r.array()?,
            since: r.varint()?,
        },
        RELAY_REPLY => RelayMsg::Reply {
            request: r.u8()?,
            code: RelayCode::from_u8(r.u8()?),
            key: r.array()?,
            retention_s: r.varint()?,
            cursor: r.varint()?,
            page: {
                let n = usize::from(r.u8()?);
                if n > MAX_PAGE {
                    return Err(DecodeError::TooLarge);
                }
                let mut page = Vec::with_capacity(n);
                for _ in 0..n {
                    page.push(r.array()?);
                }
                page
            },
        },
        RELAY_RECEIPT => {
            let code = RelayCode::from_u8(r.u8()?);
            let n = usize::from(r.u8()?);
            if n > MAX_RECEIPT_HASHES {
                return Err(DecodeError::TooLarge);
            }
            let mut hashes = Vec::with_capacity(n);
            for _ in 0..n {
                hashes.push(r.array()?);
            }
            RelayMsg::Receipt { code, hashes }
        }
        k => return Err(DecodeError::UnknownVersion(k)),
    };
    if !r.is_empty() {
        return Err(DecodeError::TooLarge);
    }
    Ok(msg)
}
