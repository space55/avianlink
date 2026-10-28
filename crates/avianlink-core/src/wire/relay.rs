//! Relay protocol messages (`docs/relay.md` §4), kinds 0x10–0x19.

use alloc::vec::Vec;

use super::{put_varint, DecodeError, PairTag, Reader, HELLO_HINT_LEN, TAG_LEN};

/// Bytes in a chain proof or anchor.
pub const PROOF_LEN: usize = 16;
/// Bytes in a receipt's packet hash.
pub const RECEIPT_HASH_LEN: usize = 4;
/// Most hashes in one RECEIPT (keeps it within 48 bytes).
pub const MAX_RECEIPT_HASHES: usize = 10;

/// REGISTER kind.
pub const RELAY_REGISTER: u8 = 0x10;
/// OPEN kind.
pub const RELAY_OPEN: u8 = 0x11;
/// FETCH kind.
pub const RELAY_FETCH: u8 = 0x12;
/// FETCH_HELLO kind.
pub const RELAY_FETCH_HELLO: u8 = 0x13;
/// REKEY kind.
pub const RELAY_REKEY: u8 = 0x14;
/// REPLY kind.
pub const RELAY_REPLY: u8 = 0x18;
/// RECEIPT kind.
pub const RELAY_RECEIPT: u8 = 0x19;

/// A chain proof or anchor.
pub type Proof = [u8; PROOF_LEN];
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
        /// First relay sequence number wanted; everything below is held.
        since: u64,
    },
    /// Fetch a page of Hellos for a hint.
    FetchHello {
        /// Recipient hint.
        hint: [u8; HELLO_HINT_LEN],
        /// First relay sequence number wanted.
        since: u64,
    },
    /// Replace one chain's anchor.
    Rekey {
        /// Routing tag.
        tag: PairTag,
        /// Which chain.
        role: ChainRole,
        /// Proof from the current chain.
        proof: Proof,
        /// The next generation's anchor.
        anchor: Proof,
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
        /// For FETCH and FETCH_HELLO: the next `since`.
        cursor: u64,
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
    (RELAY_REGISTER..=RELAY_RECEIPT).contains(&kind)
}

fn role_u8(r: ChainRole) -> u8 {
    match r {
        ChainRole::Up => 0,
        ChainRole::Down => 1,
    }
}

/// Encodes `msg`. Every encoding fits in 48 bytes, except a RECEIPT
/// holding more than [`MAX_RECEIPT_HASHES`] hashes, which is truncated.
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
        RelayMsg::Fetch { tag, proof, since } => {
            v.push(RELAY_FETCH);
            v.extend_from_slice(tag);
            v.extend_from_slice(proof);
            put_varint(&mut v, *since);
        }
        RelayMsg::FetchHello { hint, since } => {
            v.push(RELAY_FETCH_HELLO);
            v.extend_from_slice(hint);
            put_varint(&mut v, *since);
        }
        RelayMsg::Rekey {
            tag,
            role,
            proof,
            anchor,
        } => {
            v.push(RELAY_REKEY);
            v.extend_from_slice(tag);
            v.push(role_u8(*role));
            v.extend_from_slice(proof);
            v.extend_from_slice(anchor);
        }
        RelayMsg::Reply {
            request,
            code,
            key,
            retention_s,
            cursor,
        } => {
            v.push(RELAY_REPLY);
            v.push(*request);
            v.push(code.to_u8());
            v.extend_from_slice(key);
            put_varint(&mut v, *retention_s);
            put_varint(&mut v, *cursor);
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
    v
}

/// Parses a relay message. Trailing bytes are an error.
pub fn parse_relay(bytes: &[u8]) -> Result<RelayMsg, DecodeError> {
    let mut r = Reader::new(bytes);
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
        },
        RELAY_FETCH_HELLO => RelayMsg::FetchHello {
            hint: r.array()?,
            since: r.varint()?,
        },
        RELAY_REKEY => RelayMsg::Rekey {
            tag: r.array()?,
            role: match r.u8()? {
                0 => ChainRole::Up,
                1 => ChainRole::Down,
                k => return Err(DecodeError::UnknownVersion(k)),
            },
            proof: r.array()?,
            anchor: r.array()?,
        },
        RELAY_REPLY => RelayMsg::Reply {
            request: r.u8()?,
            code: RelayCode::from_u8(r.u8()?),
            key: r.array()?,
            retention_s: r.varint()?,
            cursor: r.varint()?,
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
