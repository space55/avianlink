//! `UdpHost`: the driver loop (`docs/hosting.md` §3).

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use avianlink_core::{
    Config, ContactStatus, ConversationId, Engine, Error, Event, Identity, LinkConfig, LinkId,
    LinkStats, PublicKey, Queued, Received, Stats, Storage, Timestamp,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::FileStorage;

/// The single link a `UdpHost` registers.
pub const LINK: LinkId = LinkId(0);

/// Longest the loop sleeps, so UI commands stay responsive.
const MAX_WAIT_MS: u64 = 50;

/// Candidate addresses remembered for pending contact requests.
const MAX_CANDIDATES: usize = 64;

/// Current wall-clock time in Unix milliseconds.
pub fn now() -> Timestamp {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    Timestamp::from_millis(ms)
}

/// A cryptographically secure RNG seeded from the operating system.
pub fn os_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("operating system RNG unavailable");
    ChaCha20Rng::from_seed(seed)
}

/// How to run a host.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// Local UDP address to bind.
    pub bind: SocketAddr,
    /// The link's MTU and budget as the engine should see it.
    pub link: LinkConfig,
    /// Engine configuration.
    pub engine: Config,
}

/// A request from the UI thread.
#[derive(Debug)]
pub enum Command {
    /// Queue a message.
    Send {
        /// Conversation.
        to: ConversationId,
        /// Text.
        text: String,
    },
    /// Accept a contact request (`Event::ContactRequest`): add the key,
    /// reachable at the address its Hello came from.
    Accept {
        /// The requesting key.
        key: PublicKey,
    },
    /// Connectivity may have changed: probe unreachable contacts now.
    Nudge,
    /// Ask for a [`StatusReport`].
    Status,
    /// Stop the loop.
    Quit,
}

/// What the host reports to the UI.
#[derive(Debug)]
pub enum HostEvent {
    /// An engine event.
    Engine(Event),
    /// A `Send` was durably queued.
    Queued {
        /// Conversation.
        to: ConversationId,
        /// Its ID, seq and Lamport value.
        queued: Queued,
    },
    /// A `Send` failed (nothing was queued).
    SendFailed(Error),
    /// An `Accept` added the contact.
    Accepted {
        /// The accepted key.
        key: PublicKey,
        /// Its conversation.
        conversation: ConversationId,
    },
    /// An `Accept` failed.
    AcceptFailed(Error),
    /// Answer to [`Command::Status`].
    Status(Box<StatusReport>),
}

/// A snapshot for `/status`.
#[derive(Debug)]
pub struct StatusReport {
    /// Engine-wide counters.
    pub stats: Stats,
    /// The link's counters and budget state.
    pub link: Option<LinkStats>,
    /// Per contact: status and the address in use.
    pub contacts: Vec<(ConversationId, Option<ContactStatus>, Option<SocketAddr>)>,
    /// Undelivered messages.
    pub outbox: usize,
}

/// Failure to start a host.
#[derive(Debug)]
pub enum HostError {
    /// Socket or file system.
    Io(io::Error),
    /// The engine refused (bad config, corrupt storage, wrong identity...).
    Engine(Error),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Engine(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for HostError {}

impl From<io::Error> for HostError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Error> for HostError {
    fn from(e: Error) -> Self {
        Self::Engine(e)
    }
}

/// An engine on a UDP socket with durable storage in a directory.
pub struct UdpHost {
    engine: Engine<FileStorage, ChaCha20Rng>,
    socket: UdpSocket,
    peers: BTreeMap<ConversationId, SocketAddr>,
    /// Where pending contact requests came from. Hellos can be replayed, so
    /// these are only candidates until the contact's own packets confirm
    /// them (`docs/security.md` §6).
    candidates: BTreeMap<PublicKey, SocketAddr>,
}

impl UdpHost {
    /// Opens the node stored in `dir` (restoring it if it exists) and binds
    /// its socket.
    pub fn open(dir: &Path, identity: Identity, config: HostConfig) -> Result<Self, HostError> {
        let mut storage = FileStorage::open(dir.join("state"))?;
        let fresh = storage
            .load(b"v")
            .map_err(|_| HostError::Io(io::Error::other("storage read failed")))?
            .is_none();
        let mut engine = if fresh {
            Engine::new(config.engine, identity, storage, os_rng())?
        } else {
            Engine::restore(config.engine, identity, storage, os_rng())?
        };
        engine.add_link(LINK, config.link)?;
        let socket = UdpSocket::bind(config.bind)?;
        Ok(Self {
            engine,
            socket,
            peers: BTreeMap::new(),
            candidates: BTreeMap::new(),
        })
    }

    /// Adds `key` as a contact (if it is not one already) reachable at
    /// `addr`; returns the conversation.
    pub fn add_peer(&mut self, key: PublicKey, addr: SocketAddr) -> Result<ConversationId, Error> {
        let existing = self
            .engine
            .contacts()
            .find(|(_, k)| *k == key)
            .map(|(c, _)| c);
        let conv = match existing {
            Some(c) => c,
            None => self.engine.add_contact(key)?,
        };
        self.peers.insert(conv, addr);
        Ok(conv)
    }

    /// Accepts a contact request from `key`. Its Hello's source address is
    /// used until the contact's own packets say otherwise.
    pub fn accept(&mut self, key: PublicKey) -> Result<ConversationId, Error> {
        let existing = self
            .engine
            .contacts()
            .find(|(_, k)| *k == key)
            .map(|(c, _)| c);
        let conv = match existing {
            Some(c) => c,
            None => self.engine.add_contact(key)?,
        };
        if let Some(addr) = self.candidates.remove(&key) {
            self.peers.entry(conv).or_insert(addr);
        }
        Ok(conv)
    }

    /// The bound address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The engine, for inspection.
    pub fn engine(&self) -> &Engine<FileStorage, ChaCha20Rng> {
        &self.engine
    }

    /// Runs until [`Command::Quit`] or until either channel closes.
    pub fn run(mut self, commands: Receiver<Command>, events: Sender<HostEvent>) -> io::Result<()> {
        let mut buf = vec![0u8; 65_536];
        loop {
            loop {
                match commands.try_recv() {
                    Ok(Command::Quit) | Err(TryRecvError::Disconnected) => return Ok(()),
                    Ok(cmd) => self.command(cmd, &events),
                    Err(TryRecvError::Empty) => break,
                }
            }
            if !self.pump(&events) {
                return Ok(());
            }
            let t = now();
            let wait = self
                .engine
                .next_timeout()
                .map_or(MAX_WAIT_MS, |n| n.saturating_millis_since(t))
                .clamp(1, MAX_WAIT_MS);
            self.socket
                .set_read_timeout(Some(Duration::from_millis(wait)))?;
            match self.socket.recv_from(&mut buf) {
                Ok((n, src)) => match self.engine.handle_packet(LINK, &buf[..n], now()) {
                    // Only authenticated data packets move an address.
                    Received::Contact(conv) => {
                        self.peers.insert(conv, src);
                    }
                    Received::ContactRequest(key) => {
                        if self.candidates.len() >= MAX_CANDIDATES {
                            self.candidates.pop_first();
                        }
                        self.candidates.insert(key, src);
                    }
                    Received::Ignored => {}
                },
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.engine.handle_timeout(now());
                }
                // ICMP-induced errors (e.g. port unreachable) are transient.
                Err(_) => {}
            }
        }
    }

    fn command(&mut self, cmd: Command, events: &Sender<HostEvent>) {
        let ev = match cmd {
            Command::Send { to, text } => match self.engine.send_text(to, &text, now()) {
                Ok(queued) => HostEvent::Queued { to, queued },
                Err(e) => HostEvent::SendFailed(e),
            },
            Command::Accept { key } => match self.accept(key) {
                Ok(conversation) => HostEvent::Accepted { key, conversation },
                Err(e) => HostEvent::AcceptFailed(e),
            },
            Command::Nudge => {
                self.engine.nudge(now());
                return;
            }
            Command::Status => HostEvent::Status(Box::new(StatusReport {
                stats: self.engine.stats(),
                link: self.engine.link_stats(LINK),
                contacts: self
                    .engine
                    .contacts()
                    .map(|(c, _)| {
                        (
                            c,
                            self.engine.contact_status(c),
                            self.peers.get(&c).copied(),
                        )
                    })
                    .collect(),
                outbox: self.engine.outbox_len(),
            })),
            Command::Quit => return,
        };
        let _ = events.send(ev);
    }

    /// Sends what the engine wants sent and forwards its events. Returns
    /// false once the UI has gone away.
    fn pump(&mut self, events: &Sender<HostEvent>) -> bool {
        let t = now();
        while let Some(tx) = self.engine.poll_transmit(t) {
            if let Some(addr) = self.peers.get(&tx.to) {
                // Send errors (no route, buffer full) are like loss: the
                // engine retransmits.
                let _ = self.socket.send_to(tx.packet.as_bytes(), addr);
            }
        }
        while let Some(ev) = self.engine.poll_event() {
            if events.send(HostEvent::Engine(ev)).is_err() {
                return false;
            }
        }
        true
    }
}
