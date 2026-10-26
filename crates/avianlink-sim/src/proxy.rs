//! A real-time UDP impairment proxy driven by the simulator's [`Channel`]
//! model (`udp-impair`, `docs/hosting.md` §1). Host A talks to the proxy's
//! `a` socket, host B to its `b` socket, and each direction gets its own
//! channel. Outages are shared.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::impair::{Channel, ChannelStats, LinkProfile, Outages};

/// Packets in flight: (due ms, insertion order, direction, bytes).
type InFlight = BinaryHeap<Reverse<(u64, u64, usize, Vec<u8>)>>;

/// A two-sided impairing relay.
pub struct Proxy {
    socks: [UdpSocket; 2],
    /// Where to deliver to: A (reached via socket 0) and B (via socket 1).
    peers: [Option<SocketAddr>; 2],
    /// Direction 0 is A→B, 1 is B→A.
    channels: [Channel; 2],
    outages: Outages,
    start: Instant,
    queue: InFlight,
    order: u64,
}

fn stream(seed: u64, n: u64) -> rand_chacha::ChaCha20Rng {
    let mut rng = crate::seeded_rng(seed);
    rng.set_stream(n);
    rng
}

impl Proxy {
    /// Binds the two sides. `to_a` / `to_b` are the hosts' addresses if
    /// known; otherwise each is learned from the first packet on its side.
    pub fn bind(
        listen_a: SocketAddr,
        listen_b: SocketAddr,
        to_a: Option<SocketAddr>,
        to_b: Option<SocketAddr>,
        profile: LinkProfile,
        seed: u64,
    ) -> io::Result<Self> {
        let socks = [UdpSocket::bind(listen_a)?, UdpSocket::bind(listen_b)?];
        for s in &socks {
            s.set_nonblocking(true)?;
        }
        Ok(Self {
            socks,
            peers: [to_a, to_b],
            channels: [
                Channel::new(profile, stream(seed, 1)),
                Channel::new(profile, stream(seed, 2)),
            ],
            outages: Outages::new(profile.outage, stream(seed, 3), 0),
            start: Instant::now(),
            queue: BinaryHeap::new(),
            order: 0,
        })
    }

    /// Sets where to deliver to on each side.
    pub fn set_peers(&mut self, to_a: Option<SocketAddr>, to_b: Option<SocketAddr>) {
        self.peers = [to_a, to_b];
    }

    /// The bound addresses of the A and B sides.
    pub fn local_addrs(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        Ok((self.socks[0].local_addr()?, self.socks[1].local_addr()?))
    }

    /// Per-direction counters (0: A→B).
    pub fn stats(&self) -> [ChannelStats; 2] {
        [self.channels[0].stats(), self.channels[1].stats()]
    }

    /// Whether the shared link is down right now.
    pub fn is_down(&mut self) -> bool {
        let t = self.now();
        self.outages.is_down(t)
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Relays until `stop` is set.
    pub fn run(&mut self, stop: &AtomicBool) -> io::Result<()> {
        while !stop.load(Ordering::Relaxed) {
            self.run_for(Duration::from_millis(100))?;
        }
        Ok(())
    }

    /// Relays for `d`.
    pub fn run_for(&mut self, d: Duration) -> io::Result<()> {
        let mut buf = vec![0u8; 65_536];
        let until = Instant::now() + d;
        while Instant::now() < until {
            let now = self.now();
            while let Some(Reverse((due, _, _, _))) = self.queue.peek() {
                if *due > now {
                    break;
                }
                let Some(Reverse((_, _, dir, bytes))) = self.queue.pop() else {
                    break;
                };
                // A→B leaves through B's side, and vice versa.
                let out = 1 - dir;
                if let Some(to) = self.peers[out] {
                    let _ = self.socks[out].send_to(&bytes, to);
                }
            }
            let mut idle = true;
            for side in 0..2 {
                match self.socks[side].recv_from(&mut buf) {
                    Ok((n, src)) => {
                        idle = false;
                        self.peers[side] = Some(src);
                        let copies =
                            self.channels[side].send(now, buf[..n].to_vec(), &mut self.outages);
                        for (at, bytes) in copies {
                            self.order += 1;
                            self.queue.push(Reverse((at, self.order, side, bytes)));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            if idle {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
}
