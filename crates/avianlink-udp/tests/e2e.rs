//! Two real `UdpHost`s on loopback, talking through an impairing proxy
//! (the simulator's channel model in real time).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use avianlink_core::{Config, Event, LinkBudget, LinkConfig, MemoryStorage, PublicKey};
use avianlink_relay::{Relay, RelayConfig};
use avianlink_sim::proxy::Proxy;
use avianlink_sim::Scenario;
use avianlink_udp::{init_node, Command, HostConfig, HostEvent, UdpHost};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("avianlink-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Runs `per_side` messages each way over the named scenario's link and
/// returns how long full delivery took.
fn exchange(scenario: &str, per_side: usize, limit: Duration) -> Duration {
    let sc = Scenario::named(scenario, 7).unwrap();
    let mut link = sc.link;
    link.outage = None; // keep wall-clock time short; outages are sim-tested
    let mut proxy = Proxy::bind(localhost(), localhost(), None, None, link, 7).unwrap();
    let (pa, pb) = proxy.local_addrs().unwrap();

    let (da, db) = (dir(&format!("{scenario}-a")), dir(&format!("{scenario}-b")));
    let ida = init_node(&da).unwrap();
    let idb = init_node(&db).unwrap();
    let (ka, kb) = (ida.public_key(), idb.public_key());
    let cfg = |_: ()| HostConfig {
        bind: localhost(),
        link: link.engine_link(),
        engine: Config::default(),
        relay: None,
    };
    let mut a = UdpHost::open(&da, ida, cfg(())).unwrap();
    let mut b = UdpHost::open(&db, idb, cfg(())).unwrap();
    // Each host reaches the other through the proxy side facing it.
    let conv_a = a.add_peer(kb, pa).unwrap();
    let conv_b = b.add_peer(ka, pb).unwrap();
    // The proxy delivers to the hosts' real sockets.
    let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());
    proxy.set_peers(Some(aa), Some(ba));

    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let proxy_thread = std::thread::spawn(move || proxy.run(&s2).unwrap());
    let (ca, ra) = mpsc::channel();
    let (ea, a_events) = mpsc::channel();
    let (cb, rb) = mpsc::channel();
    let (eb, b_events) = mpsc::channel();
    let ta = std::thread::spawn(move || a.run(ra, ea).unwrap());
    let tb = std::thread::spawn(move || b.run(rb, eb).unwrap());

    let start = Instant::now();
    for i in 0..per_side {
        let text = format!("a→b {i} {}", "x".repeat(150));
        ca.send(Command::Send { to: conv_a, text }).unwrap();
        let text = format!("b→a {i} {}", "y".repeat(150));
        cb.send(Command::Send { to: conv_b, text }).unwrap();
    }
    let (mut got_a, mut got_b, mut delivered) = (0, 0, 0);
    while (got_a < per_side || got_b < per_side || delivered < 2 * per_side)
        && start.elapsed() < limit
    {
        for (rx, got) in [(&a_events, &mut got_a), (&b_events, &mut got_b)] {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    HostEvent::Engine(Event::MessageReceived(m)) => {
                        assert!(m.text.len() > 150);
                        *got += 1;
                    }
                    HostEvent::Engine(Event::MessageDelivered { .. }) => delivered += 1,
                    HostEvent::SendFailed(e) => panic!("send failed: {e}"),
                    _ => {}
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = start.elapsed();
    ca.send(Command::Quit).unwrap();
    cb.send(Command::Quit).unwrap();
    ta.join().unwrap();
    tb.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    proxy_thread.join().unwrap();
    assert_eq!(
        (got_a, got_b, delivered),
        (per_side, per_side, 2 * per_side),
        "after {took:?}"
    );
    let _ = std::fs::remove_dir_all(&da);
    let _ = std::fs::remove_dir_all(&db);
    took
}

#[test]
fn chat_over_loopback_edge_2g() {
    let took = exchange("edge_2g", 10, Duration::from_secs(60));
    eprintln!("edge_2g: 20 messages exchanged in {took:?}");
}

/// The Phase 6 link in miniature: disaster_cellular's ~35% bursty loss,
/// heavy-tailed delay, corruption and duplication over real sockets
/// (outages excluded to bound wall time).
#[test]
fn chat_over_loopback_disaster_cellular() {
    let took = exchange("disaster_cellular", 10, Duration::from_secs(240));
    eprintln!("disaster_cellular: 20 messages exchanged in {took:?}");
}

/// A node whose state is gone refuses to start with its old identity
/// (D-046): it would restart packet counters and reuse nonces.
#[test]
fn lost_state_refuses_the_old_identity() {
    let d = dir("lost-state");
    let id = init_node(&d).unwrap();
    std::fs::remove_dir_all(d.join("state")).unwrap();
    let cfg = HostConfig {
        bind: localhost(),
        link: Scenario::named("clean", 0).unwrap().link.engine_link(),
        engine: Config::default(),
        relay: None,
    };
    match UdpHost::open(&d, id, cfg) {
        Err(avianlink_udp::HostError::Engine(avianlink_core::Error::StateMissing)) => {}
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("opened without state"),
    }
}

/// Runs an in-process relay on a real UDP socket until `stop`.
fn spawn_relay(stop: Arc<AtomicBool>) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let socket = std::net::UdpSocket::bind(localhost()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let addr = socket.local_addr().unwrap();
    let t = std::thread::spawn(move || {
        let mut relay: Relay<MemoryStorage, SocketAddr> =
            Relay::open(RelayConfig::default(), MemoryStorage::new()).unwrap();
        let mut buf = vec![0u8; 65_536];
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, from)) = socket.recv_from(&mut buf) {
                relay.handle(from, &buf[..n], avianlink_udp::now());
            }
            while let Some((to, bytes)) = relay.poll_transmit() {
                let _ = socket.send_to(&bytes, to);
            }
        }
    });
    (addr, t)
}

/// Opens the node in `dir` through `relay`, runs it until `until` says
/// stop (or `limit`), and returns what it reported.
fn relay_turn(
    dir: &std::path::Path,
    relay: SocketAddr,
    peer: PublicKey,
    send: Option<&str>,
    limit: Duration,
    until: impl Fn(&[HostEvent]) -> bool,
) -> Vec<HostEvent> {
    let id = avianlink_udp::load_identity(dir).unwrap().unwrap();
    let cfg = HostConfig {
        bind: localhost(),
        link: LinkConfig {
            mtu: 48,
            budget: LinkBudget::Unlimited,
            cost: 1,
        },
        engine: Config::default(),
        relay: Some(relay),
    };
    let mut host = UdpHost::open(dir, id, cfg).unwrap();
    let conv = host.add_contact(peer).unwrap();
    let (cmd, rx) = mpsc::channel();
    let (tx, events) = mpsc::channel();
    let t = std::thread::spawn(move || host.run(rx, tx).unwrap());
    if let Some(text) = send {
        cmd.send(Command::Send {
            to: conv,
            text: text.to_string(),
        })
        .unwrap();
    }
    let start = Instant::now();
    let mut got = Vec::new();
    while start.elapsed() < limit && !until(&got) {
        while let Ok(ev) = events.try_recv() {
            got.push(ev);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cmd.send(Command::Quit).unwrap();
    t.join().unwrap();
    got.extend(events.try_iter());
    got
}

fn has(evs: &[HostEvent], f: fn(&Event) -> bool) -> bool {
    evs.iter()
        .any(|e| matches!(e, HostEvent::Engine(ev) if f(ev)))
}

/// A and B are never online together: each turn the node starts, collects,
/// sends, sees its message stored at the relay, and quits (D-045).
#[test]
fn turns_through_a_udp_relay() {
    let stop = Arc::new(AtomicBool::new(false));
    let (relay, relay_thread) = spawn_relay(stop.clone());
    let (da, db) = (dir("relay-a"), dir("relay-b"));
    let (ka, kb) = (
        init_node(&da).unwrap().public_key(),
        init_node(&db).unwrap().public_key(),
    );
    let limit = Duration::from_secs(20);
    let stored = |e: &Event| matches!(e, Event::MessageStored { .. });
    // A: send, and leave once the relay holds it.
    let a1 = relay_turn(&da, relay, kb, Some(&"from A ".repeat(20)), limit, |evs| {
        has(evs, stored)
    });
    assert!(has(&a1, stored), "A's message stored at the relay");
    // B: collect A's message, reply, leave once the reply is stored.
    // It leaves only once settled: its ACK of A's message is stored too.
    let b1 = relay_turn(&db, relay, ka, Some("from B"), limit, |evs| {
        has(evs, stored) && settled_after(evs, |e| matches!(e, Event::MessageReceived(_)))
    });
    assert!(has(
        &b1,
        |e| matches!(e, Event::MessageReceived(m) if m.text.starts_with("from A"))
    ));
    // A again: B's reply, and B's ACK of A's message.
    let a2 = relay_turn(&da, relay, kb, None, limit, |evs| {
        has(evs, |e| matches!(e, Event::MessageReceived(_)))
            && has(evs, |e| matches!(e, Event::MessageDelivered { .. }))
    });
    assert!(has(
        &a2,
        |e| matches!(e, Event::MessageReceived(m) if m.text == "from B")
    ));
    assert!(has(&a2, |e| matches!(e, Event::MessageDelivered { .. })));
    stop.store(true, Ordering::Relaxed);
    relay_thread.join().unwrap();
    let _ = std::fs::remove_dir_all(&da);
    let _ = std::fs::remove_dir_all(&db);
}

/// Settled after the last event of interest: safe to go offline.
fn settled_after(evs: &[HostEvent], f: fn(&Event) -> bool) -> bool {
    let Some(i) = evs
        .iter()
        .rposition(|e| matches!(e, HostEvent::Engine(ev) if f(ev)))
    else {
        return false;
    };
    evs[i..].iter().any(|e| matches!(e, HostEvent::Settled))
}
