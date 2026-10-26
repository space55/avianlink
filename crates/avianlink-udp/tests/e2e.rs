//! Two real `UdpHost`s on loopback, talking through an impairing proxy
//! (the simulator's channel model in real time).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use avianlink_core::{Config, Event};
use avianlink_sim::proxy::Proxy;
use avianlink_sim::Scenario;
use avianlink_udp::{load_or_create_identity, Command, HostConfig, HostEvent, UdpHost};

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
    let (ida, _) = load_or_create_identity(&da).unwrap();
    let (idb, _) = load_or_create_identity(&db).unwrap();
    let (ka, kb) = (ida.public_key(), idb.public_key());
    let cfg = |_: ()| HostConfig {
        bind: localhost(),
        link: link.engine_link(),
        engine: Config::default(),
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
