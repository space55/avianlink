//! Real-time UDP impairment proxy using a simulator profile or scenario.
//!
//! ```text
//! udp-impair --a HOST:PORT --b HOST:PORT [--to-a ADDR] [--to-b ADDR]
//!            [--profile NAME] [--seed N]
//! ```
//!
//! Point host A's peer address at `--a` and host B's at `--b`. NAME is any
//! `simrun` scenario (default `disaster_cellular`); its link profile,
//! including outages, is applied in real time.

use std::net::SocketAddr;
use std::time::Duration;

use avianlink_sim::proxy::Proxy;
use avianlink_sim::Scenario;

fn main() {
    let mut a: Option<SocketAddr> = None;
    let mut b: Option<SocketAddr> = None;
    let (mut to_a, mut to_b) = (None, None);
    let mut profile = "disaster_cellular".to_string();
    let mut seed = 1u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut val = || {
            args.next()
                .unwrap_or_else(|| usage(&format!("{arg} needs a value")))
        };
        match arg.as_str() {
            "--a" => a = Some(addr(&val())),
            "--b" => b = Some(addr(&val())),
            "--to-a" => to_a = Some(addr(&val())),
            "--to-b" => to_b = Some(addr(&val())),
            "--profile" => profile = val(),
            "--seed" => seed = val().parse().unwrap_or_else(|_| usage("bad --seed")),
            _ => usage(&format!("unknown argument {arg}")),
        }
    }
    let (Some(a), Some(b)) = (a, b) else {
        usage("--a and --b are required")
    };
    let sc = Scenario::named(&profile, seed)
        .unwrap_or_else(|| usage(&format!("unknown profile {profile}")));
    let mut proxy = Proxy::bind(a, b, to_a, to_b, sc.link, seed).unwrap_or_else(|e| {
        eprintln!("udp-impair: {e}");
        std::process::exit(1)
    });
    eprintln!(
        "udp-impair: {profile} (MTU {}), A side {a}, B side {b}",
        sc.link.mtu
    );
    loop {
        if let Err(e) = proxy.run_for(Duration::from_secs(10)) {
            eprintln!("udp-impair: {e}");
            std::process::exit(1);
        }
        let [ab, ba] = proxy.stats();
        let state = if proxy.is_down() { "DOWN" } else { "up" };
        eprintln!(
            "udp-impair: link {state} | A→B sent {} delivered {} lost {} outage {} | B→A sent {} delivered {} lost {} outage {}",
            ab.sent, ab.delivered, ab.lost, ab.lost_outage, ba.sent, ba.delivered, ba.lost, ba.lost_outage
        );
    }
}

fn addr(s: &str) -> SocketAddr {
    s.parse()
        .unwrap_or_else(|_| usage(&format!("bad address {s}")))
}

fn usage(msg: &str) -> ! {
    eprintln!("udp-impair: {msg}");
    eprintln!("usage: udp-impair --a HOST:PORT --b HOST:PORT [--to-a ADDR] [--to-b ADDR] [--profile NAME] [--seed N]");
    std::process::exit(2)
}
