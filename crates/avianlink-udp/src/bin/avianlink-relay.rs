//! `avianlink-relay`: the relay on a UDP socket with durable storage.
//!
//! ```text
//! avianlink-relay --dir DIR [--bind HOST:PORT (default 0.0.0.0:41000)]
//!                 [--retention-days N] [--mailbox-quota-kib N] [--total-quota-mib N]
//!                 [--push-service HOST:PORT]
//! ```
//!
//! With `--push-service`, clients may register for push notifications, and
//! the relay sends NOTIFY datagrams to that `avianlink-push` (`push.md`).

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use avianlink_core::push::AckCode;
use avianlink_relay::{Notifier, Relay, RelayConfig, MAX_RETENTION_MS};
use avianlink_udp::{now, FileStorage};

const USAGE: &str = "usage: avianlink-relay --dir DIR [--bind HOST:PORT (default 0.0.0.0:41000)] [--retention-days N (1-30, default 7)]
                       [--mailbox-quota-kib N (default 1024)] [--total-quota-mib N (default 1024)]
                       [--push-service HOST:PORT]";

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut config = RelayConfig::default();
    let (mut bind, mut dir, mut service) = (None, None, None);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .cloned()
                .ok_or(format!("{a} needs a value\n{USAGE}"))
        };
        let num = |s: String| s.parse::<u64>().map_err(|_| format!("not a number: {s}"));
        match a.as_str() {
            "--bind" => bind = Some(val()?.parse::<SocketAddr>().map_err(|e| e.to_string())?),
            "--dir" => dir = Some(PathBuf::from(val()?)),
            "--retention-days" => config.retention_ms = num(val()?)? * 24 * 3_600_000,
            "--mailbox-quota-kib" => config.mailbox_quota_bytes = num(val()?)? * 1024,
            "--total-quota-mib" => config.total_quota_bytes = num(val()?)? << 20,
            "--push-service" => {
                let s = val()?;
                let addr = s
                    .to_socket_addrs()
                    .map_err(|e| format!("--push-service {s}: {e}"))?
                    .next()
                    .ok_or(format!("--push-service {s}: no address"))?;
                service = Some(addr);
            }
            _ => return Err(USAGE.to_string()),
        }
    }
    let bind = bind.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 41_000)));
    let dir = dir.ok_or(USAGE)?;
    if config.retention_ms > MAX_RETENTION_MS {
        return Err("--retention-days is at most 30".into());
    }
    config.push = service.is_some();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let storage = FileStorage::open(dir.join("relay")).map_err(|e| e.to_string())?;
    let mut relay: Relay<FileStorage, SocketAddr> =
        Relay::open(config, storage).map_err(|e| e.to_string())?;
    let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    eprintln!(
        "avianlink-relay on {}: retention {} days, {} mailboxes, {} KiB held, push {}",
        socket.local_addr().map_err(|e| e.to_string())?,
        config.retention_ms / (24 * 3_600_000),
        relay.mailbox_count(),
        relay.used_bytes() / 1024,
        service.map_or("off".to_string(), |s| format!("via {s}"))
    );
    let mut notifier = Notifier::new();
    let mut buf = vec![0u8; 65_536];
    let mut last_report = Instant::now();
    loop {
        let t = now();
        let wait = [relay.next_timeout(), notifier.next_timeout()]
            .into_iter()
            .flatten()
            .min()
            .map_or(1_000, |n| n.saturating_millis_since(t))
            .clamp(1, 1_000);
        socket
            .set_read_timeout(Some(Duration::from_millis(wait)))
            .map_err(|e| e.to_string())?;
        match socket.recv_from(&mut buf) {
            Ok((n, from)) if Some(from) == service => {
                if let Some(ack) = notifier.handle(&buf[..n]) {
                    if ack.code == AckCode::Gone {
                        relay.push_gone(&ack.handle);
                    }
                }
            }
            Ok((n, from)) => relay.handle(from, &buf[..n], now()),
            Err(_) => relay.handle_timeout(now()),
        }
        // Cheap, so every turn: re-sends must not wait for a quiet socket.
        notifier.handle_timeout(now());
        if let Some(service) = service {
            while let Some(push) = relay.poll_push() {
                let mut id = [0u8; 8];
                getrandom::fill(&mut id).map_err(|e| e.to_string())?;
                notifier.push(push, u64::from_be_bytes(id), now());
            }
            while let Some(bytes) = notifier.poll_transmit() {
                let _ = socket.send_to(&bytes, service);
            }
        }
        while let Some((to, bytes)) = relay.poll_transmit() {
            // Send failures look like loss; clients retry.
            let _ = socket.send_to(&bytes, to);
        }
        if last_report.elapsed() >= Duration::from_secs(60) {
            last_report = Instant::now();
            eprintln!(
                "{} mailboxes, {} push handles, {} KiB held; {:?}; {:?}",
                relay.mailbox_count(),
                relay.push_handle_count(),
                relay.used_bytes() / 1024,
                relay.stats(),
                notifier.stats()
            );
        }
    }
}
