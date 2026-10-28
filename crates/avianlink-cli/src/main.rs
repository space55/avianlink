//! Terminal demo: two avianlink peers chatting over UDP
//! (`docs/hosting.md` §4).
//!
//! ```text
//! avianlink init   DIR
//! avianlink whoami DIR
//! avianlink chat   DIR --bind HOST:PORT [--peer KEY@HOST:PORT]
//!                  [--profile NAME | --mtu N [--rate BYTES_PER_S]]
//! avianlink chat   DIR --bind HOST:PORT --relay HOST:PORT [--peer KEY]
//! ```

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use avianlink_core::{
    format_fingerprint, Config, ConversationId, Event, LinkBudget, LinkConfig, MessageId,
    PublicKey, Timestamp,
};
use avianlink_sim::Scenario;
use avianlink_udp::{
    init_node, load_identity, now, parse_public_key, public_key_hex, Command, HostConfig,
    HostError, HostEvent, UdpHost,
};

const USAGE: &str = "usage:
  avianlink init   DIR
  avianlink whoami DIR
  avianlink chat   DIR --bind HOST:PORT [--peer KEY@HOST:PORT]
                   [--profile NAME | --mtu N [--rate BYTES_PER_S]]
  avianlink chat   DIR --bind HOST:PORT --relay HOST:PORT [--peer KEY]
                   (through a store-and-forward relay; peers need not be
                   online at the same time; MTU defaults to 48)

In chat, type a line to send it. Commands: /status, /nudge, /accept,
/add KEY@HOST:PORT (or /add KEY through a relay), /quit.
Without --peer, wait for a contact request: compare its fingerprint with the
sender out of band, then /accept it.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("init") | Some("whoami") if args.len() == 2 => whoami(&args[1], args[0] == "init"),
        Some("chat") if args.len() >= 2 => chat(&args[1], &args[2..]),
        _ => Err(USAGE.to_string()),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

fn whoami(dir: &str, init: bool) -> Result<(), String> {
    let dir = PathBuf::from(dir);
    let existing = load_identity(&dir).map_err(|e| e.to_string())?;
    let id = match (existing, init) {
        (Some(id), true) => {
            eprintln!("(identity already existed; not replaced)");
            id
        }
        (Some(id), false) => id,
        (None, true) => init_node(&dir).map_err(|e| e.to_string())?,
        (None, false) => return Err(format!("no identity in {}; run init", dir.display())),
    };
    let key = id.public_key();
    println!("address:     {}", public_key_hex(&key));
    println!("fingerprint: {}", format_fingerprint(&key.fingerprint()));
    Ok(())
}

fn hms(t: Timestamp) -> String {
    let s = t.as_millis() / 1000;
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

fn ago(from: Timestamp) -> String {
    let ms = now().saturating_millis_since(from);
    match ms {
        0..=9_999 => format!("{:.1}s", ms as f64 / 1e3),
        10_000..=3_599_999 => format!("{}m{:02}s", ms / 60_000, (ms / 1000) % 60),
        _ => format!("{}h{:02}m", ms / 3_600_000, (ms / 60_000) % 60),
    }
}

fn resolve(s: &str) -> Result<SocketAddr, String> {
    s.to_socket_addrs()
        .map_err(|e| format!("{s}: {e}"))?
        .next()
        .ok_or_else(|| format!("{s}: no address"))
}

fn chat(dir: &str, opts: &[String]) -> Result<(), String> {
    let (mut bind, mut peer, mut profile, mut relay) = (None, None, None, None);
    let (mut mtu, mut rate) = (None, None);
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{o} needs a value"));
        match o.as_str() {
            "--bind" => bind = Some(resolve(&val()?)?),
            "--peer" => peer = Some(val()?),
            "--profile" => profile = Some(val()?),
            "--mtu" => mtu = Some(val()?.parse().map_err(|_| "bad --mtu")?),
            "--relay" => relay = Some(resolve(&val()?)?),
            "--rate" => rate = Some(val()?.parse().map_err(|_| "bad --rate")?),
            _ => return Err(format!("unknown option {o}\n{USAGE}")),
        }
    }
    let bind = bind.ok_or("--bind is required")?;
    let peer = match (peer, relay) {
        (Some(p), Some(_)) => {
            let key = parse_public_key(&p).ok_or("with --relay, --peer is just the 64-hex KEY")?;
            Some((key, None))
        }
        (Some(p), None) => {
            let (key, addr) = p.split_once('@').ok_or("--peer must be KEY@HOST:PORT")?;
            let key = parse_public_key(key).ok_or("peer KEY must be 64 hex characters")?;
            Some((key, Some(resolve(addr)?)))
        }
        (None, _) => None,
    };
    // Through a relay, packets must suit whatever link the recipient
    // fetches over: the smallest MTU unless told otherwise.
    let mtu = mtu.unwrap_or(if relay.is_some() { 48 } else { 1200 });
    let link = match profile {
        Some(name) => {
            let sc = Scenario::named(&name, 0).ok_or(format!("unknown profile {name}"))?;
            sc.link.engine_link()
        }
        None => LinkConfig {
            mtu,
            budget: rate.map_or(LinkBudget::Unlimited, LinkBudget::BytesPerSecond),
            cost: 1,
        },
    };

    let dir = PathBuf::from(dir);
    let identity = load_identity(&dir)
        .map_err(|e| e.to_string())?
        .ok_or(format!("no identity in {}; run init first", dir.display()))?;
    let me = identity.public_key();
    let config = HostConfig {
        bind,
        link,
        engine: Config::default(),
        relay,
    };
    let mut host = UdpHost::open(&dir, identity, config).map_err(|e| match e {
        HostError::Engine(avianlink_core::Error::StateMissing) => format!(
            "{} has an identity but its state is gone. Reusing the identity would reuse \
             encryption nonces, so run `avianlink init` in a new directory and re-share \
             your address.",
            dir.display()
        ),
        e => e.to_string(),
    })?;
    let local = host.local_addr().map_err(|e| e.to_string())?;
    // The conversation lines are sent to, and the latest contact request.
    let conv: Arc<Mutex<Option<ConversationId>>> = Arc::new(Mutex::new(None));
    let request: Arc<Mutex<Option<PublicKey>>> = Arc::new(Mutex::new(None));
    match peer {
        Some((key, Some(addr))) => {
            *conv.lock().unwrap() = Some(host.add_peer(key, addr).map_err(|e| e.to_string())?);
            println!(
                "avianlink: {} on {local} → peer {} at {addr}",
                format_fingerprint(&me.fingerprint()),
                format_fingerprint(&key.fingerprint()),
            );
        }
        Some((key, None)) => {
            *conv.lock().unwrap() = Some(host.add_contact(key).map_err(|e| e.to_string())?);
            println!(
                "avianlink: {} on {local} → peer {} through relay {}",
                format_fingerprint(&me.fingerprint()),
                format_fingerprint(&key.fingerprint()),
                relay.map_or("?".into(), |r| r.to_string()),
            );
        }
        None => println!(
            "avianlink: {} on {local}, waiting for a contact request (address {})",
            format_fingerprint(&me.fingerprint()),
            public_key_hex(&me),
        ),
    }
    println!(
        "link MTU {}, budget {:?}; {} undelivered from before",
        link.mtu,
        link.budget,
        host.engine().outbox_len()
    );

    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (ev_tx, ev_rx) = mpsc::channel();
    let host_thread = std::thread::spawn(move || host.run(cmd_rx, ev_tx));

    // stdin → commands, on its own thread.
    let tx = cmd_tx.clone();
    let (to, pending) = (conv.clone(), request.clone());
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            let cmd = match line.trim() {
                "" => continue,
                "/quit" => Command::Quit,
                "/status" => Command::Status,
                "/nudge" => Command::Nudge,
                l if l.starts_with("/add ") => {
                    let arg = l["/add ".len()..].trim();
                    let (key, addr) = match arg.split_once('@') {
                        Some((k, a)) => (k, resolve(a).ok()),
                        // Through a relay, no address is needed.
                        None => (arg, Some(SocketAddr::from(([0, 0, 0, 0], 0)))),
                    };
                    match (parse_public_key(key), addr) {
                        (Some(key), Some(addr)) => Command::AddPeer { key, addr },
                        _ => {
                            println!("   usage: /add KEY@HOST:PORT (or /add KEY with --relay)");
                            continue;
                        }
                    }
                }
                "/accept" => match *pending.lock().unwrap() {
                    Some(key) => Command::Accept { key },
                    None => {
                        println!("   no contact request to accept");
                        continue;
                    }
                },
                _ => match *to.lock().unwrap() {
                    Some(to) => Command::Send { to, text: line },
                    None => {
                        println!("   no peer yet: wait for a contact request and /accept it");
                        continue;
                    }
                },
            };
            let quit = matches!(cmd, Command::Quit);
            if tx.send(cmd).is_err() || quit {
                break;
            }
        }
        let _ = tx.send(Command::Quit);
    });

    // Our messages: id → (seq, queued at).
    let mut ours: BTreeMap<MessageId, (u64, Timestamp)> = BTreeMap::new();
    let out = io::stdout();
    loop {
        let ev = match ev_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(ev) => ev,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if host_thread.is_finished() {
                    break;
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let mut o = out.lock();
        let line = match ev {
            HostEvent::Queued { queued, .. } => {
                ours.insert(queued.id, (queued.seq, now()));
                format!("   queued   #{} (lamport {})", queued.seq, queued.lamport)
            }
            HostEvent::SendFailed(e) => format!("   not sent: {e}"),
            HostEvent::Engine(Event::ContactRequest { public_key, .. }) => {
                *request.lock().unwrap() = Some(public_key);
                format!(
                    "   ?? contact request from {} (address {}).\n      Compare the fingerprint with the sender, then /accept.",
                    format_fingerprint(&public_key.fingerprint()),
                    public_key_hex(&public_key),
                )
            }
            HostEvent::Settled => {
                "   ✓ everything is stored on the relay: safe to go offline".to_string()
            }
            HostEvent::Engine(Event::MessageStored { id, .. }) => match ours.get(&id) {
                Some((seq, t)) => format!("   stored   #{seq} on the relay after {}", ago(*t)),
                None => continue,
            },
            HostEvent::Accepted { key, conversation } => {
                *conv.lock().unwrap() = Some(conversation);
                *request.lock().unwrap() = None;
                format!("   accepted {}", format_fingerprint(&key.fingerprint()))
            }
            HostEvent::AcceptFailed(e) => format!("   not accepted: {e}"),
            HostEvent::PeerAdded { key, conversation } => {
                let mut c = conv.lock().unwrap();
                if c.is_none() {
                    *c = Some(conversation);
                }
                format!("   added {}", format_fingerprint(&key.fingerprint()))
            }
            HostEvent::PeerFailed { key, error } => format!(
                "   could not add {}: {error}",
                format_fingerprint(&key.fingerprint())
            ),
            HostEvent::Engine(Event::MessageTransmitted { id, .. }) => match ours.get(&id) {
                Some((seq, t)) => format!("   sent     #{seq} after {}", ago(*t)),
                None => continue,
            },
            HostEvent::Engine(Event::MessageDelivered { id, .. }) => match ours.remove(&id) {
                Some((seq, t)) => format!("   ✓ delivered #{seq} after {}", ago(t)),
                None => "   ✓ delivered (from before restart)".to_string(),
            },
            HostEvent::Engine(Event::MessageReceived(m)) => {
                let when = m
                    .sender_time
                    .map(|t| format!("written {} UTC, ", hms(t)))
                    .unwrap_or_default();
                let late = if m.missing_before > 0 {
                    format!(" [{} earlier still on the way]", m.missing_before)
                } else {
                    String::new()
                };
                format!(
                    "<< #{} ({when}lamport {}){late}: {}",
                    m.seq, m.lamport, m.text
                )
            }
            HostEvent::Engine(Event::MessagesSkipped { count, .. }) => {
                format!("   !! {count} earlier messages were delivered to a previous install")
            }
            HostEvent::Engine(Event::SyncDiverged {
                first_seq, last_seq, ..
            }) => format!(
                "   !! peer's history differs from ours for #{first_seq}..#{last_seq} (restored backup?)"
            ),
            HostEvent::Engine(_) => continue,
            HostEvent::Status(s) => {
                let mut v = format!(
                    "   status: {} undelivered; sent {} pkts / {} B, received {}; drops: {} unauth, {} replay",
                    s.outbox,
                    s.stats.packets_sent,
                    s.stats.bytes_sent,
                    s.stats.packets_received,
                    s.stats.packets_dropped_unauthenticated,
                    s.stats.packets_dropped_replay
                );
                for (_, st, addr) in s.contacts {
                    if let Some(st) = st {
                        v.push_str(&format!(
                            "\n   peer at {}: last heard {}, rtt {}, rto {} ms, {}; loss in {}‰ / out {}‰",
                            addr.map_or("?".into(), |a| a.to_string()),
                            st.last_heard.map_or("never".into(), |t| format!("{} ago", ago(t))),
                            st.srtt_ms.map_or("?".into(), |r| format!("{r} ms")),
                            st.rto_ms,
                            if st.unreachable { "UNREACHABLE (probing)" } else { "reachable" },
                            st.loss_in_permille.map_or("?".into(), |l| l.to_string()),
                            st.loss_out_permille.map_or("?".into(), |l| l.to_string()),
                        ));
                    }
                }
                if let Some(l) = s.link.and_then(|l| l.budget_blocked_until) {
                    v.push_str(&format!("\n   link budget exhausted until {} UTC", hms(l)));
                }
                v
            }
            // Events newer than this CLI.
            _ => continue,
        };
        let _ = writeln!(o, "{line}");
    }
    match host_thread.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("host thread panicked".to_string()),
    }
}
