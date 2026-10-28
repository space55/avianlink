//! Runs simulator scenarios and prints metrics.
//!
//! ```text
//! simrun [--profile NAME|all|everything] [--seed N] [--seeds K] [--messages N]
//!        [--interval-ms N] [--verbose] [--csv] [--fec off|xor|rs]
//!        [--hello off|unconfirmed|backoff]
//!        [--mix SHORT,MEDIUM] [--fec-sources K] [--fec-flush MS] [--mtu BYTES]
//!        [--deep-after MS] [--max-probe MS] [--nudge]
//!        [--max-rto MS] [--min-rto MS] [--initial-rto MS] [--var-mult N] [--grace N]
//!
//! NAME is a profile (clean, geo_satellite, edge_2g, disaster_cellular,
//! lora_like) or a stress scenario (harsh_64, harsh_64_crashy,
//! disaster_hostile, bursty_loss). `all` runs
//! the profiles; `everything` adds the stress scenarios.
//! ```

use avianlink_core::{FecMode, HelloMode};
use avianlink_sim::{Profile, Report, Scenario, TurnsScenario};

fn main() {
    let mut profiles: Vec<&str> = Scenario::NAMES[..5].to_vec();
    let mut seed = 1u64;
    let mut seeds = 1u64;
    let mut messages = None;
    let mut interval = None;
    let mut verbose = false;
    let mut csv = false;
    let mut fec = None;
    let mut hello = None;
    let mut mix: Option<(f64, f64)> = None;
    let mut nudge = false;
    let mut tweak: Vec<(String, u64)> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || {
            args.next()
                .unwrap_or_else(|| usage(&format!("{a} needs a value")))
        };
        match a.as_str() {
            "--profile" => {
                let v = val();
                // Relay turns (D-045): `turns_<profile>` or `turns_all`.
                if let Some(p) = v.strip_prefix("turns_") {
                    let list: Vec<Profile> = match p {
                        "all" => Profile::ALL.to_vec(),
                        p => vec![Profile::from_name(p)
                            .unwrap_or_else(|| usage(&format!("unknown profile {p}")))],
                    };
                    let all: Vec<String> = std::env::args().collect();
                    let k = all
                        .iter()
                        .position(|a| a == "--seeds")
                        .and_then(|i| all.get(i + 1))
                        .map_or(1, |s| num(s));
                    run_turns(&list, k);
                }
                profiles = match v.as_str() {
                    "all" => Scenario::NAMES[..5].to_vec(),
                    "everything" => Scenario::NAMES.to_vec(),
                    _ => vec![Scenario::NAMES
                        .into_iter()
                        .find(|n| *n == v)
                        .unwrap_or_else(|| usage(&format!("unknown scenario {v}")))],
                };
            }
            "--seed" => seed = num(&val()),
            "--seeds" => seeds = num(&val()),
            "--messages" => messages = Some(num(&val()) as usize),
            "--interval-ms" => interval = Some(num(&val())),
            "--verbose" | "-v" => verbose = true,
            "--csv" => csv = true,
            "--nudge" => nudge = true,
            "--mix" => {
                let v = val();
                let parts: Vec<f64> = v.split(',').filter_map(|x| x.parse().ok()).collect();
                match parts[..] {
                    [short, medium] => mix = Some((short, medium)),
                    _ => usage("--mix wants SHORT,MEDIUM fractions, e.g. 0,0 for all long"),
                }
            }
            "--fec" => {
                fec = Some(match val().as_str() {
                    "off" => FecMode::Off,
                    "xor" => FecMode::Xor,
                    "rs" => FecMode::ReedSolomon,
                    v => usage(&format!("unknown FEC mode {v}")),
                })
            }
            "--hello" => {
                hello = Some(match val().as_str() {
                    "off" => HelloMode::Off,
                    "unconfirmed" => HelloMode::Unconfirmed,
                    "backoff" => HelloMode::UnconfirmedAndBackoff,
                    v => usage(&format!("unknown Hello mode {v}")),
                })
            }
            "--max-rto" | "--min-rto" | "--initial-rto" | "--var-mult" | "--grace"
            | "--fec-sources" | "--fec-flush" | "--mtu" | "--deep-after" | "--max-probe" => {
                tweak.push((a.clone(), num(&val())))
            }
            _ => usage(&format!("unknown argument {a}")),
        }
    }
    if csv {
        println!("{}", Report::csv_header());
    } else {
        println!("{}", Report::table_header());
    }
    let mut failed = false;
    let mut details = Vec::new();
    for p in profiles {
        for s in seed..seed + seeds {
            let mut sc = Scenario::named(p, s).expect("known name");
            if let Some(m) = messages {
                sc.messages = m;
            }
            if let Some(i) = interval {
                sc.mean_interval_ms = i;
            }
            if let Some(h) = hello {
                sc.config.hello = h;
            }
            if let Some(f) = fec {
                sc.config.fec = f;
            }
            sc.nudge_on_reconnect |= nudge;
            if let Some((short, medium)) = mix {
                sc.lengths = avianlink_sim::LengthMix { short, medium };
            }
            for (k, v) in &tweak {
                match k.as_str() {
                    "--max-rto" => sc.config.max_rto_ms = *v,
                    "--min-rto" => sc.config.min_rto_ms = *v,
                    "--initial-rto" => sc.config.initial_rto_ms = *v,
                    "--var-mult" => sc.config.rttvar_multiplier = *v as u8,
                    "--fec-sources" => sc.config.fec_max_sources = *v as u8,
                    "--fec-flush" => sc.config.fec_flush_ms = *v,
                    "--mtu" => sc.link.mtu = *v as u16,
                    "--deep-after" => sc.config.deep_backoff_after_ms = *v,
                    "--max-probe" => sc.config.max_probe_interval_ms = *v,
                    _ => sc.config.backoff_grace = *v as u8,
                }
            }
            let r = sc.run();
            if csv {
                println!("{}", r.csv_row());
            } else {
                println!("{}", r.table_row());
            }
            failed |= r.delivered != r.messages || r.bugs() != 0;
            details.push(r);
        }
    }
    if verbose {
        for r in &details {
            println!("\n{r}");
        }
    }
    if failed {
        eprintln!("FAILED: incomplete delivery or engine bug counters non-zero");
        std::process::exit(1);
    }
}

fn num(s: &str) -> u64 {
    s.parse()
        .unwrap_or_else(|_| usage(&format!("not a number: {s}")))
}

/// Runs relay turns scenarios and prints a summary table.
fn run_turns(profiles: &[Profile], seeds: u64) -> ! {
    println!("| scenario | seed | delivered | acked | queued | lost | sessions p50/p95/max | latency p50/p95 | wire/payload | relay peak |");
    println!("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|");
    let mut failed = false;
    for &p in profiles {
        for seed in 1..=seeds {
            let r = TurnsScenario::new(p, seed).run();
            println!(
                "| {} | {} | {}/{} | {} | {} | {} | {}/{}/{} | {}/{} | {:.2} | {} B |",
                r.name,
                r.seed,
                r.delivered,
                r.messages,
                r.acked,
                r.still_queued,
                r.lost,
                r.sessions_p50,
                r.sessions_p95,
                r.sessions_max,
                avianlink_sim::fmt_ms(r.latency_p50_ms),
                avianlink_sim::fmt_ms(r.latency_p95_ms),
                r.wire_per_payload(),
                r.relay_peak_bytes
            );
            failed |= r.bugs() != 0;
        }
    }
    std::process::exit(i32::from(failed));
}

fn usage(msg: &str) -> ! {
    eprintln!("simrun: {msg}");
    eprintln!("usage: simrun [--profile NAME|all|everything] [--seed N] [--seeds K] [--messages N] [--interval-ms N] [--verbose] [--max-rto MS] [--min-rto MS] [--initial-rto MS] [--var-mult N] [--grace N]");
    std::process::exit(2)
}
