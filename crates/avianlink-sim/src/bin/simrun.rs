//! Runs simulator scenarios and prints metrics.
//!
//! ```text
//! simrun [--profile NAME|all] [--seed N] [--seeds K] [--messages N]
//!        [--interval-ms N] [--verbose]
//! ```

use avianlink_sim::{Profile, Report, Scenario};

fn main() {
    let mut profiles: Vec<Profile> = Profile::ALL.to_vec();
    let mut seed = 1u64;
    let mut seeds = 1u64;
    let mut messages = None;
    let mut interval = None;
    let mut verbose = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || {
            args.next()
                .unwrap_or_else(|| usage(&format!("{a} needs a value")))
        };
        match a.as_str() {
            "--profile" => {
                let v = val();
                if v != "all" {
                    profiles = vec![Profile::from_name(&v)
                        .unwrap_or_else(|| usage(&format!("unknown profile {v}")))];
                }
            }
            "--seed" => seed = num(&val()),
            "--seeds" => seeds = num(&val()),
            "--messages" => messages = Some(num(&val()) as usize),
            "--interval-ms" => interval = Some(num(&val())),
            "--verbose" | "-v" => verbose = true,
            _ => usage(&format!("unknown argument {a}")),
        }
    }
    println!("{}", Report::table_header());
    let mut failed = false;
    let mut details = Vec::new();
    for p in profiles {
        for s in seed..seed + seeds {
            let mut sc = Scenario::new(p, s);
            if let Some(m) = messages {
                sc.messages = m;
            }
            if let Some(i) = interval {
                sc.mean_interval_ms = i;
            }
            let r = sc.run();
            println!("{}", r.table_row());
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

fn usage(msg: &str) -> ! {
    eprintln!("simrun: {msg}");
    eprintln!("usage: simrun [--profile NAME|all] [--seed N] [--seeds K] [--messages N] [--interval-ms N] [--verbose]");
    std::process::exit(2)
}
