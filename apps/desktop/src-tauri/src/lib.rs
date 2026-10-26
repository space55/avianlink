//! Desktop app backend for avianlink.
//!
//! The app is a host for the library's sans-IO engine. The structure is:
//!
//! - [`engine`] — the [`engine::EngineHandle`] boundary, and `FakeEngine`.
//! - [`driver`] — the single task that owns the engine and pumps it.
//! - [`storage`] — the app's own history, contacts, read marks and settings.
//! - [`commands`] / [`events`] — the IPC surface, typed in [`ipc`].
//!
//! Platform-specific code is kept out of this module's body so the Tauri
//! mobile targets can reuse `run` unchanged.

pub mod commands;
pub mod driver;
pub mod engine;
pub mod error;
pub mod events;
pub mod identity;
pub mod ipc;
pub mod storage;

use std::sync::Arc;

use avianlink_core::{Identity, LinkId};
use tauri::Manager;
use tokio::sync::mpsc;

use crate::driver::{Inbound, LinkRecord, NullTransport, Shared, SystemClock};
use crate::engine::{FakeEngine, LinkCounters, LinkHealth};
use crate::events::TauriSink;
use crate::ipc::{LinkKind, LinkSettings};

/// Depth of the inbound packet queue.
///
/// Packets are dropped when it is full, which is the correct behaviour for a
/// lossy link: the engine already handles loss, and blocking a receive loop
/// would be worse than dropping.
const INBOUND_CAPACITY: usize = 256;

/// Id of the link the app starts with.
const DEFAULT_LINK: LinkId = LinkId(1);

/// Impairment profile the app starts on.
///
/// Not `clean`: the interface's whole purpose is to be right about a bad
/// link, and starting on a good one would mean every launch looks like an
/// ordinary chat app until something goes wrong.
const DEFAULT_PROFILE: &str = "disaster_cellular";

/// Handle the receive side of the app uses to inject packets.
///
/// Managed separately from [`Shared`] because only the transport layer should
/// be able to inject packets, and keeping the sender out of `Shared` means a
/// command cannot reach it.
pub struct InboundSender(pub mpsc::Sender<Inbound>);

/// Generates this machine's identity.
///
/// **Phase 0/1: ephemeral.** A fresh keypair is generated on every launch, so
/// restarting the app changes who you are and existing contacts stop
/// matching. Phase 2 stores `Identity::secret_bytes` in the OS keychain and
/// this becomes a load.
fn generate_identity() -> Identity {
    Identity::generate(&mut rand_core::OsRng)
}

/// Registers the starting state: identity and the simulated link.
///
/// The link's MTU and budget come from the engine's impairment profile, so
/// selecting a LoRa profile really does hand the engine a 51-byte MTU and a
/// 1% duty cycle to pace against, rather than a comfortable default that
/// would hide the behaviour the interface exists to show.
async fn bootstrap(shared: &Arc<Shared>, link: LinkRecord) -> Result<(), avianlink_core::Error> {
    {
        let mut engine = shared.engine.lock().await;
        let local = engine.local_key();
        shared.with_store(|store| store.set_identity(local));
        engine.add_link(DEFAULT_LINK, link.config)?;
    }
    shared.with_links(|links| links.insert(DEFAULT_LINK.0, link));
    // Drain the registration events the engine produced, so the link table is
    // consistent before the window opens.
    shared.pump().await;
    Ok(())
}

/// Builds the app's starting link record from the simulated engine.
fn simulated_link(engine: &FakeEngine) -> LinkRecord {
    LinkRecord {
        label: "Simulated link".to_string(),
        kind: LinkKind::Fake,
        enabled: true,
        config: engine.link_config(),
        settings: LinkSettings::Fake {
            profile: engine.settings().profile,
        },
        health: LinkHealth {
            up: true,
            loss_permille: None,
            budget_blocked_until: None,
        },
        counters: LinkCounters::default(),
    }
}

/// Builds and runs the app.
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let engine = FakeEngine::with_profile(
                generate_identity(),
                DEFAULT_PROFILE,
                SystemClock.now_ms_for_bootstrap(),
            );
            let link = simulated_link(&engine);
            let sink = Arc::new(TauriSink::new(app.handle().clone()));
            let shared = Arc::new(Shared::new(
                Box::new(engine),
                Box::new(NullTransport),
                Arc::new(SystemClock),
                sink,
            ));
            let (tx, rx) = mpsc::channel(INBOUND_CAPACITY);
            tauri::async_runtime::block_on(bootstrap(&shared, link))?;
            app.manage(Arc::clone(&shared));
            app.manage(InboundSender(tx));
            tauri::async_runtime::spawn(driver::run(shared, rx));
            Ok(())
        })
        .invoke_handler(command_handlers!())
        .run(tauri::generate_context!())
        .expect("avianlink failed to start");
}
