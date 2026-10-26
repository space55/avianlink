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

use avianlink_core::{LinkBudget, LinkConfig, LinkId, PublicKey};
use rand_core::RngCore;
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

/// Handle the receive side of the app uses to inject packets.
///
/// Managed separately from [`Shared`] because only the transport layer should
/// be able to inject packets, and keeping the sender out of `Shared` means a
/// command cannot reach it.
pub struct InboundSender(pub mpsc::Sender<Inbound>);

/// Generates this machine's identity key.
///
/// **Phase 0: ephemeral.** A fresh key is generated on every launch, so
/// restarting the app changes who you are and existing contacts stop
/// matching. Phase 2 stores it in the OS keychain and this becomes a load.
/// It is random rather than a fixed test key so that two instances running
/// side by side are distinguishable.
fn generate_identity() -> PublicKey {
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    PublicKey(bytes)
}

/// The link the app starts with: one simulated link, so the interface has
/// something to show before any transport is configured.
fn default_link_config() -> LinkConfig {
    LinkConfig {
        mtu: 1200,
        budget: LinkBudget::Unlimited,
        cost: 1,
    }
}

/// Registers the starting state: identity and the default link.
async fn bootstrap(shared: &Arc<Shared>) -> Result<(), avianlink_core::Error> {
    let config = default_link_config();
    {
        let mut engine = shared.engine.lock().await;
        let local = engine.local_key();
        shared.with_store(|store| store.set_identity(local));
        engine.add_link(DEFAULT_LINK, config)?;
    }
    shared.with_links(|links| {
        links.insert(
            DEFAULT_LINK.0,
            LinkRecord {
                label: "Simulated link".to_string(),
                kind: LinkKind::Fake,
                enabled: true,
                config,
                settings: LinkSettings::Fake {
                    profile: "clean".to_string(),
                },
                health: LinkHealth {
                    up: true,
                    loss_permille: Some(0),
                    budget_blocked_until: None,
                },
                counters: LinkCounters::default(),
            },
        );
    });
    // Drain the registration events the engine produced, so the link table is
    // consistent before the window opens.
    shared.pump().await;
    Ok(())
}

/// Builds and runs the app.
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let engine = Box::new(FakeEngine::new(generate_identity()));
            let sink = Arc::new(TauriSink::new(app.handle().clone()));
            let shared = Arc::new(Shared::new(
                engine,
                Box::new(NullTransport),
                Arc::new(SystemClock),
                sink,
            ));
            let (tx, rx) = mpsc::channel(INBOUND_CAPACITY);
            tauri::async_runtime::block_on(bootstrap(&shared))?;
            app.manage(Arc::clone(&shared));
            app.manage(InboundSender(tx));
            tauri::async_runtime::spawn(driver::run(shared, rx));
            Ok(())
        })
        .invoke_handler(command_handlers!())
        .run(tauri::generate_context!())
        .expect("avianlink failed to start");
}
