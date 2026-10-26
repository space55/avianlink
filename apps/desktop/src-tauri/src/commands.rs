//! Tauri commands: the only way the frontend can reach the backend.
//!
//! Each command is documented in `docs/ipc.md`, which is the contract. The
//! rules this module enforces:
//!
//! - **Arguments are decoded before anything is touched.** A bad hex string
//!   fails with `bad_request` and changes nothing.
//! - **Secrets never leave.** No command returns key material. The frontend
//!   can ask for a public key and a fingerprint, and nothing else.
//! - **`send_message` never fails for a link reason.** Sending is a local
//!   durable write; from the user's point of view it always succeeds
//!   instantly and means "queued".
//! - **Anything that touches the engine pokes the driver afterwards**, so the
//!   engine is pumped immediately rather than at the end of its sleep.

use std::sync::Arc;

use tauri::State;

use crate::driver::Shared;
use crate::error::{IpcError, IpcResult};
use crate::identity;
use crate::ipc::{
    AddContactArgs, AddSimulatedContactArgs, ConfigureLinkArgs, Contact, ConversationSummary,
    GetMessagesArgs, Identity, Link, LinkSettings, MarkReadArgs, Message, MessagePage,
    SendMessageArgs, SetContactVerifiedArgs, SetLinkEnabledArgs, SetSettingsArgs, Settings,
};
use crate::storage::OutgoingMessage;

/// Shorthand for the managed state.
type Ctx<'a> = State<'a, Arc<Shared>>;

/// This machine's identity.
///
/// Establishes it from the engine's local key on first call, so the frontend
/// never has to care whether setup has happened.
#[tauri::command]
pub async fn get_identity(ctx: Ctx<'_>) -> IpcResult<Identity> {
    if let Some(identity) = ctx.with_store(|store| store.identity()) {
        return Ok(identity);
    }
    let local = ctx.engine.lock().await.local_key();
    ctx.with_store(|store| {
        store.set_identity(local);
        store
            .identity()
            .ok_or_else(|| IpcError::internal("identity did not persist"))
    })
}

/// All contacts, sorted by display name.
#[tauri::command]
pub async fn list_contacts(ctx: Ctx<'_>) -> IpcResult<Vec<Contact>> {
    Ok(ctx.with_store(|store| store.contacts()))
}

/// Registers a peer from a pasted public key.
#[tauri::command]
pub async fn add_contact(ctx: Ctx<'_>, args: AddContactArgs) -> IpcResult<Contact> {
    let key = identity::decode_key(&args.public_key)?;
    let now = ctx.clock.now_ms();
    let conversation = {
        let mut engine = ctx.engine.lock().await;
        if key == engine.local_key() {
            return Err(IpcError::conflict(
                "that is this machine's own key, not a contact's",
            ));
        }
        engine.add_contact(key)?
    };
    let contact = ctx.with_store(|store| {
        store.upsert_contact(conversation, key, &args.display_name, args.verified, now)
    });
    ctx.sink.contact_changed(&contact);
    ctx.poke();
    Ok(contact)
}

/// Sidebar rows, most recent first.
#[tauri::command]
pub async fn list_conversations(ctx: Ctx<'_>) -> IpcResult<Vec<ConversationSummary>> {
    Ok(ctx.with_store(|store| store.conversations()))
}

/// A page of history, oldest first. See `docs/ipc.md` for why the cursor is
/// an `order_key` rather than an offset.
#[tauri::command]
pub async fn get_messages(ctx: Ctx<'_>, args: GetMessagesArgs) -> IpcResult<MessagePage> {
    let conversation = identity::decode_conversation(&args.conversation_id)?;
    ctx.with_store(|store| {
        store
            .messages(&conversation, args.before.as_deref(), args.limit)
            .ok_or_else(|| IpcError::not_found("no such conversation"))
    })
}

/// Queues a message. Returns the message as stored, with status `queued`.
#[tauri::command]
pub async fn send_message(ctx: Ctx<'_>, args: SendMessageArgs) -> IpcResult<Message> {
    let conversation = identity::decode_conversation(&args.conversation_id)?;
    let text = args.text.trim();
    if text.is_empty() {
        return Err(IpcError::bad_request("a message cannot be empty"));
    }
    if !ctx.with_store(|store| store.has_contact(&conversation)) {
        return Err(IpcError::not_found("no such conversation"));
    }
    let now = ctx.now();
    // The engine assigns the sequence and Lamport numbers, so it has to go
    // first; the history row cannot be keyed without them.
    //
    // Phase 2 must close the window this opens: a crash between these two
    // statements leaves the engine holding a message with no history row. The
    // fix is an intent row written before `send_text` and finalised after,
    // which is only meaningful once either side is actually durable.
    let queued = {
        let mut engine = ctx.engine.lock().await;
        engine.send_text(conversation, text, now)?
    };
    let message = ctx.with_store(|store| {
        store.insert_outgoing(OutgoingMessage {
            conversation,
            id: queued.id,
            seq: queued.seq,
            lamport: queued.lamport,
            text,
            queued_at: now.as_millis(),
        })
    });
    ctx.poke();
    Ok(message)
}

/// All links, sorted by id.
#[tauri::command]
pub async fn list_links(ctx: Ctx<'_>) -> IpcResult<Vec<Link>> {
    Ok(ctx.with_links(|links| links.list()))
}

/// Replaces a link's settings.
#[tauri::command]
pub async fn configure_link(ctx: Ctx<'_>, args: ConfigureLinkArgs) -> IpcResult<Link> {
    validate_link_settings(&args.config)?;
    let link = ctx.with_links(|links| {
        let record = links
            .record_mut(args.id)
            .ok_or_else(|| IpcError::not_found("no such link"))?;
        if std::mem::discriminant(&record.settings) != std::mem::discriminant(&args.config) {
            return Err(IpcError::bad_request(
                "a link's transport kind cannot be changed; remove it and add another",
            ));
        }
        record.settings = args.config.clone();
        links
            .get(args.id)
            .ok_or_else(|| IpcError::internal("link vanished while being configured"))
    })?;
    // Phase 3 rebinds the UDP socket here when `local_port` changed. Until
    // then settings are recorded and reported but not acted on.
    ctx.sink.link_status_changed(&link);
    ctx.poke();
    Ok(link)
}

/// Switches a link on or off.
///
/// Disabling unregisters it from the engine so nothing is paced onto it.
/// Queued messages stay queued: on these links that is the normal state, not
/// a failure.
#[tauri::command]
pub async fn set_link_enabled(ctx: Ctx<'_>, args: SetLinkEnabledArgs) -> IpcResult<Link> {
    let id = avianlink_core::LinkId(args.id);
    let config = ctx
        .with_links(|links| links.record_mut(args.id).map(|r| (r.config, r.enabled)))
        .ok_or_else(|| IpcError::not_found("no such link"))?;
    let (config, was_enabled) = config;
    if was_enabled != args.enabled {
        let mut engine = ctx.engine.lock().await;
        if args.enabled {
            engine.add_link(id, config)?;
        } else {
            engine.remove_link(id)?;
        }
    }
    let link = ctx.with_links(|links| {
        let record = links
            .record_mut(args.id)
            .ok_or_else(|| IpcError::internal("link vanished while being toggled"))?;
        record.enabled = args.enabled;
        if !args.enabled {
            record.health.up = false;
        }
        links
            .get(args.id)
            .ok_or_else(|| IpcError::internal("link vanished while being toggled"))
    })?;
    ctx.sink.link_status_changed(&link);
    ctx.poke();
    Ok(link)
}

/// Clears unread state up to a point the user has seen.
#[tauri::command]
pub async fn mark_conversation_read(ctx: Ctx<'_>, args: MarkReadArgs) -> IpcResult<()> {
    let conversation = identity::decode_conversation(&args.conversation_id)?;
    if !ctx.with_store(|store| store.has_contact(&conversation)) {
        return Err(IpcError::not_found("no such conversation"));
    }
    let contact = ctx.with_store(|store| store.mark_read(&conversation, &args.through_order_key));
    // `None` means the mark did not move, which needs no event.
    if let Some(contact) = contact {
        ctx.sink.contact_changed(&contact);
    }
    Ok(())
}

/// Sets the "I compared the fingerprint" mark on a contact.
#[tauri::command]
pub async fn set_contact_verified(
    ctx: Ctx<'_>,
    args: SetContactVerifiedArgs,
) -> IpcResult<Contact> {
    let conversation = identity::decode_conversation(&args.conversation_id)?;
    let contact = ctx
        .with_store(|store| store.set_verified(&conversation, args.verified))
        .ok_or_else(|| IpcError::not_found("no such contact"))?;
    ctx.sink.contact_changed(&contact);
    Ok(contact)
}

/// Current settings, including the simulated engine's controls when one is
/// running.
#[tauri::command]
pub async fn get_settings(ctx: Ctx<'_>) -> IpcResult<Settings> {
    let mut settings = ctx.with_store(|store| store.settings());
    settings.fake_engine = ctx
        .engine
        .lock()
        .await
        .simulation()
        .map(|sim| sim.settings());
    Ok(settings)
}

/// Replaces settings.
#[tauri::command]
pub async fn set_settings(ctx: Ctx<'_>, args: SetSettingsArgs) -> IpcResult<Settings> {
    let mut settings = args.settings;
    settings.display_name = settings
        .display_name
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());
    // The simulation's controls live in the engine, not the store, so they
    // are split off before the rest is persisted and put back afterwards.
    let simulation = settings.fake_engine.take();
    let mut stored = ctx.with_store(|store| store.set_settings(settings));
    let mut engine = ctx.engine.lock().await;
    if let Some(sim) = engine.simulation() {
        if let Some(wanted) = simulation {
            sim.set_settings(wanted);
        }
        stored.fake_engine = Some(sim.settings());
    }
    drop(engine);
    ctx.poke();
    // The display name is part of the identity the UI shows, and `Identity`
    // reads it straight from settings, so there is nothing else to update.
    Ok(stored)
}

/// Adds a contact backed by a simulated device that answers.
///
/// Only meaningful on `FakeEngine`. It exists because the interface cannot be
/// reviewed — or screenshotted, or driven through its states — without a peer,
/// and inventing a key by hand to paste into the add-contact dialog is a
/// pointless ritual. On the real engine it fails rather than silently
/// creating a contact that nothing will ever answer.
#[tauri::command]
pub async fn add_simulated_contact(
    ctx: Ctx<'_>,
    args: AddSimulatedContactArgs,
) -> IpcResult<Contact> {
    let now = ctx.clock.now_ms();
    let (key, conversation) = {
        let mut engine = ctx.engine.lock().await;
        if engine.simulation().is_none() {
            return Err(IpcError::bad_request(
                "this build is not running the simulated engine",
            ));
        }
        let key = engine
            .simulation()
            .map(|sim| sim.invent_key())
            .ok_or_else(|| IpcError::internal("the simulation vanished"))?;
        let conversation = engine.add_contact(key)?;
        if args.history > 0 {
            if let Some(sim) = engine.simulation() {
                sim.seed_history(conversation, args.history as usize);
            }
        }
        (key, conversation)
    };
    let contact = ctx.with_store(|store| {
        store.upsert_contact(conversation, key, &args.display_name, false, now)
    });
    ctx.sink.contact_changed(&contact);
    ctx.poke();
    Ok(contact)
}

/// Deletes all local data. Destructive; the UI confirms first.
#[tauri::command]
pub async fn reset_local_data(ctx: Ctx<'_>) -> IpcResult<()> {
    // Hold the engine lock for the whole operation so the driver cannot pump
    // a half-cleared store.
    let engine = ctx.engine.lock().await;
    ctx.with_store(|store| store.reset());
    ctx.with_links(|links| links.clear());
    let local = engine.local_key();
    // Phase 2 also discards the keychain entry and recreates the identity
    // here. With no persistence yet, the engine's key is all there is.
    ctx.with_store(|store| store.set_identity(local));
    drop(engine);
    ctx.poke();
    Ok(())
}

/// Rejects link settings the transport could never honour.
fn validate_link_settings(settings: &LinkSettings) -> IpcResult<()> {
    match settings {
        LinkSettings::Udp { peers, .. } => {
            for peer in peers {
                identity::decode_conversation(&peer.conversation_id)?;
                // Parsed rather than pattern-matched: a hostname is allowed,
                // so the check is that there is a host part and a numeric
                // port, not that it is an IP address.
                let (host, port) = peer.address.rsplit_once(':').ok_or_else(|| {
                    IpcError::bad_request(format!(
                        "peer address '{}' needs a host and a port",
                        peer.address
                    ))
                })?;
                if host.is_empty() {
                    return Err(IpcError::bad_request(format!(
                        "peer address '{}' has no host",
                        peer.address
                    )));
                }
                let port: u16 = port.parse().map_err(|_| {
                    IpcError::bad_request(format!(
                        "peer address '{}' has an invalid port",
                        peer.address
                    ))
                })?;
                if port == 0 {
                    return Err(IpcError::bad_request(
                        "port 0 cannot be a destination".to_string(),
                    ));
                }
            }
            Ok(())
        }
        LinkSettings::Fake { .. } => Ok(()),
    }
}

/// Every command, for `tauri::generate_handler!`.
///
/// Kept as a macro so the list exists once. A command missing here is
/// invisible to the frontend with no compile error, which is exactly the kind
/// of mistake that is cheap to prevent and expensive to debug.
#[macro_export]
macro_rules! command_handlers {
    () => {
        tauri::generate_handler![
            $crate::commands::get_identity,
            $crate::commands::list_contacts,
            $crate::commands::add_contact,
            $crate::commands::list_conversations,
            $crate::commands::get_messages,
            $crate::commands::send_message,
            $crate::commands::list_links,
            $crate::commands::configure_link,
            $crate::commands::set_link_enabled,
            $crate::commands::mark_conversation_read,
            $crate::commands::set_contact_verified,
            $crate::commands::get_settings,
            $crate::commands::set_settings,
            $crate::commands::add_simulated_contact,
            $crate::commands::reset_local_data,
        ]
    };
}
