//! C ABI for avianlink (`docs/ffi.md`): the sans-IO engine behind opaque
//! handles and status codes. The header `include/avianlink.h` is generated
//! from this file by `cbindgen`.

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use avianlink_core::push;
use avianlink_core::wire::MAX_PUSH_BLOB;
use avianlink_core::{
    format_fingerprint, AirtimeModel, Config, ConversationId, Engine, Error, Event, FecMode,
    HelloMode, Identity, LinkBudget, LinkConfig, LinkId, MemoryStorage, PublicKey, Received,
    Storage, Timestamp, Transmit,
};
use avianlink_relay::{PushConfig, RelayClient};
use avianlink_udp::{os_rng, FileStorage};
use rand_chacha::ChaCha20Rng;
use std::collections::VecDeque;

/// Result of every fallible call.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvlStatus {
    /// Success.
    Ok = 0,
    /// Nothing to return (empty queue, nothing to send).
    None = 1,
    /// `avl_engine_handle_packet`: a verified Hello from an unknown key.
    Hello = 2,
    /// A required pointer was null, or a value was malformed.
    ErrInvalidArgument = -1,
    /// The output buffer is too small; the needed length was reported.
    ErrBufferTooSmall = -2,
    /// The engine refused; see `avl_last_engine_error`.
    ErrEngine = -3,
    /// Storage could not be opened.
    ErrStorage = -4,
    /// An internal panic was caught (a bug; the handle may be unusable).
    ErrPanic = -5,
}

/// Detail for `AVL_STATUS_ERR_ENGINE` (mirrors `avianlink_core::Error`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvlEngineError {
    /// No engine error recorded.
    None = 0,
    /// Invalid engine configuration.
    InvalidConfig,
    /// Invalid link configuration.
    InvalidLinkConfig,
    /// Link already registered.
    LinkExists,
    /// Unknown link.
    UnknownLink,
    /// Too many links.
    TooManyLinks,
    /// Own key, duplicate, or invalid public key.
    InvalidContact,
    /// Too many contacts.
    TooManyContacts,
    /// Unknown conversation.
    UnknownConversation,
    /// Message text too long.
    TextTooLong,
    /// Outbox full.
    OutboxFull,
    /// A sequence counter is exhausted.
    Exhausted,
    /// Storage failure.
    Storage,
    /// Storage already holds a different engine state.
    StorageNotEmpty,
    /// Stored state is corrupt.
    CorruptStorage,
    /// Stored state belongs to another identity.
    IdentityMismatch,
    /// Restoring from empty storage: the identity's state is lost.
    StateMissing,
    /// An error this ABI version does not know.
    Other,
}

impl From<Error> for AvlEngineError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidConfig => Self::InvalidConfig,
            Error::InvalidLinkConfig => Self::InvalidLinkConfig,
            Error::LinkExists => Self::LinkExists,
            Error::UnknownLink => Self::UnknownLink,
            Error::TooManyLinks => Self::TooManyLinks,
            Error::InvalidContact => Self::InvalidContact,
            Error::TooManyContacts => Self::TooManyContacts,
            Error::UnknownConversation => Self::UnknownConversation,
            Error::TextTooLong => Self::TextTooLong,
            Error::OutboxFull => Self::OutboxFull,
            Error::Exhausted => Self::Exhausted,
            Error::Storage => Self::Storage,
            Error::StorageNotEmpty => Self::StorageNotEmpty,
            Error::CorruptStorage => Self::CorruptStorage,
            Error::IdentityMismatch => Self::IdentityMismatch,
            Error::StateMissing => Self::StateMissing,
            _ => Self::Other,
        }
    }
}

thread_local! {
    static LAST_ENGINE_ERROR: Cell<AvlEngineError> = const { Cell::new(AvlEngineError::None) };
}

fn engine_err(e: Error) -> AvlStatus {
    LAST_ENGINE_ERROR.with(|c| c.set(e.into()));
    AvlStatus::ErrEngine
}

/// The detail of the most recent `AVL_STATUS_ERR_ENGINE` on this thread.
#[no_mangle]
pub extern "C" fn avl_last_engine_error() -> AvlEngineError {
    LAST_ENGINE_ERROR.with(Cell::get)
}

fn guard(f: impl FnOnce() -> AvlStatus) -> AvlStatus {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(AvlStatus::ErrPanic)
}

// ---------------------------------------------------------------------
// Identity

/// Generates a new identity: writes its 32-byte secret (keep it in the
/// keychain) and 32-byte public key (its address).
///
/// # Safety
/// `secret_out` and `public_out` must each point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn avl_identity_generate(
    secret_out: *mut u8,
    public_out: *mut u8,
) -> AvlStatus {
    guard(|| {
        if secret_out.is_null() || public_out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        let id = Identity::generate(&mut os_rng());
        // SAFETY: caller guarantees 32 writable bytes at each pointer.
        unsafe {
            std::ptr::copy_nonoverlapping(id.secret_bytes().as_ptr(), secret_out, 32);
            std::ptr::copy_nonoverlapping(id.public_key().0.as_ptr(), public_out, 32);
        }
        AvlStatus::Ok
    })
}

/// Derives the public key of a secret.
///
/// # Safety
/// `secret` must point to 32 readable bytes, `public_out` to 32 writable.
#[no_mangle]
pub unsafe extern "C" fn avl_identity_public_key(
    secret: *const u8,
    public_out: *mut u8,
) -> AvlStatus {
    guard(|| {
        if secret.is_null() || public_out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees 32 readable bytes.
        let id = Identity::from_secret_bytes(unsafe { &*secret.cast::<[u8; 32]>() });
        // SAFETY: caller guarantees 32 writable bytes.
        unsafe { std::ptr::copy_nonoverlapping(id.public_key().0.as_ptr(), public_out, 32) };
        AvlStatus::Ok
    })
}

/// Writes the fingerprint of a public key (`a1b2-c3d4-e5f6-7890-abcd`, 24
/// characters plus NUL) for out-of-band comparison.
///
/// # Safety
/// `public_key` must point to 32 readable bytes, `out` to 25 writable.
#[no_mangle]
pub unsafe extern "C" fn avl_fingerprint(public_key: *const u8, out: *mut c_char) -> AvlStatus {
    guard(|| {
        if public_key.is_null() || out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees 32 readable bytes.
        let key = PublicKey(unsafe { *public_key.cast::<[u8; 32]>() });
        let s = format_fingerprint(&key.fingerprint());
        let bytes = s.as_bytes();
        // SAFETY: caller guarantees 25 writable bytes; the string is 24.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), bytes.len());
            *out.add(bytes.len()) = 0;
        }
        AvlStatus::Ok
    })
}

// ---------------------------------------------------------------------
// Storage

/// Storage supplied by the app (`docs/ffi.md` §3). It must provide atomic,
/// durable batches.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AvlStorageCallbacks {
    /// Passed back to every callback.
    pub ctx: *mut c_void,
    /// 0: found (value copied, or `*value_len` set above `value_cap` to ask
    /// for a bigger buffer); 1: not found; <0: error.
    pub load: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            key: *const u8,
            key_len: usize,
            value: *mut u8,
            value_cap: usize,
            value_len: *mut usize,
        ) -> c_int,
    >,
    /// Calls `visit` for every key with the prefix, ascending. 0 ok, <0 error.
    pub scan_prefix: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            prefix: *const u8,
            prefix_len: usize,
            visit: unsafe extern "C" fn(
                visit_ctx: *mut c_void,
                key: *const u8,
                key_len: usize,
                value: *const u8,
                value_len: usize,
            ),
            visit_ctx: *mut c_void,
        ) -> c_int,
    >,
    /// Starts a batch. 0 ok.
    pub begin: Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>,
    /// Stores within the batch. 0 ok.
    pub store: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            key: *const u8,
            key_len: usize,
            value: *const u8,
            value_len: usize,
        ) -> c_int,
    >,
    /// Removes within the batch. 0 ok.
    pub remove:
        Option<unsafe extern "C" fn(ctx: *mut c_void, key: *const u8, key_len: usize) -> c_int>,
    /// Makes the batch durable atomically. 0 ok.
    pub commit: Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>,
    /// Discards the batch.
    pub rollback: Option<unsafe extern "C" fn(ctx: *mut c_void)>,
    /// Called once when the engine (or storage handle) is freed. May be null.
    pub release: Option<unsafe extern "C" fn(ctx: *mut c_void)>,
}

struct Callbacks(AvlStorageCallbacks);

impl Drop for Callbacks {
    fn drop(&mut self) {
        if let Some(release) = self.0.release {
            // SAFETY: the app supplied `release` for this `ctx`; called once.
            unsafe { release(self.0.ctx) };
        }
    }
}

/// Trampoline for `scan_prefix`: `visit_ctx` points at the Rust closure.
unsafe extern "C" fn visit_trampoline(
    visit_ctx: *mut c_void,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
) {
    if key.is_null() || (value.is_null() && value_len > 0) {
        return;
    }
    // SAFETY: `visit_ctx` is the `&mut &mut dyn FnMut` passed by
    // `scan_prefix` below, alive for the duration of the call; the app
    // guarantees the slices are valid for this call.
    unsafe {
        let f = &mut *visit_ctx.cast::<&mut dyn FnMut(&[u8], &[u8])>();
        let k = std::slice::from_raw_parts(key, key_len);
        let v = if value_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(value, value_len)
        };
        let _ = catch_unwind(AssertUnwindSafe(|| f(k, v)));
    }
}

impl Storage for Callbacks {
    type Error = ();

    fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        let f = self.0.load.ok_or(())?;
        let mut buf = vec![0u8; 256];
        for _ in 0..4 {
            let mut len = 0usize;
            // SAFETY: `buf` is writable for `buf.len()` bytes; `key` is valid.
            let r = unsafe {
                f(
                    self.0.ctx,
                    key.as_ptr(),
                    key.len(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut len,
                )
            };
            match r {
                0 if len <= buf.len() => {
                    buf.truncate(len);
                    return Ok(Some(buf));
                }
                0 => buf.resize(len, 0),
                1 => return Ok(None),
                _ => return Err(()),
            }
        }
        Err(())
    }

    fn scan_prefix(&mut self, prefix: &[u8], f: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), ()> {
        let scan = self.0.scan_prefix.ok_or(())?;
        let mut f = f;
        let ctx: *mut &mut dyn FnMut(&[u8], &[u8]) = &mut f;
        // SAFETY: `ctx` outlives the call; the trampoline casts it back.
        let r = unsafe {
            scan(
                self.0.ctx,
                prefix.as_ptr(),
                prefix.len(),
                visit_trampoline,
                ctx.cast(),
            )
        };
        if r < 0 {
            Err(())
        } else {
            Ok(())
        }
    }

    fn begin(&mut self) -> Result<(), ()> {
        let f = self.0.begin.ok_or(())?;
        // SAFETY: app-supplied callback with its own ctx.
        if unsafe { f(self.0.ctx) } == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        let f = self.0.store.ok_or(())?;
        // SAFETY: slices are valid for the call.
        let r = unsafe {
            f(
                self.0.ctx,
                key.as_ptr(),
                key.len(),
                value.as_ptr(),
                value.len(),
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), ()> {
        let f = self.0.remove.ok_or(())?;
        // SAFETY: slice is valid for the call.
        if unsafe { f(self.0.ctx, key.as_ptr(), key.len()) } == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    fn commit(&mut self) -> Result<(), ()> {
        let f = self.0.commit.ok_or(())?;
        // SAFETY: app-supplied callback with its own ctx.
        if unsafe { f(self.0.ctx) } == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    fn rollback(&mut self) {
        if let Some(f) = self.0.rollback {
            // SAFETY: app-supplied callback with its own ctx.
            unsafe { f(self.0.ctx) };
        }
    }
}

/// Any of the three storage kinds, behind one handle.
pub struct AvlStorage(StorageKind);

enum StorageKind {
    File(FileStorage),
    Memory(MemoryStorage),
    Callbacks(Callbacks),
}

impl Storage for AvlStorage {
    type Error = ();

    fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        match &mut self.0 {
            StorageKind::File(s) => s.load(key).map_err(|_| ()),
            StorageKind::Memory(s) => s.load(key).map_err(|_| ()),
            StorageKind::Callbacks(s) => s.load(key),
        }
    }
    fn scan_prefix(&mut self, prefix: &[u8], f: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), ()> {
        match &mut self.0 {
            StorageKind::File(s) => s.scan_prefix(prefix, f).map_err(|_| ()),
            StorageKind::Memory(s) => s.scan_prefix(prefix, f).map_err(|_| ()),
            StorageKind::Callbacks(s) => s.scan_prefix(prefix, f),
        }
    }
    fn begin(&mut self) -> Result<(), ()> {
        match &mut self.0 {
            StorageKind::File(s) => s.begin().map_err(|_| ()),
            StorageKind::Memory(s) => s.begin().map_err(|_| ()),
            StorageKind::Callbacks(s) => s.begin(),
        }
    }
    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        match &mut self.0 {
            StorageKind::File(s) => s.store(key, value).map_err(|_| ()),
            StorageKind::Memory(s) => s.store(key, value).map_err(|_| ()),
            StorageKind::Callbacks(s) => s.store(key, value),
        }
    }
    fn remove(&mut self, key: &[u8]) -> Result<(), ()> {
        match &mut self.0 {
            StorageKind::File(s) => s.remove(key).map_err(|_| ()),
            StorageKind::Memory(s) => s.remove(key).map_err(|_| ()),
            StorageKind::Callbacks(s) => s.remove(key),
        }
    }
    fn commit(&mut self) -> Result<(), ()> {
        match &mut self.0 {
            StorageKind::File(s) => s.commit().map_err(|_| ()),
            StorageKind::Memory(s) => s.commit().map_err(|_| ()),
            StorageKind::Callbacks(s) => s.commit(),
        }
    }
    fn rollback(&mut self) {
        match &mut self.0 {
            StorageKind::File(s) => s.rollback(),
            StorageKind::Memory(s) => s.rollback(),
            StorageKind::Callbacks(s) => s.rollback(),
        }
    }
}

fn give<T>(value: T, out: *mut *mut T) -> AvlStatus {
    // SAFETY: callers check `out` is non-null before calling.
    unsafe { *out = Box::into_raw(Box::new(value)) };
    AvlStatus::Ok
}

/// Opens (creating if needed) durable file storage in directory `dir`
/// (NUL-terminated UTF-8 path).
///
/// # Safety
/// `dir` must be a valid NUL-terminated string; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn avl_storage_file_open(
    dir: *const c_char,
    out: *mut *mut AvlStorage,
) -> AvlStatus {
    guard(|| {
        if dir.is_null() || out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees a valid C string.
        let Ok(path) = unsafe { CStr::from_ptr(dir) }.to_str() else {
            return AvlStatus::ErrInvalidArgument;
        };
        match FileStorage::open(path) {
            Ok(s) => give(AvlStorage(StorageKind::File(s)), out),
            Err(_) => AvlStatus::ErrStorage,
        }
    })
}

/// In-memory storage (tests; not durable).
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn avl_storage_memory_new(out: *mut *mut AvlStorage) -> AvlStatus {
    guard(|| {
        if out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        give(AvlStorage(StorageKind::Memory(MemoryStorage::new())), out)
    })
}

/// Storage backed by the app's callbacks (copied; `release` is called when
/// the handle is freed).
///
/// # Safety
/// `callbacks` must be readable and its functions valid for its `ctx` until
/// `release`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn avl_storage_callbacks(
    callbacks: *const AvlStorageCallbacks,
    out: *mut *mut AvlStorage,
) -> AvlStatus {
    guard(|| {
        if callbacks.is_null() || out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees a readable struct.
        let cb = unsafe { *callbacks };
        let complete = cb.load.is_some()
            && cb.scan_prefix.is_some()
            && cb.begin.is_some()
            && cb.store.is_some()
            && cb.remove.is_some()
            && cb.commit.is_some()
            && cb.rollback.is_some();
        if !complete {
            return AvlStatus::ErrInvalidArgument;
        }
        give(AvlStorage(StorageKind::Callbacks(Callbacks(cb))), out)
    })
}

/// Frees a storage handle that was not passed to `avl_engine_open`.
///
/// # Safety
/// `storage` must be null or a handle from `avl_storage_*`, not yet freed
/// or given to an engine.
#[no_mangle]
pub unsafe extern "C" fn avl_storage_free(storage: *mut AvlStorage) {
    if !storage.is_null() {
        // SAFETY: caller guarantees ownership of a live handle.
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(storage) })));
    }
}

// ---------------------------------------------------------------------
// Configuration

/// When Hellos are sent (mirrors `avianlink_core::HelloMode`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvlHelloMode {
    /// Never.
    Off = 0,
    /// Only while introducing ourselves to a contact.
    Unconfirmed = 1,
    /// Also to silent contacts after the grace probes (default).
    UnconfirmedAndBackoff = 2,
}

/// FEC scheme (mirrors `avianlink_core::FecMode`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvlFecMode {
    /// No repairs sent.
    Off = 0,
    /// One XOR repair per window.
    Xor = 1,
    /// Cauchy Reed-Solomon sized to measured loss (default).
    ReedSolomon = 2,
}

/// Engine configuration (mirrors `avianlink_core::Config`; see its docs).
/// Start from `avl_config_default`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct AvlConfig {
    pub max_links: u16,
    pub max_contacts: u32,
    pub max_outbox_messages: u32,
    pub max_pending_events: u32,
    pub max_text_len: u32,
    pub max_fragments: u32,
    pub max_reassembly_bytes: u32,
    pub max_reorder_window: u32,
    pub max_ack_bitmap_bytes: u16,
    pub max_duty_log_entries: u32,
    pub initial_rto_ms: u64,
    pub min_rto_ms: u64,
    pub max_rto_ms: u64,
    pub rttvar_multiplier: u8,
    pub backoff_grace: u8,
    pub deep_backoff_after_ms: u64,
    pub max_probe_interval_ms: u64,
    pub max_sent_log: u16,
    pub max_frag_acks_per_packet: u8,
    pub counter_reservation: u32,
    pub ack_delay_ms: u64,
    /// An `AvlFecMode` value.
    pub fec: u8,
    pub fec_max_sources: u8,
    pub fec_flush_ms: u64,
    pub fec_min_loss_permille: u16,
    pub fec_max_packet_cost_ms: u64,
    pub max_fec_rx_bytes: u32,
    pub max_fec_pending_repairs: u16,
    pub wall_clock: bool,
    /// An `AvlHelloMode` value.
    pub hello: u8,
    pub hello_verify_per_minute: u16,
    pub hello_verify_burst: u8,
    pub hello_dedupe_entries: u16,
}

impl From<Config> for AvlConfig {
    fn from(c: Config) -> Self {
        Self {
            max_links: c.max_links,
            max_contacts: c.max_contacts,
            max_outbox_messages: c.max_outbox_messages,
            max_pending_events: c.max_pending_events,
            max_text_len: c.max_text_len,
            max_fragments: c.max_fragments,
            max_reassembly_bytes: c.max_reassembly_bytes,
            max_reorder_window: c.max_reorder_window,
            max_ack_bitmap_bytes: c.max_ack_bitmap_bytes,
            max_duty_log_entries: c.max_duty_log_entries,
            initial_rto_ms: c.initial_rto_ms,
            min_rto_ms: c.min_rto_ms,
            max_rto_ms: c.max_rto_ms,
            rttvar_multiplier: c.rttvar_multiplier,
            backoff_grace: c.backoff_grace,
            deep_backoff_after_ms: c.deep_backoff_after_ms,
            max_probe_interval_ms: c.max_probe_interval_ms,
            max_sent_log: c.max_sent_log,
            max_frag_acks_per_packet: c.max_frag_acks_per_packet,
            counter_reservation: c.counter_reservation,
            ack_delay_ms: c.ack_delay_ms,
            fec: match c.fec {
                FecMode::Off => AvlFecMode::Off,
                FecMode::Xor => AvlFecMode::Xor,
                FecMode::ReedSolomon => AvlFecMode::ReedSolomon,
            } as u8,
            fec_max_sources: c.fec_max_sources,
            fec_flush_ms: c.fec_flush_ms,
            fec_min_loss_permille: c.fec_min_loss_permille,
            fec_max_packet_cost_ms: c.fec_max_packet_cost_ms,
            max_fec_rx_bytes: c.max_fec_rx_bytes,
            max_fec_pending_repairs: c.max_fec_pending_repairs,
            wall_clock: c.wall_clock,
            hello: match c.hello {
                HelloMode::Off => AvlHelloMode::Off,
                HelloMode::Unconfirmed => AvlHelloMode::Unconfirmed,
                HelloMode::UnconfirmedAndBackoff => AvlHelloMode::UnconfirmedAndBackoff,
            } as u8,
            hello_verify_per_minute: c.hello_verify_per_minute,
            hello_verify_burst: c.hello_verify_burst,
            hello_dedupe_entries: c.hello_dedupe_entries,
        }
    }
}

impl TryFrom<AvlConfig> for Config {
    type Error = ();

    /// Fails on an unknown `fec` or `hello` value.
    fn try_from(c: AvlConfig) -> Result<Self, ()> {
        let fec = match c.fec {
            0 => FecMode::Off,
            1 => FecMode::Xor,
            2 => FecMode::ReedSolomon,
            _ => return Err(()),
        };
        let hello = match c.hello {
            0 => HelloMode::Off,
            1 => HelloMode::Unconfirmed,
            2 => HelloMode::UnconfirmedAndBackoff,
            _ => return Err(()),
        };
        Ok(Self {
            max_links: c.max_links,
            max_contacts: c.max_contacts,
            max_outbox_messages: c.max_outbox_messages,
            max_pending_events: c.max_pending_events,
            max_text_len: c.max_text_len,
            max_fragments: c.max_fragments,
            max_reassembly_bytes: c.max_reassembly_bytes,
            max_reorder_window: c.max_reorder_window,
            max_ack_bitmap_bytes: c.max_ack_bitmap_bytes,
            max_duty_log_entries: c.max_duty_log_entries,
            initial_rto_ms: c.initial_rto_ms,
            min_rto_ms: c.min_rto_ms,
            max_rto_ms: c.max_rto_ms,
            rttvar_multiplier: c.rttvar_multiplier,
            backoff_grace: c.backoff_grace,
            deep_backoff_after_ms: c.deep_backoff_after_ms,
            max_probe_interval_ms: c.max_probe_interval_ms,
            max_sent_log: c.max_sent_log,
            max_frag_acks_per_packet: c.max_frag_acks_per_packet,
            counter_reservation: c.counter_reservation,
            ack_delay_ms: c.ack_delay_ms,
            fec,
            fec_max_sources: c.fec_max_sources,
            fec_flush_ms: c.fec_flush_ms,
            fec_min_loss_permille: c.fec_min_loss_permille,
            fec_max_packet_cost_ms: c.fec_max_packet_cost_ms,
            max_fec_rx_bytes: c.max_fec_rx_bytes,
            max_fec_pending_repairs: c.max_fec_pending_repairs,
            wall_clock: c.wall_clock,
            hello,
            hello_verify_per_minute: c.hello_verify_per_minute,
            hello_verify_burst: c.hello_verify_burst,
            hello_dedupe_entries: c.hello_dedupe_entries,
        })
    }
}

/// Writes the default configuration.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn avl_config_default(out: *mut AvlConfig) -> AvlStatus {
    guard(|| {
        if out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees a writable struct.
        unsafe { *out = Config::default().into() };
        AvlStatus::Ok
    })
}

/// Link budget kind.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvlBudgetKind {
    /// No pacing.
    Unlimited = 0,
    /// `bytes_per_second`.
    Rate = 1,
    /// `duty_permille` of `duty_window_ms`, with the airtime model.
    DutyCycle = 2,
}

/// A link's MTU, budget and cost (mirrors `avianlink_core::LinkConfig`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AvlLinkConfig {
    /// Maximum packet size (at least 48).
    pub mtu: u16,
    /// Relative cost; lower is preferred.
    pub cost: u16,
    /// An `AvlBudgetKind` value: which budget fields apply.
    pub budget: u8,
    /// For `RATE`.
    pub bytes_per_second: u32,
    /// For `DUTY_CYCLE`: allowed airtime in parts per thousand.
    pub duty_permille: u16,
    /// For `DUTY_CYCLE`: window length.
    pub duty_window_ms: u32,
    /// For `DUTY_CYCLE`: fixed airtime per packet.
    pub airtime_per_packet_us: u32,
    /// For `DUTY_CYCLE`: airtime per byte.
    pub airtime_per_byte_us: u32,
}

impl TryFrom<AvlLinkConfig> for LinkConfig {
    type Error = ();

    /// Fails on an unknown `budget` value.
    fn try_from(c: AvlLinkConfig) -> Result<Self, ()> {
        const UNLIMITED: u8 = AvlBudgetKind::Unlimited as u8;
        const RATE: u8 = AvlBudgetKind::Rate as u8;
        const DUTY_CYCLE: u8 = AvlBudgetKind::DutyCycle as u8;
        let budget = match c.budget {
            UNLIMITED => LinkBudget::Unlimited,
            RATE => LinkBudget::BytesPerSecond(c.bytes_per_second),
            DUTY_CYCLE => LinkBudget::DutyCycle {
                permille: c.duty_permille,
                window_ms: c.duty_window_ms,
                airtime: AirtimeModel {
                    per_packet_us: c.airtime_per_packet_us,
                    per_byte_us: c.airtime_per_byte_us,
                },
            },
            _ => return Err(()),
        };
        Ok(LinkConfig {
            mtu: c.mtu,
            budget,
            cost: c.cost,
        })
    }
}

// ---------------------------------------------------------------------
// Engine

/// An engine instance. Not thread-safe: use from one thread at a time.
pub struct AvlEngine {
    engine: Engine<AvlStorage, ChaCha20Rng>,
    /// A packet that did not fit the caller's buffer.
    pending_tx: Option<Transmit>,
    /// Backing store for the last event's text (NUL-terminated).
    event_text: Vec<u8>,
    /// The relay protocol, once a relay link is added (`docs/relay.md`).
    relay: Option<RelayClient>,
    /// Direct-link packets drawn from the engine while serving the relay.
    direct_tx: VecDeque<Transmit>,
    /// A relay datagram that did not fit the caller's buffer.
    pending_relay: Option<Vec<u8>>,
}

impl AvlEngine {
    /// Moves the engine's packets to where they go: relay-link packets to
    /// the relay client, the rest to `direct_tx`.
    fn pump(&mut self, now: Timestamp) {
        let Some(client) = self.relay.as_mut() else {
            return;
        };
        while let Some(tx) = self.engine.poll_transmit(now) {
            if tx.link == client.link() {
                client.upload(&mut self.engine, tx, now);
            } else {
                self.direct_tx.push_back(tx);
            }
        }
    }
}

/// Opens an engine for the identity with 32-byte `secret`, taking ownership
/// of `storage`. `create`: start fresh state for a *new* identity (fails
/// with `AVL_ENGINE_ERROR_STORAGE_NOT_EMPTY` if `storage` holds an engine).
/// Otherwise restore it (fails with `AVL_ENGINE_ERROR_STATE_MISSING` if
/// `storage` is empty). An identity whose state is lost must not be reused:
/// generate a new one (`docs/ffi.md` §2). `config` may be null for defaults.
/// On failure `storage` is freed.
///
/// # Safety
/// `secret` must point to 32 readable bytes; `storage` must be a live handle
/// not owned elsewhere; `config` null or readable; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_open(
    secret: *const u8,
    storage: *mut AvlStorage,
    config: *const AvlConfig,
    create: bool,
    out: *mut *mut AvlEngine,
) -> AvlStatus {
    guard(|| {
        if storage.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller hands over ownership of a live handle.
        let storage = *unsafe { Box::from_raw(storage) };
        if secret.is_null() || out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees 32 readable bytes.
        let identity = Identity::from_secret_bytes(unsafe { &*secret.cast::<[u8; 32]>() });
        let config = if config.is_null() {
            Config::default()
        } else {
            // SAFETY: caller guarantees a readable struct.
            match Config::try_from(unsafe { *config }) {
                Ok(c) => c,
                Err(()) => return engine_err(Error::InvalidConfig),
            }
        };
        let opened = if create {
            Engine::new(config, identity, storage, os_rng())
        } else {
            Engine::restore(config, identity, storage, os_rng())
        };
        match opened {
            Ok(engine) => give(
                AvlEngine {
                    engine,
                    pending_tx: None,
                    event_text: Vec::new(),
                    relay: None,
                    direct_tx: VecDeque::new(),
                    pending_relay: None,
                },
                out,
            ),
            Err(e) => engine_err(e),
        }
    })
}

/// Frees an engine and its storage.
///
/// # Safety
/// `engine` must be null or a live handle from `avl_engine_open`.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_free(engine: *mut AvlEngine) {
    if !engine.is_null() {
        // SAFETY: caller guarantees ownership of a live handle.
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(engine) })));
    }
}

/// Runs `f` on a live engine handle.
fn with_engine(engine: *mut AvlEngine, f: impl FnOnce(&mut AvlEngine) -> AvlStatus) -> AvlStatus {
    guard(|| {
        if engine.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: every caller of the public functions guarantees a live,
        // exclusively used handle.
        f(unsafe { &mut *engine })
    })
}

fn ts(ms: u64) -> Timestamp {
    Timestamp::from_millis(ms)
}

/// Reads a 16-byte conversation ID.
///
/// # Safety
/// `p` must be null or point to 16 readable bytes.
unsafe fn conv_in(p: *const u8) -> Option<ConversationId> {
    if p.is_null() {
        return None;
    }
    // SAFETY: caller guarantees 16 readable bytes.
    Some(ConversationId(unsafe { *p.cast::<[u8; 16]>() }))
}

/// Writes `bytes` to `p` if non-null.
///
/// # Safety
/// `p` must be null or point to `bytes.len()` writable bytes.
unsafe fn copy_out(bytes: &[u8], p: *mut u8) {
    if !p.is_null() {
        // SAFETY: caller guarantees room.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
    }
}

/// Registers a link (`link_id` is the host's own number for it).
///
/// # Safety
/// `engine` live; `link` readable.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_add_link(
    engine: *mut AvlEngine,
    link_id: u16,
    link: *const AvlLinkConfig,
) -> AvlStatus {
    with_engine(engine, |e| {
        if link.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees a readable struct.
        let Ok(cfg) = LinkConfig::try_from(unsafe { *link }) else {
            return engine_err(Error::InvalidLinkConfig);
        };
        match e.engine.add_link(LinkId(link_id), cfg) {
            Ok(()) => AvlStatus::Ok,
            Err(err) => engine_err(err),
        }
    })
}

/// Unregisters a link.
///
/// # Safety
/// `engine` live.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_remove_link(engine: *mut AvlEngine, link_id: u16) -> AvlStatus {
    with_engine(engine, |e| match e.engine.remove_link(LinkId(link_id)) {
        Ok(()) => AvlStatus::Ok,
        Err(err) => engine_err(err),
    })
}

/// Adds a contact by 32-byte public key (or finds an existing one) and
/// writes the 16-byte conversation ID.
///
/// # Safety
/// `engine` live; `public_key` 32 readable bytes; `conversation_out` 16
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_add_contact(
    engine: *mut AvlEngine,
    public_key: *const u8,
    conversation_out: *mut u8,
) -> AvlStatus {
    with_engine(engine, |e| {
        if public_key.is_null() || conversation_out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees 32 readable bytes.
        let key = PublicKey(unsafe { *public_key.cast::<[u8; 32]>() });
        let existing = e.engine.contacts().find(|(_, k)| *k == key).map(|(c, _)| c);
        let conv = match existing {
            Some(c) => c,
            None => match e.engine.add_contact(key) {
                Ok(c) => c,
                Err(err) => return engine_err(err),
            },
        };
        // SAFETY: caller guarantees 16 writable bytes.
        unsafe { copy_out(&conv.0, conversation_out) };
        AvlStatus::Ok
    })
}

/// Removes a contact and abandons its undelivered messages.
///
/// # Safety
/// `engine` live; `conversation` 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_remove_contact(
    engine: *mut AvlEngine,
    conversation: *const u8,
) -> AvlStatus {
    with_engine(engine, |e| {
        // SAFETY: caller guarantees 16 readable bytes.
        let Some(conv) = (unsafe { conv_in(conversation) }) else {
            return AvlStatus::ErrInvalidArgument;
        };
        match e.engine.remove_contact(conv) {
            Ok(_) => AvlStatus::Ok,
            Err(err) => engine_err(err),
        }
    })
}

/// A queued message (`avl_engine_send_text`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AvlQueued {
    /// Content-addressed message ID.
    pub id: [u8; 16],
    /// Sequence number in the conversation.
    pub seq: u64,
    /// Lamport value: the causal sort key.
    pub lamport: u64,
}

/// Queues a UTF-8 message (durable on `AVL_STATUS_OK`).
///
/// # Safety
/// `engine` live; `conversation` 16 readable bytes; `text` `text_len`
/// readable bytes; `queued_out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_send_text(
    engine: *mut AvlEngine,
    conversation: *const u8,
    text: *const u8,
    text_len: usize,
    now_ms: u64,
    queued_out: *mut AvlQueued,
) -> AvlStatus {
    with_engine(engine, |e| {
        // SAFETY: caller guarantees 16 readable bytes.
        let Some(conv) = (unsafe { conv_in(conversation) }) else {
            return AvlStatus::ErrInvalidArgument;
        };
        if text.is_null() && text_len > 0 {
            return AvlStatus::ErrInvalidArgument;
        }
        let bytes = if text_len == 0 {
            &[][..]
        } else {
            // SAFETY: caller guarantees `text_len` readable bytes.
            unsafe { std::slice::from_raw_parts(text, text_len) }
        };
        let Ok(s) = std::str::from_utf8(bytes) else {
            return AvlStatus::ErrInvalidArgument;
        };
        match e.engine.send_text(conv, s, ts(now_ms)) {
            Ok(q) => {
                if !queued_out.is_null() {
                    // SAFETY: caller guarantees a writable struct.
                    unsafe {
                        *queued_out = AvlQueued {
                            id: q.id.0,
                            seq: q.seq,
                            lamport: q.lamport,
                        }
                    };
                }
                AvlStatus::Ok
            }
            Err(err) => engine_err(err),
        }
    })
}

/// Feeds a received packet. Returns:
/// - `AVL_STATUS_OK`: an authenticated packet from a contact; its
///   conversation is written. Update that contact's address to the source.
/// - `AVL_STATUS_HELLO`: a verified Hello from an unknown key, written to
///   `public_key_out`; an `AVL_EVENT_KIND_CONTACT_REQUEST` was queued. The
///   source address is only a candidate (Hellos can be replayed).
/// - `AVL_STATUS_NONE`: dropped, or nothing to act on.
///
/// # Safety
/// `engine` live; `bytes` `len` readable bytes; `conversation_out` null or
/// 16 writable bytes; `public_key_out` null or 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_handle_packet(
    engine: *mut AvlEngine,
    link_id: u16,
    bytes: *const u8,
    len: usize,
    now_ms: u64,
    conversation_out: *mut u8,
    public_key_out: *mut u8,
) -> AvlStatus {
    with_engine(engine, |e| {
        if bytes.is_null() && len > 0 {
            return AvlStatus::ErrInvalidArgument;
        }
        let data = if len == 0 {
            &[][..]
        } else {
            // SAFETY: caller guarantees `len` readable bytes.
            unsafe { std::slice::from_raw_parts(bytes, len) }
        };
        let received = e.engine.handle_packet(LinkId(link_id), data, ts(now_ms));
        // SAFETY: caller guarantees the output buffers (or null).
        unsafe { received_status(received, conversation_out, public_key_out) }
    })
}

/// Advances timers; call when `avl_engine_next_timeout` is reached.
///
/// # Safety
/// `engine` live.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_handle_timeout(
    engine: *mut AvlEngine,
    now_ms: u64,
) -> AvlStatus {
    with_engine(engine, |e| {
        e.engine.handle_timeout(ts(now_ms));
        if let Some(client) = e.relay.as_mut() {
            client.handle_timeout(&mut e.engine, ts(now_ms));
        }
        AvlStatus::Ok
    })
}

/// Connectivity may have changed: probe unreachable contacts now.
///
/// # Safety
/// `engine` live.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_nudge(engine: *mut AvlEngine, now_ms: u64) -> AvlStatus {
    with_engine(engine, |e| {
        e.engine.nudge(ts(now_ms));
        AvlStatus::Ok
    })
}

/// Writes the next packet to send into `buf`. On `AVL_STATUS_OK`: the link,
/// destination conversation and length are written. `AVL_STATUS_NONE`:
/// nothing to send now. `AVL_STATUS_ERR_BUFFER_TOO_SMALL`: `*len_out` is
/// the size needed and the packet is kept for the next call. Call until
/// `AVL_STATUS_NONE`.
///
/// # Safety
/// `engine` live; `buf` `cap` writable bytes; `link_out`, `len_out`
/// writable; `conversation_out` null or 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_poll_transmit(
    engine: *mut AvlEngine,
    now_ms: u64,
    link_out: *mut u16,
    conversation_out: *mut u8,
    buf: *mut u8,
    cap: usize,
    len_out: *mut usize,
) -> AvlStatus {
    with_engine(engine, |e| {
        if link_out.is_null() || len_out.is_null() || (buf.is_null() && cap > 0) {
            return AvlStatus::ErrInvalidArgument;
        }
        let next = if e.relay.is_some() {
            // Relay-link packets go to the relay client instead
            // (`avl_relay_poll_transmit`).
            e.pump(ts(now_ms));
            e.direct_tx.pop_front()
        } else {
            e.engine.poll_transmit(ts(now_ms))
        };
        let tx = match e.pending_tx.take().or(next) {
            Some(tx) => tx,
            None => return AvlStatus::None,
        };
        let bytes = tx.packet.as_bytes();
        // SAFETY: caller guarantees writable `len_out`.
        unsafe { *len_out = bytes.len() };
        if bytes.len() > cap {
            e.pending_tx = Some(tx);
            return AvlStatus::ErrBufferTooSmall;
        }
        // SAFETY: caller guarantees `cap` ≥ len writable bytes, a writable
        // `link_out` and 16 bytes (or null) at `conversation_out`.
        unsafe {
            copy_out(bytes, buf);
            *link_out = tx.link.0;
            copy_out(&tx.to.0, conversation_out);
        }
        AvlStatus::Ok
    })
}

/// When the engine next wants `avl_engine_handle_timeout`: returns true and
/// writes the time, or false for "only on new input".
///
/// # Safety
/// `engine` null or live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_next_timeout(engine: *mut AvlEngine, out: *mut u64) -> bool {
    let mut found = false;
    let _ = with_engine(engine, |e| {
        let relay = e.relay.as_ref().and_then(RelayClient::next_timeout);
        let next = match (e.engine.next_timeout(), relay) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let (Some(t), false) = (next, out.is_null()) {
            // SAFETY: caller guarantees a writable `out`.
            unsafe { *out = t.as_millis() };
            found = true;
        }
        AvlStatus::Ok
    });
    found
}

// ---------------------------------------------------------------------
// Relays (`docs/relay.md`, `docs/ffi.md` §4)

/// Registers a link to a store-and-forward relay and starts the relay
/// protocol on it (`docs/relay.md` §6–7). One relay per engine. The host
/// sends what `avl_relay_poll_transmit` returns to the relay's address and
/// feeds what arrives from it to `avl_relay_handle`. Its MTU should suit
/// the smallest link any recipient fetches over (48 when unsure).
///
/// # Safety
/// `engine` live; `link` readable.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_add_relay_link(
    engine: *mut AvlEngine,
    link_id: u16,
    link: *const AvlLinkConfig,
) -> AvlStatus {
    with_engine(engine, |e| {
        if link.is_null() || e.relay.is_some() {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees a readable struct.
        let Ok(cfg) = LinkConfig::try_from(unsafe { *link }) else {
            return engine_err(Error::InvalidLinkConfig);
        };
        match e.engine.add_relay_link(LinkId(link_id), cfg) {
            Ok(()) => {
                e.relay = Some(RelayClient::new(LinkId(link_id)));
                AvlStatus::Ok
            }
            Err(err) => engine_err(err),
        }
    })
}

/// Runs `f` on an engine that has a relay link.
fn with_relay(engine: *mut AvlEngine, f: impl FnOnce(&mut AvlEngine) -> AvlStatus) -> AvlStatus {
    with_engine(engine, |e| {
        if e.relay.is_none() {
            return AvlStatus::ErrInvalidArgument;
        }
        f(e)
    })
}

/// The host came online (or the network came back): register mailboxes,
/// open upload sessions and fetch everything waiting at the relay.
///
/// # Safety
/// `engine` live, with a relay link.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_connect(engine: *mut AvlEngine, now_ms: u64) -> AvlStatus {
    with_relay(engine, |e| {
        if let Some(client) = e.relay.as_mut() {
            client.connect(&mut e.engine, ts(now_ms));
        }
        AvlStatus::Ok
    })
}

/// The host is going offline. Nothing is lost: what isn't stored at the
/// relay or delivered stays queued. Check `avl_relay_safe_to_disconnect`
/// first.
///
/// # Safety
/// `engine` live, with a relay link.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_disconnect(engine: *mut AvlEngine) -> AvlStatus {
    with_relay(engine, |e| {
        if let Some(client) = e.relay.as_mut() {
            client.disconnect();
        }
        e.pending_relay = None;
        AvlStatus::Ok
    })
}

/// Feeds a datagram that arrived from the relay. Relay messages are handled
/// inside; packets and Hellos it delivers go to the engine, with the same
/// results as `avl_engine_handle_packet` (`AVL_STATUS_OK` with the
/// conversation, `AVL_STATUS_HELLO` with the key, or `AVL_STATUS_NONE`).
///
/// # Safety
/// `engine` live, with a relay link; `bytes` `len` readable bytes;
/// `conversation_out` null or 16 writable bytes; `public_key_out` null or
/// 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_handle(
    engine: *mut AvlEngine,
    bytes: *const u8,
    len: usize,
    now_ms: u64,
    conversation_out: *mut u8,
    public_key_out: *mut u8,
) -> AvlStatus {
    with_relay(engine, |e| {
        if bytes.is_null() && len > 0 {
            return AvlStatus::ErrInvalidArgument;
        }
        let data = if len == 0 {
            &[][..]
        } else {
            // SAFETY: caller guarantees `len` readable bytes.
            unsafe { std::slice::from_raw_parts(bytes, len) }
        };
        let Some(client) = e.relay.as_mut() else {
            return AvlStatus::ErrInvalidArgument;
        };
        let received = client.handle(&mut e.engine, data, ts(now_ms));
        // SAFETY: caller guarantees the output buffers (or null).
        unsafe { received_status(received, conversation_out, public_key_out) }
    })
}

/// Writes the next datagram to send to the relay into `buf`. Like
/// `avl_engine_poll_transmit`: `AVL_STATUS_NONE` when there is nothing,
/// `AVL_STATUS_ERR_BUFFER_TOO_SMALL` with the size needed (the datagram is
/// kept). Call until `AVL_STATUS_NONE`.
///
/// # Safety
/// `engine` live, with a relay link; `buf` `cap` writable bytes; `len_out`
/// writable.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_poll_transmit(
    engine: *mut AvlEngine,
    now_ms: u64,
    buf: *mut u8,
    cap: usize,
    len_out: *mut usize,
) -> AvlStatus {
    with_relay(engine, |e| {
        if len_out.is_null() || (buf.is_null() && cap > 0) {
            return AvlStatus::ErrInvalidArgument;
        }
        e.pump(ts(now_ms));
        let next = e.relay.as_mut().and_then(RelayClient::poll_transmit);
        let Some(bytes) = e.pending_relay.take().or(next) else {
            return AvlStatus::None;
        };
        // SAFETY: caller guarantees writable `len_out`.
        unsafe { *len_out = bytes.len() };
        if bytes.len() > cap {
            e.pending_relay = Some(bytes);
            return AvlStatus::ErrBufferTooSmall;
        }
        // SAFETY: caller guarantees `cap` ≥ len writable bytes.
        unsafe { copy_out(&bytes, buf) };
        AvlStatus::Ok
    })
}

/// Everything owed to relay contacts (messages, ACKs, Hellos) is stored at
/// the relay.
///
/// # Safety
/// `engine` null or live.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_settled(engine: *mut AvlEngine) -> bool {
    let mut v = false;
    let _ = with_relay(engine, |e| {
        v = e.engine.relay_settled();
        AvlStatus::Ok
    });
    v
}

/// Everything waiting at the relay has been read.
///
/// # Safety
/// `engine` null or live.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_caught_up(engine: *mut AvlEngine) -> bool {
    let mut v = false;
    let _ = with_relay(engine, |e| {
        v = e.relay.as_ref().is_some_and(RelayClient::caught_up);
        AvlStatus::Ok
    });
    v
}

/// Settled and caught up: safe to go offline ("come online, collect,
/// reply, leave").
///
/// # Safety
/// `engine` null or live.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_safe_to_disconnect(engine: *mut AvlEngine) -> bool {
    // SAFETY: forwarded under the same contract.
    unsafe { avl_relay_settled(engine) && avl_relay_caught_up(engine) }
}

// ---------------------------------------------------------------------
// Push notifications (docs/push.md)

/// Who delivers a push: the `provider` argument of `avl_push_seal`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvlPushProvider {
    /// APNs, production.
    Apns = 1,
    /// APNs sandbox (development builds).
    ApnsSandbox = 2,
    /// Firebase Cloud Messaging.
    Fcm = 3,
}

/// Seals a device token to the push service whose public key is
/// `service_key` (`push.md` §2). Do it once per token and keep the blob;
/// pass it to `avl_relay_set_push`. `provider` is an `AvlPushProvider`;
/// `app` is the app's index in the push service's configuration. Writes at
/// most 512 bytes; `AVL_STATUS_ERR_BUFFER_TOO_SMALL` with the size needed.
///
/// # Safety
/// `service_key` 32 readable bytes; `token` `token_len` readable bytes;
/// `buf` `cap` writable bytes; `len_out` writable.
#[no_mangle]
pub unsafe extern "C" fn avl_push_seal(
    service_key: *const u8,
    provider: u8,
    app: u8,
    token: *const u8,
    token_len: usize,
    buf: *mut u8,
    cap: usize,
    len_out: *mut usize,
) -> AvlStatus {
    guard(|| {
        if service_key.is_null()
            || token.is_null()
            || len_out.is_null()
            || (buf.is_null() && cap > 0)
            || token_len > push::MAX_TOKEN
        {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees 32 and `token_len` readable bytes.
        let (key, token) = unsafe {
            (
                PublicKey(*service_key.cast::<[u8; 32]>()),
                std::slice::from_raw_parts(token, token_len),
            )
        };
        let reg = push::Registration {
            provider: push::Provider::from_u8(provider),
            app,
            token: token.to_vec(),
        };
        let Some(blob) = push::seal(&key, &reg, &mut os_rng()) else {
            return AvlStatus::ErrInvalidArgument;
        };
        // SAFETY: caller guarantees writable `len_out`.
        unsafe { *len_out = blob.len() };
        if blob.len() > cap {
            return AvlStatus::ErrBufferTooSmall;
        }
        // SAFETY: caller guarantees `cap` ≥ len writable bytes.
        unsafe { copy_out(&blob, buf) };
        AvlStatus::Ok
    })
}

/// Turns on push notifications at the relay, or updates them. `secret` is
/// 16 random bytes the app chooses once and keeps (in the keychain, beside
/// the identity); `blob` comes from `avl_push_seal`. With `hellos`, contact
/// requests push too, which lets the relay operator link this registration
/// to the identity (`push.md` §4.3). Takes effect at once if connected,
/// else at the next `avl_relay_connect`.
///
/// # Safety
/// `engine` live, with a relay link; `secret` 16 readable bytes; `blob`
/// `blob_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_set_push(
    engine: *mut AvlEngine,
    secret: *const u8,
    blob: *const u8,
    blob_len: usize,
    hellos: bool,
    now_ms: u64,
) -> AvlStatus {
    with_relay(engine, |e| {
        if secret.is_null() || blob.is_null() || blob_len == 0 || blob_len > MAX_PUSH_BLOB {
            return AvlStatus::ErrInvalidArgument;
        }
        // SAFETY: caller guarantees 16 and `blob_len` readable bytes.
        let (secret, blob) = unsafe {
            (
                *secret.cast::<[u8; 16]>(),
                std::slice::from_raw_parts(blob, blob_len).to_vec(),
            )
        };
        if let Some(client) = e.relay.as_mut() {
            client.set_push(Some(PushConfig {
                secret,
                blob,
                hellos,
            }));
            client.handle_timeout(&mut e.engine, ts(now_ms));
        }
        AvlStatus::Ok
    })
}

/// Turns push notifications off: the relay deletes the registration and
/// its bindings at the next chance.
///
/// # Safety
/// `engine` live, with a relay link.
#[no_mangle]
pub unsafe extern "C" fn avl_relay_clear_push(engine: *mut AvlEngine, now_ms: u64) -> AvlStatus {
    with_relay(engine, |e| {
        if let Some(client) = e.relay.as_mut() {
            client.set_push(None);
            client.handle_timeout(&mut e.engine, ts(now_ms));
        }
        AvlStatus::Ok
    })
}

/// Maps a `Received` to a status and its outputs.
///
/// # Safety
/// `conversation_out` null or 16 writable bytes; `public_key_out` null or
/// 32 writable bytes.
unsafe fn received_status(
    received: Received,
    conversation_out: *mut u8,
    public_key_out: *mut u8,
) -> AvlStatus {
    match received {
        Received::Contact(conv) => {
            // SAFETY: caller guarantees 16 writable bytes or null.
            unsafe { copy_out(&conv.0, conversation_out) };
            AvlStatus::Ok
        }
        Received::ContactRequest(key) => {
            // SAFETY: caller guarantees 32 writable bytes or null.
            unsafe { copy_out(&key.0, public_key_out) };
            AvlStatus::Hello
        }
        Received::Ignored => AvlStatus::None,
    }
}

/// Event kinds (`AvlEvent::kind`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvlEventKind {
    /// A message arrived: `conversation`, `id`, `seq`, `lamport`,
    /// `missing_before`, `sender_time_ms` (if `has_sender_time`),
    /// `received_at_ms`, `text`/`text_len`.
    MessageReceived = 1,
    /// One of our messages was acknowledged: `conversation`, `id`.
    MessageDelivered = 2,
    /// One of our messages went out for the first time: `conversation`, `id`.
    MessageTransmitted = 3,
    /// `count` messages from `first_seq` will never arrive (previous install).
    MessagesSkipped = 4,
    /// The peer's history differs for `first_seq..=last_seq`.
    SyncDiverged = 5,
    /// A key we don't know asks to be added: `public_key`, `link`,
    /// `received_at_ms`. Compare fingerprints, then `avl_engine_add_contact`.
    ContactRequest = 6,
    /// Every fragment of one of our messages is stored at the relay:
    /// `conversation`, `id`. Not delivery (that is `MESSAGE_DELIVERED`).
    MessageStored = 7,
}

/// An event. `text` is borrowed (see `docs/ffi.md` §2).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct AvlEvent {
    pub kind: AvlEventKind,
    pub conversation: [u8; 16],
    pub id: [u8; 16],
    pub seq: u64,
    pub lamport: u64,
    pub missing_before: u64,
    pub has_sender_time: bool,
    pub sender_time_ms: u64,
    pub received_at_ms: u64,
    /// NUL-terminated UTF-8, valid until the next `avl_engine_poll_event`.
    pub text: *const c_char,
    pub text_len: usize,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    pub public_key: [u8; 32],
    pub link: u16,
}

impl AvlEvent {
    fn blank(kind: AvlEventKind, conversation: ConversationId) -> Self {
        Self {
            kind,
            conversation: conversation.0,
            id: [0; 16],
            seq: 0,
            lamport: 0,
            missing_before: 0,
            has_sender_time: false,
            sender_time_ms: 0,
            received_at_ms: 0,
            text: std::ptr::null(),
            text_len: 0,
            first_seq: 0,
            last_seq: 0,
            count: 0,
            public_key: [0; 32],
            link: 0,
        }
    }
}

/// Writes the next event. `AVL_STATUS_NONE` when there is none.
///
/// # Safety
/// `engine` live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_poll_event(
    engine: *mut AvlEngine,
    out: *mut AvlEvent,
) -> AvlStatus {
    with_engine(engine, |e| {
        if out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        loop {
            let Some(ev) = e.engine.poll_event() else {
                return AvlStatus::None;
            };
            let mapped = match ev {
                Event::MessageReceived(m) => {
                    e.event_text.clear();
                    e.event_text.extend_from_slice(m.text.as_bytes());
                    e.event_text.push(0);
                    let mut v = AvlEvent::blank(AvlEventKind::MessageReceived, m.conversation);
                    v.id = m.id.0;
                    v.seq = m.seq;
                    v.lamport = m.lamport;
                    v.missing_before = m.missing_before;
                    v.has_sender_time = m.sender_time.is_some();
                    v.sender_time_ms = m.sender_time.map_or(0, Timestamp::as_millis);
                    v.received_at_ms = m.received_at.as_millis();
                    v.text = e.event_text.as_ptr().cast();
                    v.text_len = m.text.len();
                    v
                }
                Event::MessageDelivered { conversation, id } => {
                    let mut v = AvlEvent::blank(AvlEventKind::MessageDelivered, conversation);
                    v.id = id.0;
                    v
                }
                Event::MessageTransmitted { conversation, id } => {
                    let mut v = AvlEvent::blank(AvlEventKind::MessageTransmitted, conversation);
                    v.id = id.0;
                    v
                }
                Event::MessageStored { conversation, id } => {
                    let mut v = AvlEvent::blank(AvlEventKind::MessageStored, conversation);
                    v.id = id.0;
                    v
                }
                Event::MessagesSkipped {
                    conversation,
                    first_seq,
                    count,
                } => {
                    let mut v = AvlEvent::blank(AvlEventKind::MessagesSkipped, conversation);
                    v.first_seq = first_seq;
                    v.count = count;
                    v
                }
                Event::SyncDiverged {
                    conversation,
                    first_seq,
                    last_seq,
                } => {
                    let mut v = AvlEvent::blank(AvlEventKind::SyncDiverged, conversation);
                    v.first_seq = first_seq;
                    v.last_seq = last_seq;
                    v
                }
                Event::ContactRequest {
                    public_key,
                    link,
                    received_at,
                } => {
                    let mut v =
                        AvlEvent::blank(AvlEventKind::ContactRequest, ConversationId([0; 16]));
                    v.public_key = public_key.0;
                    v.link = link.0;
                    v.received_at_ms = received_at.as_millis();
                    v
                }
                // Event kinds newer than this ABI are skipped.
                _ => continue,
            };
            // SAFETY: caller guarantees a writable struct.
            unsafe { *out = mapped };
            return AvlStatus::Ok;
        }
    })
}

/// A contact's reachability (`avl_engine_contact_status`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(missing_docs)]
pub struct AvlContactStatus {
    pub has_last_heard: bool,
    pub last_heard_ms: u64,
    pub has_srtt: bool,
    pub srtt_ms: u64,
    pub rto_ms: u64,
    pub unreachable: bool,
    pub outbox_len: usize,
    /// Loss we measure on the contact's packets, permille; -1 if unknown.
    pub loss_in_permille: i32,
    /// Loss the contact reports on ours, permille; -1 if unknown.
    pub loss_out_permille: i32,
    /// The contact has shown it knows our key.
    pub confirmed: bool,
}

/// Writes a contact's status.
///
/// # Safety
/// `engine` live; `conversation` 16 readable bytes; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_contact_status(
    engine: *mut AvlEngine,
    conversation: *const u8,
    out: *mut AvlContactStatus,
) -> AvlStatus {
    with_engine(engine, |e| {
        // SAFETY: caller guarantees 16 readable bytes.
        let Some(conv) = (unsafe { conv_in(conversation) }) else {
            return AvlStatus::ErrInvalidArgument;
        };
        if out.is_null() {
            return AvlStatus::ErrInvalidArgument;
        }
        let Some(s) = e.engine.contact_status(conv) else {
            return engine_err(Error::UnknownConversation);
        };
        let perm = |p: Option<u64>| p.map_or(-1, |v| i32::try_from(v).unwrap_or(i32::MAX));
        // SAFETY: caller guarantees a writable struct.
        unsafe {
            *out = AvlContactStatus {
                has_last_heard: s.last_heard.is_some(),
                last_heard_ms: s.last_heard.map_or(0, Timestamp::as_millis),
                has_srtt: s.srtt_ms.is_some(),
                srtt_ms: s.srtt_ms.unwrap_or(0),
                rto_ms: s.rto_ms,
                unreachable: s.unreachable,
                outbox_len: s.outbox_len,
                loss_in_permille: perm(s.loss_in_permille),
                loss_out_permille: perm(s.loss_out_permille),
                confirmed: s.confirmed,
            }
        };
        AvlStatus::Ok
    })
}

/// Undelivered outgoing messages across all conversations.
///
/// # Safety
/// `engine` null or live.
#[no_mangle]
pub unsafe extern "C" fn avl_engine_outbox_len(engine: *mut AvlEngine) -> usize {
    let mut n = 0;
    let _ = with_engine(engine, |e| {
        n = e.engine.outbox_len();
        AvlStatus::Ok
    });
    n
}

#[cfg(test)]
mod tests;
