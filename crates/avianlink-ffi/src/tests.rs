//! Exercises the C ABI from Rust, as a C caller would.
//!
//! Every call here crosses the unsafe ABI with pointers to locals; rustfmt
//! separates `// SAFETY:` comments from blocks inside `assert_eq!`.
#![allow(clippy::undocumented_unsafe_blocks)]

use std::collections::BTreeMap;
use std::ptr::{null, null_mut};

use super::*;

const LINK: u16 = 7;
const MTU: u16 = 200;

fn link_config() -> AvlLinkConfig {
    AvlLinkConfig {
        mtu: MTU,
        cost: 1,
        budget: AvlBudgetKind::Unlimited as u8,
        bytes_per_second: 0,
        duty_permille: 0,
        duty_window_ms: 0,
        airtime_per_packet_us: 0,
        airtime_per_byte_us: 0,
    }
}

struct Node {
    engine: *mut AvlEngine,
    public: [u8; 32],
    secret: [u8; 32],
}

impl Drop for Node {
    fn drop(&mut self) {
        // SAFETY: owned live handle (or null).
        unsafe { avl_engine_free(self.engine) };
    }
}

fn open(secret: [u8; 32], storage: *mut AvlStorage) -> Result<*mut AvlEngine, AvlStatus> {
    let mut engine = null_mut();
    // SAFETY: valid pointers; storage is a live handle.
    let st = unsafe { avl_engine_open(secret.as_ptr(), storage, null(), &mut engine) };
    if st != AvlStatus::Ok {
        return Err(st);
    }
    // SAFETY: live engine, readable config.
    assert_eq!(
        unsafe { avl_engine_add_link(engine, LINK, &link_config()) },
        AvlStatus::Ok
    );
    Ok(engine)
}

fn memory_node() -> Node {
    let (mut secret, mut public) = ([0u8; 32], [0u8; 32]);
    // SAFETY: 32-byte buffers.
    assert_eq!(
        unsafe { avl_identity_generate(secret.as_mut_ptr(), public.as_mut_ptr()) },
        AvlStatus::Ok
    );
    let mut storage = null_mut();
    // SAFETY: writable out.
    assert_eq!(
        unsafe { avl_storage_memory_new(&mut storage) },
        AvlStatus::Ok
    );
    Node {
        engine: open(secret, storage).unwrap(),
        public,
        secret,
    }
}

fn add_contact(node: &Node, key: &[u8; 32]) -> [u8; 16] {
    let mut conv = [0u8; 16];
    // SAFETY: live engine; sized buffers.
    let st = unsafe { avl_engine_add_contact(node.engine, key.as_ptr(), conv.as_mut_ptr()) };
    assert_eq!(st, AvlStatus::Ok);
    conv
}

/// Moves every pending packet from `from` into `to`. Returns how many.
fn deliver(from: &Node, to: &Node, now: u64) -> usize {
    let mut n = 0;
    let mut buf = [0u8; MTU as usize];
    loop {
        let (mut link, mut len) = (0u16, 0usize);
        let mut conv = [0u8; 16];
        // SAFETY: live engine; sized buffers.
        let st = unsafe {
            avl_engine_poll_transmit(
                from.engine,
                now,
                &mut link,
                conv.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
            )
        };
        if st == AvlStatus::None {
            return n;
        }
        assert_eq!(st, AvlStatus::Ok);
        assert_eq!(link, LINK);
        // SAFETY: live engine; `len` readable bytes.
        let st = unsafe {
            avl_engine_handle_packet(to.engine, link, buf.as_ptr(), len, now, null_mut())
        };
        assert_eq!(st, AvlStatus::Ok);
        n += 1;
    }
}

fn events(node: &Node) -> Vec<(AvlEventKind, Option<String>)> {
    let mut out = Vec::new();
    loop {
        let mut ev = AvlEvent::blank(AvlEventKind::MessageDelivered, ConversationId([0; 16]));
        // SAFETY: live engine; writable event.
        match unsafe { avl_engine_poll_event(node.engine, &mut ev) } {
            AvlStatus::None => return out,
            AvlStatus::Ok => {
                let text = (!ev.text.is_null()).then(|| {
                    // SAFETY: borrowed NUL-terminated text, valid until the next poll.
                    let s = unsafe { CStr::from_ptr(ev.text) }
                        .to_str()
                        .unwrap()
                        .to_owned();
                    assert_eq!(s.len(), ev.text_len);
                    s
                });
                out.push((ev.kind, text));
            }
            st => panic!("poll_event: {st:?}"),
        }
    }
}

fn send(node: &Node, conv: &[u8; 16], text: &str, now: u64) -> AvlQueued {
    let mut q = AvlQueued::default();
    // SAFETY: live engine; sized buffers.
    let st = unsafe {
        avl_engine_send_text(
            node.engine,
            conv.as_ptr(),
            text.as_ptr(),
            text.len(),
            now,
            &mut q,
        )
    };
    assert_eq!(st, AvlStatus::Ok);
    q
}

#[test]
fn two_engines_exchange_a_message() {
    let a = memory_node();
    let b = memory_node();
    let ab = add_contact(&a, &b.public);
    add_contact(&b, &a.public);
    let text = "hello over the C ABI — with a 200-byte-ish tail ".repeat(4);
    let q = send(&a, &ab, &text, 1_000);
    assert_eq!(q.seq, 0);

    let mut now = 1_000;
    for _ in 0..20 {
        deliver(&a, &b, now);
        deliver(&b, &a, now);
        now += 100;
        // SAFETY: live engines.
        unsafe {
            avl_engine_handle_timeout(a.engine, now);
            avl_engine_handle_timeout(b.engine, now);
        }
    }
    let got = events(&b);
    assert!(
        got.contains(&(AvlEventKind::MessageReceived, Some(text))),
        "{got:?}"
    );
    let sent = events(&a);
    assert!(sent
        .iter()
        .any(|(k, _)| *k == AvlEventKind::MessageTransmitted));
    assert!(sent
        .iter()
        .any(|(k, _)| *k == AvlEventKind::MessageDelivered));
    // SAFETY: live engine.
    assert_eq!(unsafe { avl_engine_outbox_len(a.engine) }, 0);

    let mut st = AvlContactStatus::default();
    // SAFETY: live engine; sized buffers.
    assert_eq!(
        unsafe { avl_engine_contact_status(a.engine, ab.as_ptr(), &mut st) },
        AvlStatus::Ok
    );
    assert!(st.has_last_heard && st.has_srtt && !st.unreachable);
}

#[test]
fn small_buffer_keeps_the_packet() {
    let a = memory_node();
    let b = memory_node();
    let ab = add_contact(&a, &b.public);
    send(&a, &ab, "hi", 0);
    let (mut link, mut len) = (0u16, 0usize);
    let mut tiny = [0u8; 8];
    // SAFETY: live engine; sized buffers.
    let st = unsafe {
        avl_engine_poll_transmit(
            a.engine,
            0,
            &mut link,
            null_mut(),
            tiny.as_mut_ptr(),
            tiny.len(),
            &mut len,
        )
    };
    assert_eq!(st, AvlStatus::ErrBufferTooSmall);
    assert!(len > tiny.len() && len <= MTU as usize);
    let needed = len;
    let mut buf = vec![0u8; needed];
    // SAFETY: as above.
    let st = unsafe {
        avl_engine_poll_transmit(
            a.engine,
            0,
            &mut link,
            null_mut(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut len,
        )
    };
    assert_eq!(st, AvlStatus::Ok);
    assert_eq!(len, needed);
}

#[test]
fn null_and_invalid_arguments_are_rejected() {
    let a = memory_node();
    let mut conv = [0u8; 16];
    let mut q = AvlQueued::default();
    // SAFETY: every call passes at least one null or invalid argument, which
    // the ABI must reject without dereferencing.
    unsafe {
        assert_eq!(
            avl_identity_generate(null_mut(), null_mut()),
            AvlStatus::ErrInvalidArgument
        );
        assert_eq!(
            avl_engine_add_contact(null_mut(), a.public.as_ptr(), conv.as_mut_ptr()),
            AvlStatus::ErrInvalidArgument
        );
        assert_eq!(
            avl_engine_add_contact(a.engine, null(), conv.as_mut_ptr()),
            AvlStatus::ErrInvalidArgument
        );
        assert_eq!(
            avl_engine_send_text(a.engine, null(), b"x".as_ptr(), 1, 0, &mut q),
            AvlStatus::ErrInvalidArgument
        );
        assert_eq!(
            avl_engine_poll_event(a.engine, null_mut()),
            AvlStatus::ErrInvalidArgument
        );
        assert_eq!(
            avl_engine_open(a.secret.as_ptr(), null_mut(), null(), null_mut()),
            AvlStatus::ErrInvalidArgument
        );
        assert!(!avl_engine_next_timeout(null_mut(), null_mut()));
        assert_eq!(avl_engine_outbox_len(null_mut()), 0);
        avl_engine_free(null_mut());
        avl_storage_free(null_mut());

        // Own key is not a contact.
        assert_eq!(
            avl_engine_add_contact(a.engine, a.public.as_ptr(), conv.as_mut_ptr()),
            AvlStatus::ErrEngine
        );
        assert_eq!(avl_last_engine_error(), AvlEngineError::InvalidContact);
        // Unknown conversation.
        assert_eq!(
            avl_engine_send_text(a.engine, conv.as_ptr(), b"x".as_ptr(), 1, 0, &mut q),
            AvlStatus::ErrEngine
        );
        assert_eq!(avl_last_engine_error(), AvlEngineError::UnknownConversation);
        // Invalid UTF-8.
        let other = memory_node();
        let c = add_contact(&a, &other.public);
        assert_eq!(
            avl_engine_send_text(a.engine, c.as_ptr(), [0xffu8].as_ptr(), 1, 0, &mut q),
            AvlStatus::ErrInvalidArgument
        );
        // Out-of-range budget kind.
        let mut bad = link_config();
        bad.budget = 9;
        assert_eq!(
            avl_engine_add_link(a.engine, 99, &bad),
            AvlStatus::ErrEngine
        );
        assert_eq!(avl_last_engine_error(), AvlEngineError::InvalidLinkConfig);
        // Garbage packets are dropped, not errors.
        assert_eq!(
            avl_engine_handle_packet(a.engine, LINK, [1u8, 2, 3].as_ptr(), 3, 0, null_mut()),
            AvlStatus::None
        );
        assert_eq!(
            avl_engine_handle_packet(a.engine, LINK, null(), 0, 0, null_mut()),
            AvlStatus::None
        );
    }
}

#[test]
fn invalid_config_fails_open_and_frees_storage() {
    let mut cfg = std::mem::MaybeUninit::<AvlConfig>::uninit();
    // SAFETY: writable out.
    assert_eq!(
        unsafe { avl_config_default(cfg.as_mut_ptr()) },
        AvlStatus::Ok
    );
    // SAFETY: initialized above.
    let mut cfg = unsafe { cfg.assume_init() };
    assert_eq!(Config::try_from(cfg).unwrap(), Config::default());
    cfg.fec = 3;
    let (mut storage, mut engine) = (null_mut(), null_mut());
    // SAFETY: valid pointers; storage is consumed.
    unsafe {
        avl_storage_memory_new(&mut storage);
        assert_eq!(
            avl_engine_open([1u8; 32].as_ptr(), storage, &cfg, &mut engine),
            AvlStatus::ErrEngine
        );
    }
    assert_eq!(avl_last_engine_error(), AvlEngineError::InvalidConfig);
    assert!(engine.is_null());
}

#[test]
fn fingerprint_matches_core() {
    let id = Identity::from_secret_bytes(&[5u8; 32]);
    let mut out = [0 as c_char; 25];
    // SAFETY: 32 readable bytes, 25 writable.
    assert_eq!(
        unsafe { avl_fingerprint(id.public_key().0.as_ptr(), out.as_mut_ptr()) },
        AvlStatus::Ok
    );
    // SAFETY: NUL-terminated by the call.
    let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
    assert_eq!(s, format_fingerprint(&id.public_key().fingerprint()));
    let mut public = [0u8; 32];
    // SAFETY: sized buffers.
    unsafe { avl_identity_public_key([5u8; 32].as_ptr(), public.as_mut_ptr()) };
    assert_eq!(public, id.public_key().0);
}

// ---------------------------------------------------------------------
// Callback storage over a BTreeMap, as an app's database would be.

/// A pending write: a value to store, or `None` to remove.
type Op = (Vec<u8>, Option<Vec<u8>>);

#[derive(Default)]
struct Db {
    committed: BTreeMap<Vec<u8>, Vec<u8>>,
    batch: Option<Vec<Op>>,
    commits: usize,
    released: bool,
}

unsafe fn db<'a>(ctx: *mut c_void) -> &'a mut Db {
    // SAFETY: ctx is the `*mut Db` registered below, alive for the test.
    unsafe { &mut *ctx.cast::<Db>() }
}

unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        // SAFETY: the engine passes valid slices.
        unsafe { std::slice::from_raw_parts(p, len) }
    }
}

unsafe extern "C" fn cb_load(
    ctx: *mut c_void,
    key: *const u8,
    key_len: usize,
    value: *mut u8,
    cap: usize,
    len: *mut usize,
) -> c_int {
    // SAFETY: callback contract.
    unsafe {
        let Some(v) = db(ctx).committed.get(bytes(key, key_len)) else {
            return 1;
        };
        *len = v.len();
        if v.len() <= cap {
            std::ptr::copy_nonoverlapping(v.as_ptr(), value, v.len());
        }
    }
    0
}

unsafe extern "C" fn cb_scan(
    ctx: *mut c_void,
    prefix: *const u8,
    prefix_len: usize,
    visit: unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize),
    visit_ctx: *mut c_void,
) -> c_int {
    // SAFETY: callback contract.
    unsafe {
        let prefix = bytes(prefix, prefix_len);
        for (k, v) in db(ctx).committed.range(prefix.to_vec()..) {
            if !k.starts_with(prefix) {
                break;
            }
            visit(visit_ctx, k.as_ptr(), k.len(), v.as_ptr(), v.len());
        }
    }
    0
}

unsafe extern "C" fn cb_begin(ctx: *mut c_void) -> c_int {
    // SAFETY: callback contract.
    unsafe { db(ctx).batch = Some(Vec::new()) };
    0
}

unsafe extern "C" fn cb_store(
    ctx: *mut c_void,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
) -> c_int {
    // SAFETY: callback contract.
    unsafe {
        let (k, v) = (
            bytes(key, key_len).to_vec(),
            bytes(value, value_len).to_vec(),
        );
        match &mut db(ctx).batch {
            Some(b) => b.push((k, Some(v))),
            None => return -1,
        }
    }
    0
}

unsafe extern "C" fn cb_remove(ctx: *mut c_void, key: *const u8, key_len: usize) -> c_int {
    // SAFETY: callback contract.
    unsafe {
        let k = bytes(key, key_len).to_vec();
        match &mut db(ctx).batch {
            Some(b) => b.push((k, None)),
            None => return -1,
        }
    }
    0
}

unsafe extern "C" fn cb_commit(ctx: *mut c_void) -> c_int {
    // SAFETY: callback contract.
    let d = unsafe { db(ctx) };
    let Some(batch) = d.batch.take() else {
        return -1;
    };
    for (k, v) in batch {
        match v {
            Some(v) => d.committed.insert(k, v),
            None => d.committed.remove(&k),
        };
    }
    d.commits += 1;
    0
}

unsafe extern "C" fn cb_rollback(ctx: *mut c_void) {
    // SAFETY: callback contract.
    unsafe { db(ctx).batch = None };
}

unsafe extern "C" fn cb_release(ctx: *mut c_void) {
    // SAFETY: callback contract.
    unsafe { db(ctx).released = true };
}

fn callback_storage(d: &mut Db) -> *mut AvlStorage {
    let cb = AvlStorageCallbacks {
        ctx: (d as *mut Db).cast(),
        load: Some(cb_load),
        scan_prefix: Some(cb_scan),
        begin: Some(cb_begin),
        store: Some(cb_store),
        remove: Some(cb_remove),
        commit: Some(cb_commit),
        rollback: Some(cb_rollback),
        release: Some(cb_release),
    };
    let mut storage = null_mut();
    // SAFETY: readable struct, writable out.
    assert_eq!(
        unsafe { avl_storage_callbacks(&cb, &mut storage) },
        AvlStatus::Ok
    );
    storage
}

#[test]
fn callback_storage_survives_reopen() {
    let mut d = Db::default();
    let peer = memory_node();
    let secret = [9u8; 32];
    let conv;
    {
        let node = Node {
            engine: open(secret, callback_storage(&mut d)).unwrap(),
            public: [0; 32],
            secret,
        };
        conv = add_contact(&node, &peer.public);
        send(&node, &conv, "queued before a restart", 0);
    }
    assert!(d.released && d.commits > 0 && d.batch.is_none());

    d.released = false;
    let node = Node {
        engine: open(secret, callback_storage(&mut d)).unwrap(),
        public: [0; 32],
        secret,
    };
    // Same conversation, message still queued.
    assert_eq!(add_contact(&node, &peer.public), conv);
    // SAFETY: live engine.
    assert_eq!(unsafe { avl_engine_outbox_len(node.engine) }, 1);
    add_contact(&peer, &Identity::from_secret_bytes(&secret).public_key().0);
    let mut now = 0;
    for _ in 0..10 {
        deliver(&node, &peer, now);
        deliver(&peer, &node, now);
        now += 100;
    }
    let got = events(&peer);
    assert!(
        got.contains(&(
            AvlEventKind::MessageReceived,
            Some("queued before a restart".into())
        )),
        "{got:?}"
    );

    // The wrong identity is refused.
    drop(node);
    let mut engine = null_mut();
    // SAFETY: valid pointers; storage is consumed.
    let st = unsafe {
        avl_engine_open(
            [8u8; 32].as_ptr(),
            callback_storage(&mut d),
            null(),
            &mut engine,
        )
    };
    assert_eq!(st, AvlStatus::ErrEngine);
    assert_eq!(avl_last_engine_error(), AvlEngineError::IdentityMismatch);
    assert!(d.released, "storage released on failed open");
}

#[test]
fn incomplete_callbacks_are_rejected() {
    let cb = AvlStorageCallbacks {
        ctx: null_mut(),
        load: Some(cb_load),
        scan_prefix: None,
        begin: Some(cb_begin),
        store: Some(cb_store),
        remove: Some(cb_remove),
        commit: Some(cb_commit),
        rollback: Some(cb_rollback),
        release: None,
    };
    let mut storage = null_mut();
    // SAFETY: readable struct, writable out.
    assert_eq!(
        unsafe { avl_storage_callbacks(&cb, &mut storage) },
        AvlStatus::ErrInvalidArgument
    );
    assert!(storage.is_null());
}

#[test]
fn file_storage_survives_reopen() {
    let dir = std::env::temp_dir().join(format!("avianlink-ffi-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = std::ffi::CString::new(dir.to_str().unwrap()).unwrap();
    let peer = memory_node();
    let secret = [3u8; 32];
    let file_node = || {
        let mut storage = null_mut();
        // SAFETY: C string; writable out.
        assert_eq!(
            unsafe { avl_storage_file_open(path.as_ptr(), &mut storage) },
            AvlStatus::Ok
        );
        Node {
            engine: open(secret, storage).unwrap(),
            public: [0; 32],
            secret,
        }
    };
    let conv = {
        let node = file_node();
        let conv = add_contact(&node, &peer.public);
        send(&node, &conv, "durable", 0);
        conv
    };
    let node = file_node();
    assert_eq!(add_contact(&node, &peer.public), conv);
    // SAFETY: live engine.
    assert_eq!(unsafe { avl_engine_outbox_len(node.engine) }, 1);
    let mut t = 0;
    // SAFETY: live engine; writable out.
    assert!(unsafe { avl_engine_next_timeout(node.engine, &mut t) });
    drop(node);
    let _ = std::fs::remove_dir_all(&dir);
}
