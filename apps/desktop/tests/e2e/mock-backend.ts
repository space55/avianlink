/**
 * A fake Tauri backend, installed into the page before the app loads.
 *
 * Playwright drives the real frontend against this, so the suite exercises
 * the actual components, the actual IPC client and the actual rendering — and
 * nothing of the Rust side. That split is deliberate: the backend has its own
 * Rust tests, and an end-to-end suite that needed a compiled binary and a
 * webview would be too slow and too flaky to run on every change.
 *
 * It is a script string rather than an imported module because it has to run
 * inside the page, before any of the app's code, via `addInitScript`.
 *
 * The shape it emulates is Tauri 2's `window.__TAURI_INTERNALS__`:
 * `@tauri-apps/api` routes both commands and event subscriptions through
 * `invoke`, so implementing `invoke` and `transformCallback` covers the whole
 * surface the app uses.
 */

/** A conversation the mock backend knows about, keyed by conversation id. */
export interface MockSeed {
  /** Pre-existing conversations. */
  conversations?: unknown[];
  /** Messages per conversation id. */
  messages?: Record<string, unknown[]>;
  /** Links to report. */
  links?: unknown[];
  /** Commands that should reject, mapped to the error to throw. */
  failures?: Record<string, { kind: string; message: string }>;
}

export const FINGERPRINT = 'd033-9b2b-d44b-ab05-ec86';
export const CONVERSATION = 'c'.repeat(32);

/** A conversation summary shaped like the Rust `ConversationSummary`. */
export function mockConversation(overrides: Record<string, unknown> = {}) {
  return {
    conversation_id: CONVERSATION,
    contact: {
      conversation_id: CONVERSATION,
      public_key: 'a'.repeat(64),
      fingerprint: FINGERPRINT,
      display_name: 'Rook',
      verified: false,
      added_at: 1_700_000_000_000,
      last_packet_at: null,
      last_message_at: null,
      unread_count: 0,
    },
    last_message: null,
    unread_count: 0,
    undelivered_count: 0,
    ...overrides,
  };
}

/** A message shaped like the Rust `Message`. */
export function mockMessage(overrides: Record<string, unknown> = {}) {
  const lamport = (overrides.lamport as number | undefined) ?? 1;
  const id = (overrides.id as string | undefined) ?? '1'.repeat(32);
  return {
    id,
    conversation_id: CONVERSATION,
    outgoing: false,
    text: 'hello',
    lamport,
    seq: 0,
    order_key: `${lamport.toString(16).padStart(16, '0')}:${id}`,
    sent_at: 1_700_000_000_000,
    received_at: 1_700_000_001_000,
    status: null,
    delivered_at: null,
    attempts: null,
    arrived_late: false,
    ...overrides,
  };
}

/** The init script source. `SEED` is substituted before injection. */
const SCRIPT = `
(() => {
  const seed = __SEED__;
  const callbacks = new Map();
  const listeners = new Map();
  let nextCallback = 1;
  let nextListener = 1;

  const state = {
    identity: {
      public_key: 'b'.repeat(64),
      fingerprint: ${JSON.stringify(FINGERPRINT)},
      display_name: null,
    },
    conversations: seed.conversations ?? [],
    messages: seed.messages ?? {},
    links: seed.links ?? [],
    settings: {
      display_name: null,
      show_receive_time_threshold_ms: 300000,
      fake_engine: null,
    },
  };

  /** Everything the page asked the backend to do, for assertions. */
  window.__calls = [];

  function page(conversationId) {
    const messages = state.messages[conversationId] ?? [];
    return {
      messages,
      has_more: false,
      oldest_order_key: messages.length ? messages[0].order_key : null,
      total: messages.length,
    };
  }

  function handle(cmd, args) {
    switch (cmd) {
      case 'get_identity':
        return state.identity;
      case 'list_contacts':
        return state.conversations.map((c) => c.contact);
      case 'list_conversations':
        return state.conversations;
      case 'list_links':
        return state.links;
      case 'get_settings':
        return state.settings;
      case 'set_settings':
        state.settings = args.settings;
        return state.settings;
      case 'get_messages':
        return page(args.conversation_id);
      case 'send_message': {
        const existing = state.messages[args.conversation_id] ?? [];
        const lamport = existing.length + 1;
        const id = String(lamport).padStart(32, '0');
        const message = {
          id,
          conversation_id: args.conversation_id,
          outgoing: true,
          text: args.text,
          lamport,
          seq: existing.length,
          order_key: lamport.toString(16).padStart(16, '0') + ':' + id,
          sent_at: Date.now(),
          received_at: null,
          status: 'queued',
          delivered_at: null,
          attempts: 0,
          arrived_late: false,
        };
        state.messages[args.conversation_id] = [...existing, message];
        return message;
      }
      case 'add_contact': {
        const conversation = {
          conversation_id: args.public_key.slice(0, 32),
          contact: {
            conversation_id: args.public_key.slice(0, 32),
            public_key: args.public_key,
            fingerprint: ${JSON.stringify(FINGERPRINT)},
            display_name: args.display_name || 'unnamed',
            verified: args.verified,
            added_at: Date.now(),
            last_packet_at: null,
            last_message_at: null,
            unread_count: 0,
          },
          last_message: null,
          unread_count: 0,
          undelivered_count: 0,
        };
        state.conversations = [...state.conversations, conversation];
        return conversation.contact;
      }
      case 'set_link_enabled': {
        state.links = state.links.map((l) =>
          l.id === args.id
            ? { ...l, enabled: args.enabled, status: args.enabled ? 'up' : 'disabled' }
            : l,
        );
        return state.links.find((l) => l.id === args.id);
      }
      case 'configure_link':
        return state.links.find((l) => l.id === args.id);
      case 'mark_conversation_read':
      case 'set_contact_verified':
      case 'reset_local_data':
        return null;
      default:
        throw { kind: 'internal', message: 'unmocked command: ' + cmd };
    }
  }

  window.__TAURI_INTERNALS__ = {
    transformCallback(callback) {
      const id = nextCallback++;
      callbacks.set(id, callback);
      return id;
    },
    invoke(cmd, payload) {
      const args = payload && payload.args ? payload.args : payload;
      if (cmd === 'plugin:event|listen') {
        const id = nextListener++;
        listeners.set(id, { event: args.event, handler: args.handler });
        return Promise.resolve(id);
      }
      if (cmd === 'plugin:event|unlisten') {
        listeners.delete(args.eventId);
        return Promise.resolve();
      }
      window.__calls.push({ cmd, args });
      const failure = (seed.failures ?? {})[cmd];
      if (failure) return Promise.reject(failure);
      try {
        return Promise.resolve(handle(cmd, args ?? {}));
      } catch (error) {
        return Promise.reject(error);
      }
    },
  };

  /** Pushes a backend event into the page, as the real backend would. */
  window.__emit = (event, payload) => {
    for (const { event: name, handler } of listeners.values()) {
      if (name !== event) continue;
      const callback = callbacks.get(handler);
      if (callback) callback({ event, id: handler, payload });
    }
  };

  /** Replaces what the mock backend will answer with next. */
  window.__setState = (patch) => Object.assign(state, patch);
})();
`;

/** Builds the init script for a given seed. */
export function mockBackendScript(seed: MockSeed = {}): string {
  return SCRIPT.replace('__SEED__', JSON.stringify(seed));
}
