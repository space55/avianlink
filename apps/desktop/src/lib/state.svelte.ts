/**
 * The app's client state.
 *
 * One object, owned by `App.svelte`, holding everything the interface shows.
 * The rules it enforces are the ones `docs/ipc.md` warns about:
 *
 * - **Commands are the source of truth; events are a cache.** Every piece of
 *   state here is reachable by re-running a command. Events exist so the app
 *   does not poll, and dropping one costs a refresh, not correctness.
 * - **Status is monotonic.** A `sent` can arrive after the `delivered` it
 *   precedes, so status is merged by taking the furthest-along value seen.
 * - **Messages are sorted by `order_key`, never by time.** A late message
 *   belongs where the causal order puts it.
 */

import {
  commands,
  isIpcError,
  type Contact,
  type ConversationSummary,
  type Identity,
  type IpcError,
  type Link,
  type Message,
  type MessageStatus,
  type Settings,
} from './ipc/client';

/** How often relative times ("3h ago") are recomputed. */
const CLOCK_TICK_MS = 30_000;

/** Messages fetched per page. */
export const PAGE_SIZE = 100;

/** Rank used to keep status monotonic; mirrors `MessageStatus::rank`. */
const STATUS_RANK: Record<MessageStatus, number> = {
  queued: 0,
  sent: 1,
  delivered: 2,
  failed: 3,
};

/** Returns the further-along of two statuses. */
export function furthestStatus(
  a: MessageStatus | null,
  b: MessageStatus | null,
): MessageStatus | null {
  if (a === null) return b;
  if (b === null) return a;
  return STATUS_RANK[b] > STATUS_RANK[a] ? b : a;
}

/**
 * Inserts or replaces a message, keeping the list sorted by `order_key`.
 *
 * Returns the index it landed at, which is what lets the thread tell whether
 * content appeared above the viewport and therefore whether it has to hold
 * the scroll position still.
 */
export function mergeMessage(messages: Message[], incoming: Message): number {
  const existing = messages.findIndex((m) => m.id === incoming.id);
  if (existing !== -1) {
    messages[existing] = {
      ...messages[existing],
      ...incoming,
      status: furthestStatus(messages[existing].status, incoming.status),
    };
    return existing;
  }
  let index = messages.length;
  for (let i = 0; i < messages.length; i += 1) {
    if (messages[i].order_key > incoming.order_key) {
      index = i;
      break;
    }
  }
  messages.splice(index, 0, incoming);
  return index;
}

/** A problem worth showing the user. */
export interface Problem {
  message: string;
  kind: IpcError['kind'];
}

export class AppState {
  identity = $state<Identity | null>(null);
  conversations = $state<ConversationSummary[]>([]);
  links = $state<Link[]>([]);
  settings = $state<Settings | null>(null);
  selectedId = $state<string | null>(null);
  messages = $state<Message[]>([]);
  hasMore = $state(false);
  loading = $state(true);
  problem = $state<Problem | null>(null);

  /** Ticks so relative times refresh without every component owning a timer. */
  now = $state(Date.now());

  /** Text for the single polite live region (`docs/design.md` §10). */
  announcement = $state('');

  /** Set when a message lands while the user is scrolled away from the end. */
  unseenBelow = $state(0);

  /** Bumped whenever a message is inserted above the user's position. */
  insertedAbove = $state(0);

  #timer: ReturnType<typeof setInterval> | undefined;

  /** The conversation currently open, if any. */
  get selected(): ConversationSummary | null {
    return this.conversations.find((c) => c.conversation_id === this.selectedId) ?? null;
  }

  /** Whether the app is running on the simulated engine. */
  get simulated(): boolean {
    return this.settings?.fake_engine != null;
  }

  /** Gap above which the thread shows the receive time as well. */
  get receiveTimeThresholdMs(): number {
    return this.settings?.show_receive_time_threshold_ms ?? 5 * 60 * 1000;
  }

  /** Starts the clock that keeps relative times fresh. */
  startClock() {
    this.#timer ??= setInterval(() => {
      this.now = Date.now();
    }, CLOCK_TICK_MS);
  }

  /** Stops it. */
  stopClock() {
    if (this.#timer !== undefined) clearInterval(this.#timer);
    this.#timer = undefined;
  }

  /** Runs `work`, turning any backend failure into something displayable. */
  async guard<T>(work: () => Promise<T>): Promise<T | undefined> {
    try {
      const result = await work();
      this.problem = null;
      return result;
    } catch (error) {
      this.problem = isIpcError(error)
        ? { message: error.message, kind: error.kind }
        : { message: String(error), kind: 'internal' };
      return undefined;
    }
  }

  /** Loads everything the window needs to open. */
  async load() {
    await this.guard(async () => {
      const [identity, conversations, links, settings] = await Promise.all([
        commands.getIdentity(),
        commands.listConversations(),
        commands.listLinks(),
        commands.getSettings(),
      ]);
      this.identity = identity;
      this.conversations = conversations;
      this.links = links;
      this.settings = settings;
      if (this.selectedId === null && conversations.length > 0) {
        await this.select(conversations[0].conversation_id);
      }
    });
    this.loading = false;
  }

  /** Re-reads the conversation list and links. Cheap; no message bodies. */
  async refreshSummaries() {
    await this.guard(async () => {
      const [conversations, links] = await Promise.all([
        commands.listConversations(),
        commands.listLinks(),
      ]);
      this.conversations = conversations;
      this.links = links;
    });
  }

  /** Opens a conversation and loads its most recent page. */
  async select(conversationId: string) {
    this.selectedId = conversationId;
    this.messages = [];
    this.hasMore = false;
    this.unseenBelow = 0;
    await this.guard(async () => {
      const page = await commands.getMessages({
        conversation_id: conversationId,
        before: null,
        limit: PAGE_SIZE,
      });
      // Guard against a slow response for a conversation the user has already
      // navigated away from.
      if (this.selectedId !== conversationId) return;
      this.messages = page.messages;
      this.hasMore = page.has_more;
    });
    await this.markRead();
  }

  /** Loads the page before the oldest message held. */
  async loadOlder() {
    const conversationId = this.selectedId;
    const oldest = this.messages[0]?.order_key;
    if (conversationId === null || oldest === undefined || !this.hasMore) return;
    await this.guard(async () => {
      const page = await commands.getMessages({
        conversation_id: conversationId,
        before: oldest,
        limit: PAGE_SIZE,
      });
      if (this.selectedId !== conversationId) return;
      this.messages = [...page.messages, ...this.messages];
      this.hasMore = page.has_more;
    });
  }

  /**
   * Queues a message.
   *
   * Returns immediately from the user's point of view: the composer is
   * cleared by the caller *before* this is awaited, because sending means
   * "queued" and queuing is a local write that cannot fail for a link reason.
   */
  async send(text: string) {
    const conversationId = this.selectedId;
    if (conversationId === null || text.trim() === '') return;
    const message = await this.guard(() =>
      commands.sendMessage({ conversation_id: conversationId, text }),
    );
    if (message && this.selectedId === conversationId) {
      mergeMessage(this.messages, message);
      this.messages = [...this.messages];
    }
    await this.refreshSummaries();
  }

  /** Marks the open conversation read up to the newest message held. */
  async markRead() {
    const conversationId = this.selectedId;
    const newest = this.messages.at(-1)?.order_key;
    if (conversationId === null || newest === undefined) return;
    await this.guard(async () => {
      await commands.markConversationRead({
        conversation_id: conversationId,
        through_order_key: newest,
      });
    });
    await this.refreshSummaries();
  }

  // -- event handlers ----------------------------------------------------

  /**
   * A message arrived.
   *
   * `atEnd` tells the state whether the user is looking at the bottom of the
   * thread, which decides between "scroll it into view" and "mention it
   * quietly" (`docs/design.md` §4).
   */
  onMessageReceived(message: Message, atEnd: boolean) {
    const sender =
      this.conversations.find((c) => c.conversation_id === message.conversation_id)?.contact
        .display_name ?? 'a contact';
    this.announcement = `Message from ${sender}`;
    void this.refreshSummaries();
    if (message.conversation_id !== this.selectedId) return;
    const index = mergeMessage(this.messages, message);
    this.messages = [...this.messages];
    if (index < this.messages.length - 1) {
      // It landed in the middle of history: the thread must hold the user's
      // scroll position rather than letting the content shove it.
      this.insertedAbove += 1;
    } else if (!atEnd) {
      this.unseenBelow += 1;
    }
  }

  /** An outgoing message advanced. */
  onStatusChanged(change: {
    conversation_id: string;
    message_id: string;
    status: MessageStatus;
    delivered_at: number | null;
    attempts: number;
  }) {
    if (change.conversation_id === this.selectedId) {
      const index = this.messages.findIndex((m) => m.id === change.message_id);
      if (index !== -1) {
        const current = this.messages[index];
        const status = furthestStatus(current.status, change.status);
        this.messages[index] = {
          ...current,
          status,
          delivered_at: change.delivered_at ?? current.delivered_at,
          attempts: change.attempts,
        };
        this.messages = [...this.messages];
      }
    }
    // Only the terminal transitions are worth interrupting a screen reader
    // for; `queued -> sent` and attempt counts are not (docs/design.md §3).
    if (change.status === 'delivered') this.announcement = 'Message delivered';
    if (change.status === 'failed') this.announcement = 'Message could not be sent';
    void this.refreshSummaries();
  }

  /** A link's state or health changed. */
  onLinkChanged(link: Link) {
    const index = this.links.findIndex((l) => l.id === link.id);
    if (index === -1) {
      this.links = [...this.links, link].sort((a, b) => a.id - b.id);
    } else {
      this.links[index] = link;
      this.links = [...this.links];
    }
  }

  /** A contact was added, renamed, verified or heard from. */
  onContactChanged(contact: Contact) {
    const index = this.conversations.findIndex(
      (c) => c.conversation_id === contact.conversation_id,
    );
    if (index === -1) {
      void this.refreshSummaries();
      return;
    }
    this.conversations[index] = { ...this.conversations[index], contact };
    this.conversations = [...this.conversations];
  }
}
