<!--
  The message thread (docs/design.md §4).

  The hard part is not rendering the list; it is that **the user's reading
  position must not move when content is inserted above it**. On these links a
  message written an hour ago can land in the middle of history at any moment,
  and a thread that jumped every time would be unusable.

  The anchor is taken from the bottom: record `scrollHeight - scrollTop`
  before the DOM changes and restore `scrollTop = scrollHeight - recorded`
  after. CSS `overflow-anchor` is not relied on — it behaves inconsistently
  across the WebViews this app ships on, and this is too important to leave to
  a hint.
-->
<script lang="ts">
  import { tick } from 'svelte';

  import { daySeparator, isSameDay } from '../format';
  import type { Message } from '../ipc/client';
  import MessageRow from './MessageRow.svelte';

  interface Props {
    messages: Message[];
    senderName: string;
    receiveThresholdMs: number;
    now: number;
    hasMore: boolean;
    /** Bumped by the state when a message landed above the viewport. */
    insertedAbove: number;
    /** Messages that arrived at the end while the user was scrolled away. */
    unseenBelow: number;
    onLoadOlder: () => void;
    onAtEndChange: (atEnd: boolean) => void;
  }

  let {
    messages,
    senderName,
    receiveThresholdMs,
    now,
    hasMore,
    insertedAbove,
    unseenBelow,
    onLoadOlder,
    onAtEndChange,
  }: Props = $props();

  /** Distance from the bottom, in pixels, still counted as "at the end". */
  const AT_END_SLACK = 48;

  /** Distance from the top at which the previous page is fetched. */
  const LOAD_OLDER_MARGIN = 200;

  let viewport = $state<HTMLElement | null>(null);
  let atEnd = $state(true);

  /**
   * Distance from the bottom, maintained on every scroll.
   *
   * It is kept continuously rather than captured just before a change,
   * because an effect runs *after* the DOM has already updated and so cannot
   * capture a pre-change value. Prepending content leaves this quantity
   * unchanged, which is exactly what makes it the right thing to restore.
   *
   * Plain variables, not `$state`: an effect that read these reactively would
   * re-run when the user scrolls and restore a stale position — which
   * manifests as the thread snapping back to the bottom the moment you try
   * to scroll up.
   */
  let anchor = 0;
  let atEndPlain = true;

  function captureAnchor() {
    if (!viewport) return;
    anchor = viewport.scrollHeight - viewport.scrollTop;
  }

  async function restoreAnchor() {
    await tick();
    if (!viewport) return;
    viewport.scrollTop = viewport.scrollHeight - anchor;
  }

  export function scrollToEnd(behavior: ScrollBehavior = 'auto') {
    if (!viewport) return;
    viewport.scrollTo({ top: viewport.scrollHeight, behavior });
    atEndPlain = true;
    anchor = viewport.clientHeight;
  }

  function onScroll() {
    if (!viewport) return;
    captureAnchor();
    const distance = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight;
    const next = distance <= AT_END_SLACK;
    atEndPlain = next;
    if (next !== atEnd) {
      atEnd = next;
      onAtEndChange(next);
    }
    if (hasMore && viewport.scrollTop < LOAD_OLDER_MARGIN) {
      onLoadOlder();
    }
  }

  /**
   * Content changed. If the user is reading history rather than sitting at
   * the end, hold their position to the pixel — whether the change was a late
   * message inserting mid-thread or an older page being prepended.
   *
   * The caller scrolls deliberately in the two cases where movement is
   * wanted: a message arriving at the end while the user is already there,
   * and the user's own message.
   */
  $effect(() => {
    void messages.length;
    void insertedAbove;
    if (!atEndPlain) void restoreAnchor();
  });

  /** Groups messages under day separators, using the send time. */
  let rows = $derived.by(() => {
    const out: ({ kind: 'day'; label: string } | { kind: 'message'; message: Message })[] = [];
    let previous: number | null = null;
    for (const message of messages) {
      const at = message.sent_at ?? message.received_at;
      if (at !== null && (previous === null || !isSameDay(previous, at))) {
        out.push({ kind: 'day', label: daySeparator(at, now) });
        previous = at;
      }
      out.push({ kind: 'message', message });
    }
    return out;
  });
</script>

<div class="thread" bind:this={viewport} onscroll={onScroll}>
  {#if hasMore}
    <p class="more">Loading earlier messages…</p>
  {/if}

  {#if messages.length === 0}
    <div class="empty">
      <p>No messages yet.</p>
      <p class="hint">
        Anything you send is saved here and goes out when a link can carry it. That may be in a
        second or in a day.
      </p>
    </div>
  {:else}
    <ol class="list">
      {#each rows as row, index (row.kind === 'day' ? `day-${index}` : row.message.id)}
        {#if row.kind === 'day'}
          <li class="day" role="separator">{row.label}</li>
        {:else}
          <MessageRow message={row.message} {senderName} {receiveThresholdMs} />
        {/if}
      {/each}
    </ol>
  {/if}
</div>

{#if unseenBelow > 0}
  <div class="jump">
    <button type="button" onclick={() => scrollToEnd('smooth')}>
      {unseenBelow}
      {unseenBelow === 1 ? 'new message' : 'new messages'} ↓
    </button>
  </div>
{/if}

<style>
  .thread {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: var(--space-4) var(--space-5);
    /* The browser's own scroll anchoring fights the manual one above. */
    overflow-anchor: none;
  }

  .list {
    list-style: none;
    /* Bottom-anchored: a short conversation sits against the composer rather
       than floating at the top of an empty column. */
    margin: auto 0 0;
    padding: 0;
  }

  .day {
    margin: var(--space-5) 0 var(--space-3);
    color: var(--text-faint);
    font-size: var(--text-xs);
    text-align: center;
    letter-spacing: 0.03em;
  }

  .day:first-child {
    margin-top: 0;
  }

  .more {
    margin: 0 0 var(--space-3);
    color: var(--text-faint);
    font-size: var(--text-xs);
    text-align: center;
  }

  .empty {
    max-width: 28rem;
    /* Centred, unlike the message list, because there is nothing for it to
       be anchored to. */
    margin: auto;
    color: var(--text-muted);
    text-align: center;
  }

  .empty p {
    margin: 0 0 var(--space-2);
  }

  .hint {
    color: var(--text-faint);
    font-size: var(--text-sm);
  }

  .jump {
    display: flex;
    justify-content: center;
    padding: 0 var(--space-5);
    margin-top: calc(-1 * var(--space-2));
  }

  .jump button {
    padding: var(--space-1) var(--space-3);
    background: var(--bg-raised);
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    box-shadow: var(--shadow-sm);
    font-size: var(--text-xs);
    cursor: pointer;
  }

  .jump button:hover {
    background: var(--bg-hover);
  }
</style>
