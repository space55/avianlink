<!--
  The conversation sidebar (docs/design.md §2).
-->
<script lang="ts">
  import { relativeTime, truncate } from '../format';
  import type { ConversationSummary, Link } from '../ipc/client';
  import Brand from './Brand.svelte';
  import LinkHealth from './LinkHealth.svelte';

  interface Props {
    conversations: ConversationSummary[];
    links: Link[];
    selectedId: string | null;
    now: number;
    onSelect: (conversationId: string) => void;
    onAddContact: () => void;
    onSettings: () => void;
    onToggleLink: (id: number, enabled: boolean) => void;
    /** Current sidebar width, which decides which brand tier fits. */
    width: number;
  }

  let {
    conversations,
    links,
    selectedId,
    now,
    onSelect,
    onAddContact,
    onSettings,
    onToggleLink,
    width,
  }: Props = $props();

  /**
   * The compact lockup is 5.85 times as wide as it is tall, so at its
   * smallest sanctioned height (24px) it needs about 140px, plus its clear
   * space and the two action buttons. Below that the guidelines say to drop
   * the mark and use the wordmark alone rather than shrink the lockup.
   */
  const LOCKUP_MIN_SIDEBAR = 248;
  let showLockup = $derived(width >= LOCKUP_MIN_SIDEBAR);
</script>

<nav class="sidebar" aria-label="Conversations">
  <header>
    <h1>
      {#if showLockup}
        <Brand variant="lockup" size={24} />
      {:else}
        <Brand variant="wordmark" size={16} />
      {/if}
    </h1>
    <div class="actions">
      <button type="button" onclick={onAddContact} title="Add a contact (Ctrl+N)">
        <span aria-hidden="true">+</span>
        <span class="visually-hidden">Add a contact</span>
      </button>
      <button type="button" onclick={onSettings} title="Settings (Ctrl+,)">
        <span aria-hidden="true">⚙</span>
        <span class="visually-hidden">Settings</span>
      </button>
    </div>
  </header>

  <div class="list-wrap">
    {#if conversations.length === 0}
      <div class="empty">
        <p>No contacts yet.</p>
        <p class="hint">
          Add someone by their public key. You will need to get it from them over a channel you
          already trust.
        </p>
        <button type="button" class="primary" onclick={onAddContact}>Add a contact</button>
      </div>
    {:else}
      <ul>
        {#each conversations as conversation (conversation.conversation_id)}
          {@const contact = conversation.contact}
          {@const active = conversation.conversation_id === selectedId}
          <li>
            <button
              type="button"
              class="row"
              class:active
              aria-current={active ? 'true' : undefined}
              onclick={() => onSelect(conversation.conversation_id)}
            >
              <span class="top">
                <span class="who">{contact.display_name}</span>
                {#if conversation.last_message}
                  <span class="when">{relativeTime(conversation.last_message.at, now)}</span>
                {/if}
              </span>
              <span class="bottom">
                <span class="preview">
                  {#if conversation.last_message}
                    {conversation.last_message.outgoing ? 'You: ' : ''}{truncate(
                      conversation.last_message.text,
                      60,
                    )}
                  {:else}
                    <span class="faint">No messages yet</span>
                  {/if}
                </span>
                {#if conversation.unread_count > 0}
                  <span class="unread" aria-label={`${conversation.unread_count} unread`}>
                    {conversation.unread_count}
                  </span>
                {:else if conversation.undelivered_count > 0}
                  <span
                    class="pending"
                    aria-label={`${conversation.undelivered_count} not yet delivered`}
                    title={`${conversation.undelivered_count} message(s) not yet delivered`}
                  >
                    {conversation.undelivered_count}
                  </span>
                {/if}
              </span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </div>

  <LinkHealth {links} {now} onToggle={onToggleLink} />
</nav>

<style>
  .sidebar {
    display: flex;
    flex-direction: column;
    min-width: 0;
    height: 100%;
    background: var(--bg-sunken);
    border-right: 1px solid var(--border);
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-3) var(--space-2);
  }

  h1 {
    display: flex;
    min-width: 0;
    margin: 0;
    /* The brand files carry the name; the heading is here for structure and
       for anything reading the document outline. */
    font-size: 0;
    line-height: 0;
    color: var(--text);
  }

  .actions {
    display: flex;
    gap: var(--space-1);
  }

  .actions button {
    width: 24px;
    height: 24px;
    display: grid;
    place-items: center;
    background: none;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    cursor: pointer;
    font-size: var(--text-base);
    line-height: 1;
  }

  .actions button:hover {
    background: var(--bg-hover);
    color: var(--text);
  }

  .list-wrap {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0 var(--space-2);
  }

  .row {
    display: block;
    width: 100%;
    padding: var(--space-2);
    background: none;
    border: 0;
    border-radius: var(--radius-md);
    text-align: left;
    cursor: pointer;
  }

  .row:hover {
    background: var(--bg-hover);
  }

  .active {
    background: var(--accent-soft);
  }

  .active:hover {
    background: var(--accent-soft);
  }

  .top,
  .bottom {
    display: flex;
    align-items: baseline;
    gap: var(--space-2);
    min-width: 0;
  }

  .who {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: var(--text-sm);
    font-weight: 600;
  }

  .when {
    flex: none;
    color: var(--text-faint);
    font-size: var(--text-xs);
    font-variant-numeric: tabular-nums;
  }

  .preview {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-muted);
    font-size: var(--text-xs);
  }

  .faint {
    color: var(--text-faint);
  }

  .unread,
  .pending {
    flex: none;
    min-width: 17px;
    padding: 0 5px;
    border-radius: 999px;
    font-size: var(--text-xs);
    font-variant-numeric: tabular-nums;
    text-align: center;
  }

  .unread {
    background: var(--accent);
    color: var(--accent-text);
  }

  /* Undelivered is not a warning: it is the normal state of a message on
     these links, so it gets an outline rather than a fill. */
  .pending {
    border: 1px solid var(--border-strong);
    color: var(--text-faint);
  }

  .empty {
    padding: var(--space-4) var(--space-3);
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  .empty p {
    margin: 0 0 var(--space-2);
  }

  .hint {
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .primary {
    padding: var(--space-1) var(--space-3);
    background: var(--accent);
    color: var(--accent-text);
    border: 0;
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
    cursor: pointer;
  }
</style>
