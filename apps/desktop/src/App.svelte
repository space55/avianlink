<!--
  Phase 0 shell.

  This is scaffolding, not the interface. Its only job is to prove the whole
  path works end to end — command in, backend, store, event, render — so that
  Phase 1 can be about `docs/design.md` and nothing else. It is replaced
  wholesale by the real layout.
-->
<script lang="ts">
  import { onMount } from 'svelte';

  import {
    commands,
    isIpcError,
    subscribe,
    type Contact,
    type ConversationSummary,
    type Identity,
    type Link,
    type Message,
  } from './lib/ipc/client';

  let identity = $state<Identity | null>(null);
  let conversations = $state<ConversationSummary[]>([]);
  let links = $state<Link[]>([]);
  let messages = $state<Message[]>([]);
  let selected = $state<string | null>(null);
  let draft = $state('');
  let problem = $state<string | null>(null);

  async function guard(work: () => Promise<void>) {
    try {
      await work();
      problem = null;
    } catch (error) {
      problem = isIpcError(error) ? error.message : String(error);
    }
  }

  async function refresh() {
    identity = await commands.getIdentity();
    conversations = await commands.listConversations();
    links = await commands.listLinks();
    if (selected === null && conversations.length > 0) {
      selected = conversations[0].conversation_id;
    }
    if (selected !== null) {
      const page = await commands.getMessages({
        conversation_id: selected,
        before: null,
        limit: 100,
      });
      messages = page.messages;
    }
  }

  async function send(event: SubmitEvent) {
    event.preventDefault();
    const text = draft;
    const conversation = selected;
    if (!conversation || text.trim() === '') return;
    // The composer clears immediately: sending means "queued", and from the
    // user's point of view it always succeeds.
    draft = '';
    await guard(async () => {
      await commands.sendMessage({ conversation_id: conversation, text });
      await refresh();
    });
  }

  function describe(contact: Contact) {
    return `${contact.display_name} · ${contact.fingerprint}`;
  }

  onMount(() => {
    void guard(refresh);
    return subscribe({
      messageReceived: () => void guard(refresh),
      messageStatusChanged: () => void guard(refresh),
      linkStatusChanged: () => void guard(refresh),
      contactChanged: () => void guard(refresh),
    });
  });
</script>

<main>
  <h1>avianlink</h1>

  {#if problem}
    <p class="problem" role="alert">{problem}</p>
  {/if}

  <section>
    <h2>Identity</h2>
    {#if identity}
      <p class="selectable mono">{identity.fingerprint}</p>
    {:else}
      <p class="muted">Not established yet.</p>
    {/if}
  </section>

  <section>
    <h2>Links</h2>
    {#if links.length === 0}
      <p class="muted">No links configured.</p>
    {:else}
      <ul>
        {#each links as link (link.id)}
          <li>{link.label} — {link.status} · {link.packets_sent} sent</li>
        {/each}
      </ul>
    {/if}
  </section>

  <section>
    <h2>Conversations</h2>
    {#if conversations.length === 0}
      <p class="muted">No contacts yet. Phase 1 adds the interface for exchanging keys.</p>
    {:else}
      <ul>
        {#each conversations as conversation (conversation.conversation_id)}
          <li>
            <button
              type="button"
              aria-current={selected === conversation.conversation_id}
              onclick={() => {
                selected = conversation.conversation_id;
                void guard(refresh);
              }}
            >
              {describe(conversation.contact)}
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  {#if selected}
    <section>
      <h2>Thread</h2>
      <ol>
        {#each messages as message (message.id)}
          <li class="selectable">
            <span class="muted">{message.outgoing ? 'out' : 'in'}</span>
            {message.text}
            {#if message.status}<span class="muted">({message.status})</span>{/if}
          </li>
        {/each}
      </ol>
      <form onsubmit={send}>
        <label class="visually-hidden" for="draft">Message</label>
        <input id="draft" bind:value={draft} autocomplete="off" />
        <button type="submit">Send</button>
      </form>
    </section>
  {/if}
</main>

<style>
  main {
    max-width: 44rem;
    margin: 0 auto;
    padding: var(--space-6) var(--space-5);
  }

  section {
    margin-block: var(--space-5);
  }

  h2 {
    color: var(--text-muted);
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: var(--space-2);
  }

  ul,
  ol {
    margin: 0;
    padding-left: var(--space-4);
  }

  .muted {
    color: var(--text-muted);
  }

  .mono {
    font-family: var(--font-mono);
  }

  .problem {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--status-failed);
    border-radius: var(--radius-md);
    color: var(--status-failed);
  }
</style>
