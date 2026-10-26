<!--
  The thread header (docs/design.md §6, §7).

  Carries the two facts about the person that belong above their messages:
  how long since we heard from them, and whether their key has been checked.
  Both are stated neutrally — a day of silence is normal here.
-->
<script lang="ts">
  import { lastHeard } from '../format';
  import type { Contact } from '../ipc/client';
  import Fingerprint from './Fingerprint.svelte';

  interface Props {
    contact: Contact;
    now: number;
    narrow: boolean;
    onBack: () => void;
    onVerifiedChange: (verified: boolean) => void;
  }

  let { contact, now, narrow, onBack, onVerifiedChange }: Props = $props();
  let showDetail = $state(false);
</script>

<header class="header">
  {#if narrow}
    <button type="button" class="back" onclick={onBack}>
      <span aria-hidden="true">←</span>
      <span class="visually-hidden">Back to conversations</span>
    </button>
  {/if}

  <button
    type="button"
    class="who"
    aria-expanded={showDetail}
    onclick={() => (showDetail = !showDetail)}
  >
    <span class="name">{contact.display_name}</span>
    {#if !contact.verified}
      <span class="unverified" title="You have not compared this contact's fingerprint yet">
        unverified
      </span>
    {/if}
  </button>

  <span class="heard">{lastHeard(contact.last_packet_at, now)}</span>
</header>

{#if showDetail}
  <div class="detail">
    <p class="explain">
      Read these five groups aloud to each other over a channel you already trust — anyone who can
      change messages in transit can also swap the key.
    </p>
    <Fingerprint fingerprint={contact.fingerprint} />
    <label class="verify">
      <input
        type="checkbox"
        checked={contact.verified}
        onchange={(event) => onVerifiedChange(event.currentTarget.checked)}
      />
      I compared the fingerprint with {contact.display_name} directly
    </label>
  </div>
{/if}

<style>
  .header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-5);
    border-bottom: 1px solid var(--border);
    background: var(--bg);
  }

  .back {
    padding: 0 var(--space-1);
    background: none;
    border: 0;
    color: var(--text-muted);
    cursor: pointer;
    font-size: var(--text-lg);
  }

  .who {
    display: flex;
    align-items: baseline;
    gap: var(--space-2);
    min-width: 0;
    flex: 1;
    padding: 0;
    background: none;
    border: 0;
    text-align: left;
    cursor: pointer;
  }

  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-weight: 600;
  }

  /* A neutral marker, not a warning: arranging an out-of-band comparison on
     these links may legitimately take days. */
  .unverified {
    flex: none;
    padding: 0 var(--space-1);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .heard {
    flex: none;
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .detail {
    padding: var(--space-3) var(--space-5);
    border-bottom: 1px solid var(--border);
    background: var(--bg-sunken);
  }

  .explain {
    margin: 0 0 var(--space-2);
    max-width: 44rem;
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  .verify {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-top: var(--space-2);
    color: var(--text-muted);
    font-size: var(--text-sm);
    cursor: pointer;
  }
</style>
