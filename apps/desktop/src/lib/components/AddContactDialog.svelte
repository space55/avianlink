<!--
  Adding a contact (docs/design.md §7).

  Two halves, because the operation is inherently two-sided: your key for them
  to add, and theirs for you. The one sentence explaining fingerprint
  comparison sits where the decision is being made, not in a help page.
-->
<script lang="ts">
  import type { Identity } from '../ipc/client';
  import CopyButton from './CopyButton.svelte';
  import Dialog from './Dialog.svelte';
  import Fingerprint from './Fingerprint.svelte';
  import QrCode from './QrCode.svelte';

  interface Props {
    open: boolean;
    identity: Identity | null;
    /** Whether the simulated engine is running, which offers an extra path. */
    simulated: boolean;
    onClose: () => void;
    onAdd: (publicKey: string, displayName: string, verified: boolean) => Promise<boolean>;
    onAddSimulated: (displayName: string) => Promise<boolean>;
  }

  let { open, identity, simulated, onClose, onAdd, onAddSimulated }: Props = $props();

  let key = $state('');
  let name = $state('');
  let verified = $state(false);
  let busy = $state(false);

  /** Whitespace and newlines come along with anything pasted. */
  let cleaned = $derived(key.replace(/\s+/g, '').toLowerCase());

  /**
   * Says what is wrong rather than just refusing. "That is 63 characters" is
   * actionable; a disabled button is not.
   */
  let problem = $derived.by(() => {
    if (cleaned === '') return null;
    if (!/^[0-9a-f]*$/.test(cleaned)) return 'A key is hexadecimal: digits and a–f only.';
    if (cleaned.length < 64) return `That is ${cleaned.length} characters; a key is 64.`;
    if (cleaned.length > 64) return `That is ${cleaned.length} characters; a key is 64.`;
    return null;
  });

  let valid = $derived(cleaned.length === 64 && problem === null);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!valid || busy) return;
    busy = true;
    const ok = await onAdd(cleaned, name.trim(), verified);
    busy = false;
    if (ok) reset();
  }

  async function addSimulated() {
    busy = true;
    const ok = await onAddSimulated(name.trim());
    busy = false;
    if (ok) reset();
  }

  function reset() {
    key = '';
    name = '';
    verified = false;
  }
</script>

<Dialog title="Add a contact" {open} {onClose}>
  <section class="mine">
    <h3>Your key</h3>
    {#if identity}
      <div class="mine-body">
        <QrCode value={identity.public_key} size={144} />
        <div class="mine-text">
          <Fingerprint fingerprint={identity.fingerprint} />
          <p class="key selectable">{identity.public_key}</p>
          <CopyButton value={identity.public_key} label="Copy key" />
        </div>
      </div>
    {:else}
      <p class="muted">No identity yet.</p>
    {/if}
  </section>

  <form onsubmit={submit}>
    <h3>Their key</h3>

    <label for="contact-key">Public key</label>
    <textarea
      id="contact-key"
      bind:value={key}
      rows="3"
      spellcheck="false"
      autocomplete="off"
      placeholder="64 hexadecimal characters"
      aria-describedby="contact-key-problem"></textarea>
    <p id="contact-key-problem" class="problem" role={problem ? 'alert' : undefined}>
      {problem ?? ''}
    </p>

    <label for="contact-name">Name</label>
    <input
      id="contact-name"
      bind:value={name}
      autocomplete="off"
      placeholder="What you want to call them"
    />

    <p class="explain">
      Read the five fingerprint groups aloud to each other over a channel you already trust — anyone
      who can change messages in transit can also swap the key.
    </p>

    <label class="check">
      <input type="checkbox" bind:checked={verified} />
      I compared the fingerprint with them directly
    </label>

    <div class="actions">
      {#if simulated}
        <button type="button" class="secondary" onclick={addSimulated} disabled={busy}>
          Add a simulated contact
        </button>
      {/if}
      <button type="submit" class="primary" disabled={!valid || busy}>Add contact</button>
    </div>
  </form>
</Dialog>

<style>
  h3 {
    margin: 0 0 var(--space-2);
    color: var(--text-muted);
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .mine {
    padding-bottom: var(--space-4);
    margin-bottom: var(--space-4);
    border-bottom: 1px solid var(--border);
  }

  .mine-body {
    display: flex;
    gap: var(--space-4);
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .mine-text {
    flex: 1;
    min-width: 12rem;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2);
  }

  .key {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    color: var(--text-muted);
    overflow-wrap: anywhere;
  }

  label {
    display: block;
    margin-bottom: var(--space-1);
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  textarea,
  input:not([type='checkbox']) {
    width: 100%;
    padding: var(--space-2);
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    font: inherit;
    -webkit-user-select: text;
    user-select: text;
  }

  textarea {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    resize: vertical;
  }

  .problem {
    min-height: 1.2em;
    margin: var(--space-1) 0 var(--space-3);
    color: var(--status-failed);
    font-size: var(--text-xs);
  }

  .explain {
    margin: var(--space-4) 0 var(--space-2);
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
    margin-top: var(--space-4);
  }

  .primary,
  .secondary {
    padding: var(--space-2) var(--space-4);
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  .primary {
    background: var(--accent);
    color: var(--accent-text);
    border: 1px solid transparent;
  }

  .primary:disabled {
    background: var(--bg-sunken);
    color: var(--text-faint);
    border-color: var(--border);
    cursor: default;
  }

  .secondary {
    background: var(--bg-raised);
    color: var(--text);
    border: 1px solid var(--border-strong);
  }

  .muted {
    color: var(--text-muted);
  }
</style>
