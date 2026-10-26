<!--
  Settings (docs/design.md §8). Three sections, one page, no tabs.

  "Reset local data" is last, under a rule, in the quietest styling the app
  has, and requires typing a word — it is the one action with no undo, and a
  second button is too easy to press twice.
-->
<script lang="ts">
  import type { FakeEngineSettings, Identity, Link, Settings } from '../ipc/client';
  import CopyButton from './CopyButton.svelte';
  import Dialog from './Dialog.svelte';
  import Fingerprint from './Fingerprint.svelte';
  import QrCode from './QrCode.svelte';

  interface Props {
    open: boolean;
    identity: Identity | null;
    settings: Settings | null;
    links: Link[];
    onClose: () => void;
    onSave: (settings: Settings) => void;
    onReset: () => void;
  }

  let { open, identity, settings, links, onClose, onSave, onReset }: Props = $props();

  let displayName = $state('');
  let thresholdMinutes = $state(5);
  let fake = $state<FakeEngineSettings | null>(null);
  let confirmText = $state('');
  let confirming = $state(false);

  // Re-read when the dialog opens, so an edit abandoned last time does not
  // reappear as if it had been saved.
  $effect(() => {
    if (!open || !settings) return;
    displayName = settings.display_name ?? '';
    thresholdMinutes = Math.round(settings.show_receive_time_threshold_ms / 60_000);
    fake = settings.fake_engine ? { ...settings.fake_engine } : null;
    confirmText = '';
    confirming = false;
  });

  function save() {
    if (!settings) return;
    onSave({
      display_name: displayName.trim() === '' ? null : displayName.trim(),
      show_receive_time_threshold_ms: Math.max(0, Math.round(thresholdMinutes * 60_000)),
      fake_engine: fake,
    });
  }
</script>

<Dialog title="Settings" {open} {onClose}>
  <section>
    <h3>Identity</h3>
    {#if identity}
      <div class="identity">
        <QrCode value={identity.public_key} size={120} />
        <div class="identity-text">
          <Fingerprint fingerprint={identity.fingerprint} size="large" />
          <p class="key selectable">{identity.public_key}</p>
          <CopyButton value={identity.public_key} label="Copy public key" />
        </div>
      </div>
    {/if}

    <label for="display-name">Your name</label>
    <input id="display-name" bind:value={displayName} autocomplete="off" />
    <p class="hint">Only you see this. It is never sent.</p>
  </section>

  <section>
    <h3>Times</h3>
    <label for="threshold">Show arrival time when it is this far after the send time</label>
    <div class="row">
      <input id="threshold" type="number" min="0" max="1440" bind:value={thresholdMinutes} />
      <span class="unit">minutes</span>
    </div>
    <p class="hint">
      The right value depends entirely on the link. On a slow one, a five-minute gap is not worth
      mentioning; on a fast one it is.
    </p>
  </section>

  <section>
    <h3>Links</h3>
    <ul class="link-list">
      {#each links as link (link.id)}
        <li>
          <span class="link-name">{link.label}</span>
          <span class="link-state">{link.status} · MTU {link.mtu}</span>
        </li>
      {/each}
    </ul>
    {#if fake}
      <label for="profile">Simulated link profile</label>
      <select id="profile" bind:value={fake.profile}>
        {#each fake.available_profiles as profile (profile)}
          <option value={profile}>{profile.replace(/_/g, ' ')}</option>
        {/each}
      </select>
      <p class="hint">
        Sets the MTU, airtime budget, delay, bursty loss, corruption, duplication, reordering and
        outage schedule. The parameters are the simulator's.
      </p>

      <label class="check">
        <input type="checkbox" bind:checked={fake.scripted_replies} />
        Simulated contacts reply
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={fake.outages} />
        Run the profile's link outages
      </label>

      <label for="reply-delay">Reply delay</label>
      <div class="row">
        <input
          id="reply-delay"
          type="number"
          min="0"
          value={Math.round(fake.reply_delay_ms / 1000)}
          oninput={(event) => {
            if (fake) fake.reply_delay_ms = Number(event.currentTarget.value) * 1000;
          }}
        />
        <span class="unit">seconds, plus up to</span>
        <input
          type="number"
          min="0"
          aria-label="Reply delay jitter in seconds"
          value={Math.round(fake.reply_jitter_ms / 1000)}
          oninput={(event) => {
            if (fake) fake.reply_jitter_ms = Number(event.currentTarget.value) * 1000;
          }}
        />
        <span class="unit">more</span>
      </div>
    {/if}
  </section>

  <div class="save">
    <button type="button" class="primary" onclick={save}>Save</button>
  </div>

  <section class="danger">
    <h3>Reset local data</h3>
    <p class="hint">
      Deletes every message, contact and setting on this device, and your identity key — your
      contacts will no longer recognise you.
    </p>
    {#if confirming}
      <label for="confirm">Type <code>reset</code> to confirm</label>
      <div class="row">
        <input id="confirm" bind:value={confirmText} autocomplete="off" />
        <button
          type="button"
          class="destructive"
          disabled={confirmText.trim().toLowerCase() !== 'reset'}
          onclick={onReset}
        >
          Delete everything
        </button>
        <button type="button" class="quiet" onclick={() => (confirming = false)}>Cancel</button>
      </div>
    {:else}
      <button type="button" class="quiet" onclick={() => (confirming = true)}>
        Reset local data…
      </button>
    {/if}
  </section>
</Dialog>

<style>
  section + section {
    margin-top: var(--space-5);
  }

  h3 {
    margin: 0 0 var(--space-2);
    color: var(--text-muted);
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .identity {
    display: flex;
    gap: var(--space-4);
    align-items: flex-start;
    flex-wrap: wrap;
    margin-bottom: var(--space-4);
  }

  .identity-text {
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
    margin: var(--space-3) 0 var(--space-1);
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
  }

  input,
  select {
    padding: var(--space-1) var(--space-2);
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    font: inherit;
    -webkit-user-select: text;
    user-select: text;
  }

  input[type='checkbox'] {
    padding: 0;
  }

  input[type='number'] {
    width: 5rem;
  }

  #display-name,
  #confirm {
    width: 100%;
    max-width: 18rem;
  }

  .row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .unit,
  .hint {
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .hint {
    margin: var(--space-1) 0 0;
    max-width: 34rem;
  }

  .link-list {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .link-list li {
    display: flex;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-1) 0;
    font-size: var(--text-sm);
  }

  .link-state {
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .save {
    display: flex;
    justify-content: flex-end;
    margin-top: var(--space-4);
  }

  .primary {
    padding: var(--space-2) var(--space-4);
    background: var(--accent);
    color: var(--accent-text);
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  /* The quietest styling in the app, deliberately. */
  .danger {
    margin-top: var(--space-6);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
  }

  .quiet,
  .destructive {
    padding: var(--space-1) var(--space-3);
    background: none;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  .destructive {
    color: var(--status-failed);
    border-color: var(--status-failed);
  }

  .destructive:disabled {
    color: var(--text-faint);
    border-color: var(--border);
    cursor: default;
  }

  code {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
  }
</style>
