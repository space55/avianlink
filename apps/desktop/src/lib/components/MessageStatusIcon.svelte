<!--
  The four honest states of an outgoing message (docs/design.md §3).

  Each differs in *shape*, not only in tone, so the set reads correctly in
  greyscale and for colour-blind users. Colour is a second, redundant channel.
  The glyphs are hidden from assistive technology and the state reaches a
  screen reader through the message's own accessible name instead, so it is
  not read out twice.
-->
<script lang="ts">
  import type { MessageStatus } from '../ipc/client';

  interface Props {
    status: MessageStatus;
    /** Full explanation, shown on hover and used as the accessible name. */
    detail: string;
  }

  let { status, detail }: Props = $props();
</script>

<span class="icon {status}" title={detail} aria-hidden="true">
  <svg viewBox="0 0 16 12" width="16" height="12" focusable="false">
    {#if status === 'queued'}
      <!-- An open circle: nothing has happened yet, and that is fine. -->
      <circle cx="8" cy="6" r="4" fill="none" stroke="currentColor" stroke-width="1.4" />
    {:else if status === 'sent'}
      <path
        d="M3 6.6 L6 9.6 L12.5 2.6"
        fill="none"
        stroke="currentColor"
        stroke-width="1.6"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
    {:else if status === 'delivered'}
      <path
        d="M1 6.6 L3.9 9.6 L9.6 2.6"
        fill="none"
        stroke="currentColor"
        stroke-width="1.6"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
      <path
        d="M6.4 9.6 L12.1 2.6"
        fill="none"
        stroke="currentColor"
        stroke-width="1.6"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
    {:else}
      <circle cx="8" cy="6" r="4.2" fill="none" stroke="currentColor" stroke-width="1.4" />
      <path
        d="M5.4 8.6 L10.6 3.4"
        fill="none"
        stroke="currentColor"
        stroke-width="1.4"
        stroke-linecap="round"
      />
    {/if}
  </svg>
</span>

<style>
  .icon {
    display: inline-flex;
    align-items: center;
    flex: none;
    /* Reserve the same width for every state so the column does not shift
       when a message moves from queued to delivered. */
    width: 16px;
    height: 12px;
  }

  .queued {
    color: var(--status-queued);
  }

  .sent {
    color: var(--status-sent);
  }

  .delivered {
    color: var(--status-delivered);
  }

  .failed {
    color: var(--status-failed);
  }
</style>
