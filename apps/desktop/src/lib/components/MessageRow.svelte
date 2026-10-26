<!--
  One message (docs/design.md §3, §4, §5).

  Three things here are not obvious:

  - The accessible name carries everything the visual design encodes
    positionally — who sent it, when, whether it was late, what state it is
    in — because none of that survives being read out of context.
  - Both times are shown only when they differ by more than the configured
    threshold. Showing "14:09 · arrived 14:09" would be noise.
  - `missing_before` renders above the message, not on it: it is a statement
    about a hole in the history, not about this message.
-->
<script lang="ts">
  import { clockTime, duration, fullTime } from '../format';
  import type { Message } from '../ipc/client';
  import MessageStatusIcon from './MessageStatusIcon.svelte';

  interface Props {
    message: Message;
    senderName: string;
    /** Gap above which the receive time is shown as well. */
    receiveThresholdMs: number;
  }

  let { message, senderName, receiveThresholdMs }: Props = $props();

  /** The time shown by default: when the sender says they wrote it. */
  let primaryAt = $derived(message.sent_at ?? message.received_at);

  /**
   * Whether to show the arrival time too.
   *
   * Only for incoming messages: our own have no arrival time, and their
   * `sent_at` is the moment we queued them.
   */
  let showArrival = $derived(
    !message.outgoing &&
      message.received_at !== null &&
      (message.sent_at === null || message.received_at - message.sent_at >= receiveThresholdMs),
  );

  /** The sender has no wall clock, so the only time we have is arrival. */
  let senderHasNoClock = $derived(!message.outgoing && message.sent_at === null);

  let statusDetail = $derived.by(() => {
    if (!message.status) return '';
    const attempts = message.attempts ?? 0;
    const tries = attempts === 1 ? '1 attempt' : `${attempts} attempts`;
    switch (message.status) {
      case 'queued':
        return 'Queued — saved on this device, waiting for a link';
      case 'sent':
        return `Sent — left this device, ${tries}`;
      case 'delivered': {
        const took =
          message.delivered_at !== null && message.sent_at !== null
            ? `, ${duration(message.delivered_at - message.sent_at)} to deliver`
            : '';
        return `Delivered — acknowledged by ${senderName}${took}`;
      }
      case 'failed':
        return 'Not sent — the engine gave up on this message';
    }
  });

  /** Everything the layout encodes, as a sentence. */
  let accessibleName = $derived.by(() => {
    const who = message.outgoing ? 'You' : senderName;
    const parts = [who];
    if (primaryAt !== null) parts.push(clockTime(primaryAt));
    if (senderHasNoClock) parts.push('sender has no clock');
    if (showArrival && message.received_at !== null) {
      parts.push(`arrived ${clockTime(message.received_at)}`);
    }
    if (message.arrived_late) parts.push('arrived out of order');
    if (statusDetail) parts.push(statusDetail);
    return parts.join(', ');
  });

  let hoverDetail = $derived.by(() => {
    const lines: string[] = [];
    if (message.sent_at !== null) {
      lines.push(`${message.outgoing ? 'Queued' : 'Sent'} ${fullTime(message.sent_at)}`);
    }
    if (message.received_at !== null) lines.push(`Arrived ${fullTime(message.received_at)}`);
    if (statusDetail) lines.push(statusDetail);
    return lines.join('\n');
  });
</script>

{#if message.missing_before > 0}
  <li class="gap" aria-label="{message.missing_before} earlier messages have not arrived yet">
    <span>
      {message.missing_before}
      {message.missing_before === 1 ? 'earlier message is' : 'earlier messages are'} still on their way
    </span>
  </li>
{/if}

<li class="row" class:outgoing={message.outgoing} aria-label={accessibleName}>
  <div class="bubble" title={hoverDetail}>
    <p class="text selectable">{message.text}</p>
    <div class="meta">
      {#if primaryAt !== null}
        <time datetime={new Date(primaryAt).toISOString()}>
          {senderHasNoClock ? `arrived ${clockTime(primaryAt)}` : clockTime(primaryAt)}
        </time>
      {/if}
      {#if showArrival && !senderHasNoClock && message.received_at !== null}
        <time class="arrival" datetime={new Date(message.received_at).toISOString()}>
          · arrived {clockTime(message.received_at)}
        </time>
      {/if}
      {#if message.status}
        <MessageStatusIcon status={message.status} detail={statusDetail} />
      {/if}
    </div>
    {#if message.arrived_late}
      <p class="late">arrived out of order</p>
    {/if}
  </div>
</li>

<style>
  .row {
    display: flex;
    padding-block: var(--space-1);
  }

  .outgoing {
    justify-content: flex-end;
  }

  .bubble {
    /* Not a bubble: no fill, no border. Alignment already encodes direction,
       and a box around every message would encode it twice while costing the
       horizontal space long text and the markers need. */
    max-width: min(42rem, 78%);
    min-width: 0;
  }

  .text {
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .outgoing .text {
    text-align: right;
  }

  .meta {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    margin-top: 1px;
    color: var(--text-faint);
    font-size: var(--text-xs);
    font-variant-numeric: tabular-nums;
  }

  .outgoing .meta {
    justify-content: flex-end;
  }

  .arrival {
    color: var(--text-faint);
  }

  .late {
    margin: 1px 0 0;
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .late::before {
    content: '╰ ';
  }

  .outgoing .late {
    text-align: right;
  }

  .gap {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-block: var(--space-3);
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .gap::before,
  .gap::after {
    content: '';
    flex: 1;
    border-top: 1px dashed var(--border);
  }
</style>
