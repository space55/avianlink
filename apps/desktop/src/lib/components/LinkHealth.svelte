<!--
  Link health (docs/design.md §6).

  The tone is the design problem: this panel spends most of its life reporting
  things that would read as catastrophic in any other app, and it must not do
  that. No animation, no colour change to attract attention, and a vocabulary
  that never says "disconnected", "error" or "failed". A link going down is a
  text change.
-->
<script lang="ts">
  import { clockTime, lossLabel, relativeTime } from '../format';
  import type { Link } from '../ipc/client';

  interface Props {
    links: Link[];
    now: number;
    onToggle: (id: number, enabled: boolean) => void;
  }

  let { links, now, onToggle }: Props = $props();
  let expanded = $state<number | null>(null);

  function stateWord(link: Link): string {
    if (link.status === 'disabled') return 'off';
    if (link.status === 'down') return 'unavailable';
    return 'up';
  }

  /** The short clause after the link's name. */
  function summary(link: Link): string {
    const parts = [stateWord(link)];
    if (link.budget_blocked_until !== null && link.budget_blocked_until > now) {
      // Pacing, not a fault: the radio is out of airtime, which is the system
      // obeying the law rather than anything going wrong.
      parts.push(`paced until ${clockTime(link.budget_blocked_until)}`);
    }
    const loss = lossLabel(link.recent_loss_permille);
    if (loss !== null) parts.push(loss);
    if (link.last_received_at !== null) {
      parts.push(`heard ${relativeTime(link.last_received_at, now)}`);
    } else if (link.last_sent_at !== null) {
      parts.push(`sent ${relativeTime(link.last_sent_at, now)}`);
    }
    return parts.join(' · ');
  }
</script>

<section class="links" aria-label="Link health">
  <h2>Links</h2>
  {#if links.length === 0}
    <p class="none">No links configured.</p>
  {/if}
  <ul>
    {#each links as link (link.id)}
      <li>
        <button
          type="button"
          class="head"
          aria-expanded={expanded === link.id}
          onclick={() => (expanded = expanded === link.id ? null : link.id)}
        >
          <span class="dot" data-status={link.status} aria-hidden="true"></span>
          <span class="name">{link.label}</span>
          <span class="chev" aria-hidden="true">{expanded === link.id ? '▾' : '▸'}</span>
        </button>
        <p class="summary">{summary(link)}</p>

        {#if expanded === link.id}
          <dl class="detail">
            <dt>Packets</dt>
            <dd>{link.packets_sent} out · {link.packets_received} in</dd>
            <dt>Bytes</dt>
            <dd>{link.bytes_sent} out · {link.bytes_received} in</dd>
            <dt>MTU</dt>
            <dd>{link.mtu} bytes</dd>
            <dt>Loss</dt>
            <dd>{lossLabel(link.recent_loss_permille) ?? 'not measured'}</dd>
          </dl>
          <label class="toggle">
            <input
              type="checkbox"
              checked={link.enabled}
              onchange={(event) => onToggle(link.id, event.currentTarget.checked)}
            />
            Use this link
          </label>
        {/if}
      </li>
    {/each}
  </ul>
</section>

<style>
  .links {
    border-top: 1px solid var(--border);
    padding: var(--space-3) var(--space-3) var(--space-3);
  }

  h2 {
    margin: 0 0 var(--space-2);
    color: var(--text-faint);
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  li + li {
    margin-top: var(--space-2);
  }

  .head {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    width: 100%;
    padding: 0;
    background: none;
    border: 0;
    text-align: left;
    cursor: pointer;
  }

  .name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: var(--text-sm);
  }

  .chev {
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  /* Status is carried by the text; the dot is a quiet second channel and is
     hidden from assistive technology. */
  .dot {
    flex: none;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    border: 1px solid currentcolor;
    color: var(--text-faint);
  }

  .dot[data-status='up'] {
    background: var(--status-delivered);
    color: var(--status-delivered);
  }

  .dot[data-status='down'] {
    background: transparent;
    color: var(--text-muted);
  }

  .dot[data-status='disabled'] {
    background: var(--border-strong);
    color: var(--border-strong);
  }

  .summary,
  .none {
    margin: 2px 0 0 calc(7px + var(--space-2) + 2px);
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .none {
    margin-left: 0;
  }

  .detail {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 1px var(--space-2);
    margin: var(--space-2) 0 0 calc(7px + var(--space-2) + 2px);
    font-size: var(--text-xs);
  }

  dt {
    color: var(--text-faint);
  }

  dd {
    margin: 0;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .toggle {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin: var(--space-2) 0 0 calc(7px + var(--space-2) + 2px);
    color: var(--text-muted);
    font-size: var(--text-xs);
    cursor: pointer;
  }
</style>
