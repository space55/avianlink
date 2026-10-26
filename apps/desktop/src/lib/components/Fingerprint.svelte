<!--
  A fingerprint in its five groups (docs/design.md §7).

  The grouping is the entire point: an ungrouped 20-character string does not
  get compared character by character, and this is the app's only
  authentication step. Each group is a separate element so it cannot be
  reflowed into an unreadable run.
-->
<script lang="ts">
  interface Props {
    fingerprint: string;
    size?: 'normal' | 'large';
  }

  let { fingerprint, size = 'normal' }: Props = $props();
  let groups = $derived(fingerprint.split('-'));
</script>

<span class="fingerprint selectable {size}" aria-label={`Fingerprint ${groups.join(' ')}`}>
  {#each groups as group, index (index)}
    {#if index > 0}<span class="sep" aria-hidden="true">-</span>{/if}<span class="group"
      >{group}</span
    >
  {/each}
</span>

<style>
  .fingerprint {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    letter-spacing: 0.02em;
    white-space: nowrap;
  }

  .large {
    font-size: var(--text-lg);
    letter-spacing: 0.04em;
  }

  .sep {
    color: var(--text-faint);
    padding-inline: 1px;
  }
</style>
