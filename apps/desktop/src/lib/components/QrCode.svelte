<!--
  A QR code, as inline SVG.

  SVG rather than a canvas so it is crisp at any size, prints, and takes its
  colours from the theme tokens. The payload is the bare 64-character hex key
  — not a URL, not JSON — because anything cleverer is a compatibility problem
  with the CLI and with whatever reads it on a phone (docs/design.md §7).
-->
<script lang="ts">
  import encodeQR from '@paulmillr/qr';

  interface Props {
    value: string;
    /** Rendered edge length in pixels. */
    size?: number;
    label?: string;
  }

  let { value, size = 180, label = 'QR code of your public key' }: Props = $props();

  let matrix = $derived.by(() => {
    try {
      return encodeQR(value, 'raw') as boolean[][];
    } catch {
      return null;
    }
  });

  /** A quiet zone is part of the spec; without it, scanners struggle. */
  const QUIET = 2;
  let dimension = $derived(matrix ? matrix.length + QUIET * 2 : 0);
</script>

{#if matrix}
  <svg
    class="qr"
    width={size}
    height={size}
    viewBox={`0 0 ${dimension} ${dimension}`}
    role="img"
    aria-label={label}
    shape-rendering="crispEdges"
  >
    <rect width={dimension} height={dimension} fill="var(--qr-bg, #ffffff)" />
    {#each matrix as row, y (y)}
      {#each row as filled, x (x)}
        {#if filled}
          <rect x={x + QUIET} y={y + QUIET} width="1" height="1" fill="var(--qr-fg, #000000)" />
        {/if}
      {/each}
    {/each}
  </svg>
{:else}
  <p class="failed">Could not render a QR code for this key.</p>
{/if}

<style>
  .qr {
    display: block;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    /* Always light: QR scanners expect dark-on-light, and inverting it to
       match a dark theme makes it unreadable on many phones. */
    --qr-bg: #ffffff;
    --qr-fg: #000000;
  }

  .failed {
    color: var(--status-failed);
    font-size: var(--text-sm);
  }
</style>
