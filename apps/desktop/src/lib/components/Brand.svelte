<!--
  The avianlink mark, in whichever tier the rendered size calls for.

  The brand guidelines pick the file by *rendered* size, because the full
  mark's 14 fine lines blur when small:

  | variant   | rule                                    |
  | --------- | --------------------------------------- |
  | `lockup`  | lockup 24–47px tall → compact lockup    |
  | `wordmark`| below 24px tall → wordmark alone        |
  | `mark`    | mark 96px wide and up → full mark       |

  The files are inlined rather than used as `<img>` so that `currentColor`
  resolves against the surrounding text, which is what keeps the mark correct
  in both themes from one file. They are copied verbatim from the asset
  package; see `src/assets/brand/README.md`.
-->
<script lang="ts">
  import lockup from '../../assets/brand/avianlink-lockup-compact-currentcolor.svg?raw';
  import markFull from '../../assets/brand/avianlink-mark-full-currentcolor.svg?raw';
  import wordmark from '../../assets/brand/avianlink-wordmark-currentcolor.svg?raw';

  interface Props {
    variant: 'lockup' | 'wordmark' | 'mark';
    /** Rendered height in pixels (width, for `mark`). */
    size: number;
  }

  let { variant, size }: Props = $props();

  let source = $derived(
    variant === 'lockup' ? lockup : variant === 'wordmark' ? wordmark : markFull,
  );

  /**
   * Clear space is half the mark's height on every side, and nothing else may
   * enter it. Expressed as a custom property so the caller can lay out
   * against it rather than guessing.
   */
  let clearance = $derived(Math.round(size / 2));
</script>

<!--
  No `role`/`aria-label` here: every supplied file already carries
  `role="img"` and `aria-label="avianlink"`, and adding a second one would
  nest two identical image roles. The wrapper is layout only.
-->
<span class="brand {variant}" style="--brand-size: {size}px; --brand-clearance: {clearance}px">
  <!-- eslint-disable-next-line svelte/no-at-html-tags -->
  {@html source}
</span>

<style>
  .brand {
    display: inline-flex;
    align-items: center;
    /* Clear space on every side; nothing else enters it. */
    padding: 0 var(--brand-clearance);
    margin: 0 calc(-1 * var(--brand-clearance));
  }

  /* The supplied files carry their own width and height attributes. Sizing
     by height only, with `width: auto`, is what keeps the aspect ratio exact
     — the guidelines forbid stretching or squashing. `> svg` so the lockup's
     nested inner svg is left to its own coordinates. */
  .brand :global(> svg) {
    display: block;
    height: var(--brand-size);
    width: auto;
  }

  .mark :global(> svg) {
    width: var(--brand-size);
    height: auto;
  }
</style>
