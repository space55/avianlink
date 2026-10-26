<!--
  Copies a value to the clipboard and says so.

  Uses the Clipboard API directly rather than a Tauri plugin: the webview is a
  secure context, so it works, and it avoids granting a clipboard capability
  the rest of the app has no use for.
-->
<script lang="ts">
  interface Props {
    value: string;
    label?: string;
  }

  let { value, label = 'Copy' }: Props = $props();
  let state = $state<'idle' | 'copied' | 'failed'>('idle');
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      state = 'copied';
    } catch {
      // Some Linux WebViews refuse without a user-activation heuristic the
      // app cannot influence. Saying so is better than a button that does
      // nothing visible.
      state = 'failed';
    }
    clearTimeout(timer);
    timer = setTimeout(() => (state = 'idle'), 2000);
  }
</script>

<button type="button" onclick={copy}>
  {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}
</button>
<span class="visually-hidden" role="status">
  {state === 'copied' ? 'Copied to clipboard' : state === 'failed' ? 'Could not copy' : ''}
</span>

<style>
  button {
    padding: var(--space-1) var(--space-3);
    background: var(--bg-raised);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
    cursor: pointer;
  }

  button:hover {
    background: var(--bg-hover);
  }
</style>
