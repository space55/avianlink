<!--
  A modal dialog with a focus trap.

  Uses the native `<dialog>` element so Escape, the backdrop and the top layer
  are the platform's rather than reimplemented, and adds the one thing it does
  not give us: returning focus to whatever opened it.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    open: boolean;
    onClose: () => void;
    children: Snippet;
  }

  let { title, open, onClose, children }: Props = $props();
  let dialog = $state<HTMLDialogElement | null>(null);

  // Mounted only while open (App.svelte guards it), so the document never
  // holds two copies of the same element ids and labels. The one thing
  // `<dialog>` does not give us is returning focus to whatever opened it,
  // which the cleanup below does.
  $effect(() => {
    const element = dialog;
    if (!element || !open) return;
    const opener = document.activeElement;
    if (!element.open) element.showModal();
    return () => {
      if (element.open) element.close();
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  });
</script>

<dialog bind:this={dialog} oncancel={onClose} onclose={onClose} aria-label={title}>
  <div class="panel">
    <header>
      <h2>{title}</h2>
      <button type="button" class="close" onclick={onClose}>
        <span aria-hidden="true">×</span>
        <span class="visually-hidden">Close</span>
      </button>
    </header>
    <div class="body">
      {@render children()}
    </div>
  </div>
</dialog>

<style>
  dialog {
    padding: 0;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-lg);
    background: var(--bg-raised);
    color: var(--text);
    max-width: min(34rem, calc(100vw - 2rem));
    max-height: calc(100vh - 4rem);
    box-shadow: 0 8px 32px rgb(0 0 0 / 24%);
  }

  dialog::backdrop {
    background: rgb(0 0 0 / 36%);
  }

  .panel {
    display: flex;
    flex-direction: column;
    max-height: calc(100vh - 4rem);
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    border-bottom: 1px solid var(--border);
  }

  .close {
    width: 24px;
    height: 24px;
    display: grid;
    place-items: center;
    background: none;
    border: 0;
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    cursor: pointer;
    font-size: var(--text-lg);
    line-height: 1;
  }

  .close:hover {
    background: var(--bg-hover);
    color: var(--text);
  }

  .body {
    overflow-y: auto;
    padding: var(--space-4);
  }
</style>
