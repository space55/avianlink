<!--
  The composer (docs/design.md §1).

  It never blocks and never reports a link problem. Sending is a local durable
  write: the textarea clears the moment the user presses Enter, before the
  command is awaited, because from their point of view it has already
  succeeded and "succeeded" means queued.
-->
<script lang="ts">
  interface Props {
    disabled?: boolean;
    placeholder?: string;
    onSend: (text: string) => void;
  }

  let { disabled = false, placeholder = 'Message', onSend }: Props = $props();

  let draft = $state('');
  let textarea = $state<HTMLTextAreaElement | null>(null);

  export function focus() {
    textarea?.focus();
  }

  function submit() {
    const text = draft.trim();
    if (text === '' || disabled) return;
    // Cleared first, deliberately: see the comment above.
    draft = '';
    resize();
    onSend(text);
  }

  function onKeydown(event: KeyboardEvent) {
    // Enter sends; Shift+Enter is a newline. A modifier with Enter is left
    // alone so platform text shortcuts keep working.
    if (event.key === 'Enter' && !event.shiftKey && !event.metaKey && !event.ctrlKey) {
      event.preventDefault();
      submit();
    }
  }

  /** Grows the textarea with its content, up to a few lines. */
  function resize() {
    if (!textarea) return;
    textarea.style.height = 'auto';
    textarea.style.height = `${Math.min(textarea.scrollHeight, 160)}px`;
  }
</script>

<form
  class="composer"
  onsubmit={(event) => {
    event.preventDefault();
    submit();
  }}
>
  <label class="visually-hidden" for="composer-input">Message</label>
  <textarea
    id="composer-input"
    bind:this={textarea}
    bind:value={draft}
    oninput={resize}
    onkeydown={onKeydown}
    {placeholder}
    {disabled}
    rows="1"
    autocomplete="off"
    spellcheck="true"></textarea>
  <button type="submit" disabled={disabled || draft.trim() === ''}>Send</button>
</form>
<p class="hint" aria-hidden="true">Enter to send · Shift+Enter for a new line</p>

<style>
  .composer {
    display: flex;
    gap: var(--space-2);
    align-items: flex-end;
    padding: var(--space-3) var(--space-5) 0;
  }

  textarea {
    flex: 1;
    min-width: 0;
    padding: var(--space-2) var(--space-3);
    background: var(--bg-raised);
    color: var(--text);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    font: inherit;
    line-height: var(--leading-normal);
    resize: none;
    -webkit-user-select: text;
    user-select: text;
  }

  textarea::placeholder {
    color: var(--text-faint);
  }

  button {
    padding: var(--space-2) var(--space-4);
    background: var(--accent);
    color: var(--accent-text);
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  button:disabled {
    background: var(--bg-sunken);
    color: var(--text-faint);
    border-color: var(--border);
    cursor: default;
  }

  .hint {
    margin: var(--space-1) var(--space-5) var(--space-3);
    color: var(--text-faint);
    font-size: var(--text-xs);
    text-align: right;
  }
</style>
