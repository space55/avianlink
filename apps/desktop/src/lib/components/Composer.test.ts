import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

import Composer from './Composer.svelte';

function show(onSend: (text: string) => void = vi.fn(), disabled = false) {
  render(Composer, { props: { onSend, disabled } });
  return { onSend, input: screen.getByLabelText('Message') as HTMLTextAreaElement };
}

describe('sending', () => {
  it('sends on Enter', async () => {
    const { onSend, input } = show();
    await fireEvent.input(input, { target: { value: 'on my way' } });
    await fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSend).toHaveBeenCalledWith('on my way');
  });

  it('inserts a newline on Shift+Enter instead of sending', async () => {
    const { onSend, input } = show();
    await fireEvent.input(input, { target: { value: 'first line' } });
    await fireEvent.keyDown(input, { key: 'Enter', shiftKey: true });
    expect(onSend).not.toHaveBeenCalled();
  });

  it('leaves Cmd+Enter and Ctrl+Enter to the platform', async () => {
    const { onSend, input } = show();
    await fireEvent.input(input, { target: { value: 'text' } });
    await fireEvent.keyDown(input, { key: 'Enter', metaKey: true });
    await fireEvent.keyDown(input, { key: 'Enter', ctrlKey: true });
    expect(onSend).not.toHaveBeenCalled();
  });

  it('clears immediately, before anything is awaited', async () => {
    // Sending is a local durable write; from the user's point of view it has
    // already succeeded, and "succeeded" means queued (docs/design.md §1).
    // Never resolves: if the composer waited for the command, it would not
    // have cleared by the time this assertion runs.
    const onSend = vi.fn(() => new Promise<void>(() => {}));
    const { input } = show(onSend as unknown as (text: string) => void);
    await fireEvent.input(input, { target: { value: 'on my way' } });
    await fireEvent.keyDown(input, { key: 'Enter' });
    expect(input.value).toBe('');
  });

  it('trims whitespace and refuses a message that is only whitespace', async () => {
    const { onSend, input } = show();
    await fireEvent.input(input, { target: { value: '   ' } });
    await fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSend).not.toHaveBeenCalled();

    await fireEvent.input(input, { target: { value: '  hello  ' } });
    await fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSend).toHaveBeenCalledWith('hello');
  });

  it('disables the send button until there is something to send', async () => {
    const { input } = show();
    const button = screen.getByRole('button', { name: 'Send' });
    expect(button).toBeDisabled();
    await fireEvent.input(input, { target: { value: 'x' } });
    expect(button).toBeEnabled();
  });

  it('submits when the button is pressed', async () => {
    const { onSend, input } = show();
    await fireEvent.input(input, { target: { value: 'hello' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Send' }));
    expect(onSend).toHaveBeenCalledWith('hello');
  });
});

describe('labelling', () => {
  it('labels the field for screen readers without a visible label', () => {
    const { input } = show();
    expect(input).toHaveAttribute('id', 'composer-input');
    expect(document.querySelector('label[for="composer-input"]')).toHaveClass('visually-hidden');
  });

  it('explains the Enter behaviour visually but not to screen readers', () => {
    // A screen reader user is told about the field by its label; the hint is
    // a visual affordance and would be noise read aloud.
    show();
    const hint = document.querySelector('.hint');
    expect(hint?.textContent).toMatch(/Shift\+Enter/);
    expect(hint).toHaveAttribute('aria-hidden', 'true');
  });
});
