import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';

import MessageRow from './MessageRow.svelte';
import type { Message, MessageStatus } from '../ipc/client';

const HOUR = 3_600_000;
const T0 = 1_700_000_000_000;
const THRESHOLD = 5 * 60 * 1000;

function message(overrides: Partial<Message> = {}): Message {
  return {
    id: '1'.repeat(32),
    conversation_id: 'c'.repeat(32),
    outgoing: false,
    text: 'are you there',
    lamport: 1,
    seq: 0,
    order_key: '0000000000000001:' + '1'.repeat(32),
    sent_at: T0,
    received_at: T0 + 1000,
    status: null,
    delivered_at: null,
    attempts: null,
    arrived_late: false,
    missing_before: 0,
    ...overrides,
  };
}

function show(overrides: Partial<Message> = {}) {
  return render(MessageRow, {
    props: { message: message(overrides), senderName: 'Rook', receiveThresholdMs: THRESHOLD },
  });
}

/** The row's accessible name, which is where the visual encoding must land. */
function name(): string {
  const item = document.querySelector('li.row');
  return item?.getAttribute('aria-label') ?? '';
}

describe('message states', () => {
  const cases: { status: MessageStatus; expect: RegExp }[] = [
    { status: 'queued', expect: /Queued/ },
    { status: 'sent', expect: /Sent/ },
    { status: 'delivered', expect: /Delivered/ },
    { status: 'failed', expect: /Not sent/ },
  ];

  for (const { status, expect: pattern } of cases) {
    it(`renders ${status} with its state in the accessible name`, () => {
      show({ outgoing: true, status, attempts: 2, received_at: null });
      expect(name()).toMatch(pattern);
      // The glyph itself is hidden: the state reaches a screen reader through
      // the row's name instead, so it is not announced twice.
      const icon = document.querySelector('.icon');
      expect(icon).toHaveAttribute('aria-hidden', 'true');
      expect(icon).toHaveClass(status);
    });
  }

  it('gives each state a distinct glyph, not just a distinct colour', () => {
    // The set has to survive greyscale and colour blindness, so the shapes
    // must differ (docs/design.md §3).
    const shapes = new Set<string>();
    for (const status of ['queued', 'sent', 'delivered', 'failed'] as MessageStatus[]) {
      const { unmount } = show({ outgoing: true, status, received_at: null });
      const svg = document.querySelector('.icon svg');
      shapes.add(svg?.innerHTML ?? '');
      unmount();
    }
    expect(shapes.size).toBe(4);
  });

  it('shows how long delivery took, on an outgoing delivered message', () => {
    show({
      outgoing: true,
      status: 'delivered',
      sent_at: T0,
      delivered_at: T0 + HOUR + 12 * 60_000,
      attempts: 4,
      received_at: null,
    });
    expect(name()).toMatch(/1h 12m to deliver/);
  });

  it('reports the attempt count in the detail but never on screen', () => {
    show({ outgoing: true, status: 'sent', attempts: 7, received_at: null });
    expect(name()).toMatch(/7 attempts/);
    // A number that climbs on its own must not draw the eye to something the
    // user cannot act on.
    expect(screen.queryByText('7')).toBeNull();
  });

  it('gives an incoming message no status at all', () => {
    show();
    expect(document.querySelector('.icon')).toBeNull();
  });
});

describe('two times', () => {
  it('shows only the send time when the gap is small', () => {
    show({ sent_at: T0, received_at: T0 + 30_000 });
    expect(document.querySelector('.arrival')).toBeNull();
  });

  it('shows the arrival time too when the gap is worth mentioning', () => {
    show({ sent_at: T0, received_at: T0 + 3 * HOUR });
    expect(document.querySelector('.arrival')?.textContent).toMatch(/arrived/);
    expect(name()).toMatch(/arrived/);
  });

  it('shows only the arrival time when the sender has no clock', () => {
    // The library lets a host with no RTC omit the timestamp entirely.
    show({ sent_at: null, received_at: T0 });
    const times = document.querySelectorAll('time');
    expect(times).toHaveLength(1);
    expect(times[0].textContent).toMatch(/arrived/);
    expect(name()).toMatch(/sender has no clock/);
  });

  it('never claims an arrival time for our own messages', () => {
    show({ outgoing: true, status: 'queued', sent_at: T0, received_at: null });
    expect(document.querySelector('.arrival')).toBeNull();
  });
});

describe('disorder', () => {
  it('marks a message that landed behind ones already shown', () => {
    show({ arrived_late: true });
    expect(screen.getByText('arrived out of order')).toBeInTheDocument();
    expect(name()).toMatch(/arrived out of order/);
  });

  it('does not mark an ordinary message', () => {
    show();
    expect(screen.queryByText('arrived out of order')).toBeNull();
  });

  it('reports a hole in the history above the message that overtook it', () => {
    show({ missing_before: 2 });
    expect(screen.getByText(/2\s+earlier messages are\s+still on their way/)).toBeInTheDocument();
  });

  it('uses the singular for a single missing message', () => {
    show({ missing_before: 1 });
    expect(screen.getByText(/1\s+earlier message is\s+still on their way/)).toBeInTheDocument();
  });

  it('shows no gap marker when nothing is missing', () => {
    show();
    expect(document.querySelector('.gap')).toBeNull();
  });
});

describe('content', () => {
  it('keeps message text selectable, because it is content not chrome', () => {
    show({ text: 'copy me' });
    expect(screen.getByText('copy me')).toHaveClass('selectable');
  });

  it('keeps newlines in the text rather than collapsing them', () => {
    // The rendering side of this is `white-space: pre-wrap`, which jsdom
    // cannot evaluate because Vite extracts component styles to a separate
    // file. What is checkable here is that the newline survives into the DOM.
    show({ text: 'one\ntwo' });
    expect(document.querySelector('.text')?.textContent).toBe('one\ntwo');
  });
});
