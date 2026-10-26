import { describe, expect, it } from 'vitest';

import { furthestStatus, mergeMessage } from './state.svelte';
import type { Message, MessageStatus } from './ipc/client';

function message(overrides: Partial<Message> & { lamport: number; id: string }): Message {
  const { lamport, id } = overrides;
  return {
    conversation_id: 'c'.repeat(32),
    outgoing: false,
    text: 'hello',
    seq: 0,
    order_key: `${lamport.toString(16).padStart(16, '0')}:${id}`,
    sent_at: 1_700_000_000_000,
    received_at: 1_700_000_001_000,
    status: null,
    delivered_at: null,
    attempts: null,
    arrived_late: false,
    missing_before: 0,
    ...overrides,
  };
}

describe('furthestStatus', () => {
  it('never goes backwards', () => {
    // A `sent` for attempt 7 can arrive after the ack for attempt 3.
    expect(furthestStatus('delivered', 'sent')).toBe('delivered');
    expect(furthestStatus('sent', 'delivered')).toBe('delivered');
    expect(furthestStatus('queued', 'sent')).toBe('sent');
  });

  it('treats failed as terminal', () => {
    expect(furthestStatus('failed', 'delivered')).toBe('failed');
  });

  it('passes through nulls, because incoming messages have no status', () => {
    expect(furthestStatus(null, null)).toBeNull();
    expect(furthestStatus(null, 'sent')).toBe('sent');
    expect(furthestStatus('sent', null)).toBe('sent');
  });
});

describe('mergeMessage', () => {
  it('keeps the list in causal order, not arrival order', () => {
    const messages: Message[] = [];
    mergeMessage(messages, message({ lamport: 1, id: 'a'.repeat(32), text: 'first' }));
    mergeMessage(messages, message({ lamport: 3, id: 'c'.repeat(32), text: 'third' }));
    const index = mergeMessage(
      messages,
      message({ lamport: 2, id: 'b'.repeat(32), text: 'second' }),
    );
    expect(messages.map((m) => m.text)).toEqual(['first', 'second', 'third']);
    expect(index).toBe(1);
  });

  it('reports the index so the thread can tell it must hold the scroll', () => {
    const messages: Message[] = [];
    mergeMessage(messages, message({ lamport: 5, id: 'e'.repeat(32) }));
    // Landing at the end means the user can be scrolled to it.
    expect(mergeMessage(messages, message({ lamport: 6, id: 'f'.repeat(32) }))).toBe(1);
    // Landing in the middle means content appeared above the viewport.
    expect(mergeMessage(messages, message({ lamport: 1, id: '1'.repeat(32) }))).toBe(0);
  });

  it('replaces a message it already has rather than duplicating it', () => {
    // Retransmission makes this the normal case, not an anomaly.
    const messages: Message[] = [];
    const first = message({ lamport: 1, id: 'a'.repeat(32), text: 'hello' });
    mergeMessage(messages, first);
    mergeMessage(messages, { ...first, text: 'hello' });
    expect(messages).toHaveLength(1);
  });

  it('does not let a replacement move a status backwards', () => {
    const messages: Message[] = [];
    const sent = message({
      lamport: 1,
      id: 'a'.repeat(32),
      outgoing: true,
      status: 'delivered' as MessageStatus,
    });
    mergeMessage(messages, sent);
    mergeMessage(messages, { ...sent, status: 'sent' });
    expect(messages[0].status).toBe('delivered');
  });

  it('orders by lamport before id, with fixed-width keys', () => {
    // The bug this guards: lamport 9 must not sort above lamport 10.
    const messages: Message[] = [];
    mergeMessage(messages, message({ lamport: 10, id: 'a'.repeat(32) }));
    mergeMessage(messages, message({ lamport: 9, id: 'z'.repeat(32) }));
    expect(messages.map((m) => m.lamport)).toEqual([9, 10]);
  });
});
