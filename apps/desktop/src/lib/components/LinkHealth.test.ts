import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

import LinkHealth from './LinkHealth.svelte';
import type { Link } from '../ipc/client';

const T0 = 1_700_000_000_000;
const HOUR = 3_600_000;

function link(overrides: Partial<Link> = {}): Link {
  return {
    id: 1,
    label: 'Simulated link',
    kind: 'fake',
    enabled: true,
    status: 'up',
    mtu: 512,
    config: { kind: 'fake', profile: 'disaster_cellular' },
    packets_sent: 10,
    packets_received: 4,
    bytes_sent: 900,
    bytes_received: 310,
    recent_loss_permille: null,
    last_sent_at: null,
    last_received_at: null,
    budget_blocked_until: null,
    ...overrides,
  };
}

function show(overrides: Partial<Link> = {}, onToggle = vi.fn()) {
  return {
    ...render(LinkHealth, { props: { links: [link(overrides)], now: T0, onToggle } }),
    onToggle,
  };
}

/** The whole panel's text, which is what the tone assertions check. */
function text(): string {
  return document.querySelector('.links')?.textContent ?? '';
}

describe('vocabulary', () => {
  it('says "up", not "connected"', () => {
    show({ status: 'up' });
    expect(text()).toMatch(/\bup\b/);
    expect(text()).not.toMatch(/connected|online/i);
  });

  it('says "unavailable" for a link that is down, never "disconnected"', () => {
    show({ status: 'down' });
    expect(text()).toMatch(/unavailable/);
    expect(text()).not.toMatch(/disconnect|error|fail/i);
  });

  it('distinguishes a link the user switched off from one that broke', () => {
    // These deserve very different tones even though the link is equally
    // unusable (docs/design.md §6).
    show({ status: 'disabled', enabled: false });
    expect(text()).toMatch(/\boff\b/);
    expect(text()).not.toMatch(/unavailable/);
  });

  it('never raises its voice, whatever the state', () => {
    for (const status of ['up', 'down', 'disabled'] as const) {
      const { unmount } = show({ status, recent_loss_permille: 900 });
      expect(text()).not.toMatch(/[!]|warning|critical|lost|dead/i);
      unmount();
    }
  });
});

describe('loss', () => {
  it('renders measured loss as a percentage', () => {
    show({ recent_loss_permille: 320 });
    expect(text()).toMatch(/32% loss/);
  });

  it('says nothing at all when loss was never measured', () => {
    // Claiming a perfect link because nothing measured it is the worst
    // available failure (docs/design.md §6).
    show({ recent_loss_permille: null });
    expect(text()).not.toMatch(/%/);
  });

  it('calls it "not measured" in the detail, rather than showing zero', () => {
    show({ recent_loss_permille: null });
    fireEvent.click(screen.getByRole('button', { name: /Simulated link/ }));
    expect(screen.getByText('not measured')).toBeInTheDocument();
  });

  it('does show a genuine zero when that is what was measured', () => {
    show({ recent_loss_permille: 0 });
    expect(text()).toMatch(/0% loss/);
  });
});

describe('pacing', () => {
  it('reports an exhausted airtime budget without the link going down', () => {
    // Duty-cycled radios spend most of their life out of budget; that is the
    // system obeying the law, not a fault.
    show({ status: 'up', budget_blocked_until: T0 + HOUR });
    expect(text()).toMatch(/paced until/);
    expect(text()).toMatch(/\bup\b/);
    expect(text()).not.toMatch(/blocked|throttl/i);
  });

  it('ignores a budget deadline that has already passed', () => {
    show({ budget_blocked_until: T0 - HOUR });
    expect(text()).not.toMatch(/paced/);
  });
});

describe('detail', () => {
  it('stays collapsed until asked', () => {
    show();
    expect(screen.queryByText('Packets')).toBeNull();
    const head = screen.getByRole('button', { name: /Simulated link/ });
    expect(head).toHaveAttribute('aria-expanded', 'false');
  });

  it('shows counters and the MTU when expanded', () => {
    show();
    fireEvent.click(screen.getByRole('button', { name: /Simulated link/ }));
    expect(screen.getByText('10 out · 4 in')).toBeInTheDocument();
    expect(screen.getByText('512 bytes')).toBeInTheDocument();
  });

  it('lets a link be switched off from the detail', async () => {
    const { onToggle } = show();
    await fireEvent.click(screen.getByRole('button', { name: /Simulated link/ }));
    await fireEvent.click(screen.getByLabelText('Use this link'));
    expect(onToggle).toHaveBeenCalledWith(1, false);
  });
});

describe('silence', () => {
  it('reports when the link last heard something', () => {
    show({ last_received_at: T0 - 3 * HOUR });
    expect(text()).toMatch(/heard 3h/);
  });

  it('falls back to the last send when nothing has come back', () => {
    show({ last_received_at: null, last_sent_at: T0 - 2 * HOUR });
    expect(text()).toMatch(/sent 2h/);
  });
});
