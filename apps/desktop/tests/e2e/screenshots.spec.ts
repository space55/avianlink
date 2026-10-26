import { expect, test } from '@playwright/test';

import { CONVERSATION, mockBackendScript, mockConversation, mockMessage } from './mock-backend';

/**
 * Captures the interface for the phase reports.
 *
 * Skipped unless `CAPTURE=1`, because writing image files is not something an
 * ordinary test run should do. The images are of the frontend in Chromium,
 * not of the native window: the window chrome is the platform's, and
 * everything inside it is exactly what these capture.
 *
 *   CAPTURE=1 npx playwright test screenshots
 */
const capturing = process.env.CAPTURE === '1';

test.describe('screenshots', () => {
  test.skip(!capturing, 'set CAPTURE=1 to write screenshots');

  const seed = {
    conversations: [
      mockConversation({
        last_message: {
          text: 'the repeater is back up',
          outgoing: false,
          at: 1_700_000_001_000,
          status: null,
        },
        unread_count: 1,
      }),
    ],
    messages: {
      [CONVERSATION]: [
        mockMessage({ text: 'are you there', lamport: 1, id: '1'.repeat(32) }),
        mockMessage({
          text: 'yes, on the ridge until dark',
          lamport: 2,
          id: '2'.repeat(32),
          outgoing: true,
          status: 'delivered',
          delivered_at: 1_700_003_601_000,
          attempts: 4,
          received_at: null,
        }),
        mockMessage({
          text: 'the repeater is back up',
          lamport: 3,
          id: '3'.repeat(32),
          arrived_late: true,
        }),
        mockMessage({
          text: 'understood, heading down',
          lamport: 4,
          id: '4'.repeat(32),
          outgoing: true,
          status: 'queued',
          attempts: 0,
          received_at: null,
        }),
      ],
    },
    links: [
      {
        id: 1,
        label: 'Simulated link',
        kind: 'fake',
        enabled: true,
        status: 'up',
        mtu: 1200,
        config: { kind: 'fake', profile: 'disaster_cellular' },
        packets_sent: 184,
        packets_received: 97,
        bytes_sent: 41_200,
        bytes_received: 18_400,
        recent_loss_permille: 320,
        last_sent_at: 1_700_003_600_000,
        last_received_at: 1_700_003_100_000,
        budget_blocked_until: null,
      },
    ],
  };

  for (const scheme of ['light', 'dark'] as const) {
    test(`shell (${scheme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width: 1040, height: 720 });
      await page.addInitScript(mockBackendScript(seed));
      await page.goto('/');
      await expect(page.getByText('are you there')).toBeVisible();
      await page.screenshot({ path: `docs/screenshots/phase0-${scheme}.png`, fullPage: true });
    });
  }

  test('empty state', async ({ page }) => {
    await page.setViewportSize({ width: 1040, height: 720 });
    await page.addInitScript(mockBackendScript({}));
    await page.goto('/');
    await expect(page.getByText(/No contacts yet/i)).toBeVisible();
    await page.screenshot({ path: 'docs/screenshots/phase0-empty.png', fullPage: true });
  });
});
