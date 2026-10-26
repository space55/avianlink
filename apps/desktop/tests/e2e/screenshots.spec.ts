import { expect, test, type Page } from '@playwright/test';

import {
  CONVERSATION,
  mockBackendScript,
  mockConversation,
  mockLink,
  mockMessage,
  type MockSeed,
} from './mock-backend';

/**
 * Captures the interface for the phase reports.
 *
 * Skipped unless `CAPTURE=1`, because writing image files is not something an
 * ordinary test run should do. These are of the frontend in Chromium, not of
 * the native window: the window chrome is the platform's, everything inside
 * it is exactly this.
 *
 *   CAPTURE=1 npx playwright test screenshots
 */
const capturing = process.env.CAPTURE === '1';

const HOUR = 3_600_000;
/**
 * Anchored to the run, not to a fixed instant: the sidebar and link panel
 * show relative times, and a seed pinned to 2023 would render every one of
 * them as "153w" and hide exactly what they are for.
 */
const T0 = Date.now() - 5 * HOUR;

/** A conversation showing every message state and both kinds of disorder. */
const populated: MockSeed = {
  simulated: true,
  conversations: [
    mockConversation({
      last_message: {
        text: 'understood, heading down now',
        outgoing: false,
        at: T0 + 4 * HOUR,
        status: null,
      },
      unread_count: 2,
      undelivered_count: 1,
      contact: {
        conversation_id: CONVERSATION,
        public_key: 'a'.repeat(64),
        fingerprint: 'd033-9b2b-d44b-ab05-ec86',
        display_name: 'Rook',
        verified: true,
        added_at: T0 - 90 * 24 * HOUR,
        last_packet_at: T0 + 4 * HOUR - 3 * HOUR,
        last_message_at: T0 + 4 * HOUR,
        unread_count: 2,
      },
    }),
    mockConversation({
      conversation_id: 'b'.repeat(32),
      contact: {
        conversation_id: 'b'.repeat(32),
        public_key: 'b'.repeat(64),
        fingerprint: '71c4-0a9e-5b33-ef18-2d07',
        display_name: 'Wren',
        verified: false,
        added_at: T0 - 10 * 24 * HOUR,
        last_packet_at: T0 - 50 * HOUR,
        last_message_at: T0 - 50 * HOUR,
        unread_count: 0,
      },
      last_message: {
        text: 'no change overnight',
        outgoing: true,
        at: T0 - 50 * HOUR,
        status: 'delivered',
      },
    }),
    mockConversation({
      conversation_id: 'e'.repeat(32),
      contact: {
        conversation_id: 'e'.repeat(32),
        public_key: 'e'.repeat(64),
        fingerprint: '04fa-9b21-7c60-ae55-311d',
        display_name: 'Kite',
        verified: false,
        added_at: T0,
        last_packet_at: null,
        last_message_at: null,
        unread_count: 0,
      },
    }),
  ],
  messages: {
    [CONVERSATION]: [
      mockMessage({
        id: '1'.repeat(32),
        lamport: 1,
        text: 'are you there',
        sent_at: T0,
        received_at: T0 + 120_000,
      }),
      mockMessage({
        id: '2'.repeat(32),
        lamport: 2,
        outgoing: true,
        text: 'yes, on the ridge until dark',
        sent_at: T0 + 180_000,
        received_at: null,
        status: 'delivered',
        delivered_at: T0 + 180_000 + HOUR + 720_000,
        attempts: 4,
      }),
      mockMessage({
        id: '3'.repeat(32),
        lamport: 3,
        text: 'the repeater is back up',
        sent_at: T0 + 2 * HOUR,
        received_at: T0 + 3 * HOUR + 1_200_000,
        arrived_late: true,
      }),
      mockMessage({
        id: '4'.repeat(32),
        lamport: 4,
        text: 'say again, last was garbled',
        sent_at: null,
        received_at: T0 + 3 * HOUR + 1_800_000,
        missing_before: 2,
      }),
      mockMessage({
        id: '5'.repeat(32),
        lamport: 5,
        outgoing: true,
        text: 'water drop is scheduled for 06:00',
        sent_at: T0 + 4 * HOUR,
        received_at: null,
        status: 'sent',
        attempts: 2,
      }),
      mockMessage({
        id: '6'.repeat(32),
        lamport: 6,
        outgoing: true,
        text: 'bring the long hose and the spare coupling',
        sent_at: T0 + 4 * HOUR + 60_000,
        received_at: null,
        status: 'queued',
        attempts: 0,
      }),
      mockMessage({
        id: '7'.repeat(32),
        lamport: 7,
        outgoing: true,
        text: 'this one was given up on',
        sent_at: T0 + 4 * HOUR + 120_000,
        received_at: null,
        status: 'failed',
        attempts: 31,
      }),
      mockMessage({
        id: '8'.repeat(32),
        lamport: 8,
        text: 'understood, heading down now',
        sent_at: T0 + 4 * HOUR + 180_000,
        received_at: T0 + 4 * HOUR + 200_000,
      }),
    ],
  },
  links: [
    mockLink({
      packets_sent: 184,
      packets_received: 97,
      bytes_sent: 41_200,
      bytes_received: 18_400,
      recent_loss_permille: 320,
      last_sent_at: T0 + 4 * HOUR,
      last_received_at: T0 + 4 * HOUR - 3 * HOUR,
    }),
  ],
};

async function open(page: Page, seed: MockSeed, width = 1100, height = 760) {
  await page.setViewportSize({ width, height });
  await page.addInitScript(mockBackendScript(seed));
  await page.goto('/');
}

test.describe('screenshots', () => {
  test.skip(!capturing, 'set CAPTURE=1 to write screenshots');

  for (const scheme of ['light', 'dark'] as const) {
    test(`thread (${scheme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await open(page, populated);
      await expect(page.getByText('are you there')).toBeVisible();
      await page.screenshot({ path: `docs/screenshots/phase1-thread-${scheme}.png` });
    });
  }

  test('link health expanded', async ({ page }) => {
    await open(page, populated);
    await page.getByRole('button', { name: /Simulated link/ }).click();
    await expect(
      page.getByText('not measured').or(page.getByText('32% loss')).first(),
    ).toBeVisible();
    await page.screenshot({ path: 'docs/screenshots/phase1-links.png' });
  });

  test('add contact', async ({ page }) => {
    await open(page, populated);
    await page.getByRole('button', { name: 'Add a contact' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.screenshot({ path: 'docs/screenshots/phase1-add-contact.png' });
  });

  test('settings', async ({ page }) => {
    await open(page, populated, 1100, 900);
    await page.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.screenshot({ path: 'docs/screenshots/phase1-settings.png' });
  });

  test('empty', async ({ page }) => {
    await open(page, { simulated: true, links: [mockLink()] });
    await expect(page.getByText(/No contacts yet/i)).toBeVisible();
    await page.screenshot({ path: 'docs/screenshots/phase1-empty.png' });
  });

  test('narrow', async ({ page }) => {
    await open(page, populated, 560, 760);
    await expect(page.getByText('are you there')).toBeVisible();
    await page.screenshot({ path: 'docs/screenshots/phase1-narrow.png' });
  });
});
