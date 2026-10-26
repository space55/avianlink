import { expect, test, type Page } from '@playwright/test';

import {
  CONVERSATION,
  mockBackendScript,
  mockConversation,
  mockLink,
  mockMessage,
  type MockSeed,
} from './mock-backend';

const HOUR = 3_600_000;

/** Loads the app with a mocked backend. */
async function open(page: Page, seed: MockSeed = {}) {
  await page.addInitScript(mockBackendScript(seed));
  await page.goto('/');
}

/** Pushes a backend event into the page, as the real backend would. */
async function emit(page: Page, event: string, payload: unknown) {
  await page.evaluate(
    ({ event, payload }) => {
      (window as unknown as { __emit: (e: string, p: unknown) => void }).__emit(event, payload);
    },
    { event, payload },
  );
}

/** The commands the page has issued so far. */
async function calls(page: Page): Promise<{ cmd: string; args: Record<string, unknown> }[]> {
  return page.evaluate(() => (window as unknown as { __calls: never[] }).__calls);
}

const now = Date.now();

const oneConversation: MockSeed = {
  simulated: true,
  conversations: [mockConversation()],
  messages: { [CONVERSATION]: [mockMessage({ text: 'are you there', lamport: 1 })] },
  links: [mockLink()],
};

test.describe('empty states', () => {
  test('a new account explains what to do instead of showing nothing', async ({ page }) => {
    await open(page, { simulated: true, links: [mockLink()] });
    await expect(page.getByText(/No contacts yet/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add a contact' }).first()).toBeVisible();
  });

  test('a conversation with no messages says so calmly', async ({ page }) => {
    await open(page, {
      simulated: true,
      conversations: [mockConversation()],
      messages: { [CONVERSATION]: [] },
      links: [mockLink()],
    });
    await expect(page.getByText('No messages yet.')).toBeVisible();
    // The explanation has to make an hour-long delivery sound normal.
    await expect(page.locator('.empty')).toContainText(/in a\s+second or in a day/);
  });
});

test.describe('sending', () => {
  test('the composer clears instantly and the message shows as queued', async ({ page }) => {
    await open(page, oneConversation);
    const composer = page.getByLabel('Message');
    await composer.fill('on my way');
    await composer.press('Enter');

    await expect(composer).toHaveValue('');
    await expect(page.getByText('on my way')).toBeVisible();
    const row = page.locator('li.row', { hasText: 'on my way' });
    await expect(row).toHaveAttribute('aria-label', /Queued/);
  });

  test('Shift+Enter makes a newline rather than sending', async ({ page }) => {
    await open(page, oneConversation);
    const composer = page.getByLabel('Message');
    await composer.fill('first');
    await composer.press('Shift+Enter');
    await expect(composer).toHaveValue(/first/);
    expect((await calls(page)).some((c) => c.cmd === 'send_message')).toBe(false);
  });

  test('a message walks queued to sent to delivered as events arrive', async ({ page }) => {
    await open(page, { ...oneConversation, messages: { [CONVERSATION]: [] } });
    const composer = page.getByLabel('Message');
    await composer.fill('water drop at 06:00');
    await composer.press('Enter');

    const row = page.locator('li.row', { hasText: 'water drop at 06:00' });
    await expect(row).toHaveAttribute('aria-label', /Queued/);

    const id = '1'.padStart(32, '0');
    await emit(page, 'message_status_changed', {
      conversation_id: CONVERSATION,
      message_id: id,
      status: 'sent',
      delivered_at: null,
      attempts: 1,
    });
    await expect(row).toHaveAttribute('aria-label', /Sent/);

    await emit(page, 'message_status_changed', {
      conversation_id: CONVERSATION,
      message_id: id,
      status: 'delivered',
      delivered_at: now + HOUR,
      attempts: 4,
    });
    await expect(row).toHaveAttribute('aria-label', /Delivered/);
  });

  test('a late "sent" does not pull a delivered message backwards', async ({ page }) => {
    // Retransmission makes out-of-order status updates ordinary.
    await open(page, { ...oneConversation, messages: { [CONVERSATION]: [] } });
    const composer = page.getByLabel('Message');
    await composer.fill('hello');
    await composer.press('Enter');
    const id = '1'.padStart(32, '0');
    const row = page.locator('li.row', { hasText: 'hello' });

    await emit(page, 'message_status_changed', {
      conversation_id: CONVERSATION,
      message_id: id,
      status: 'delivered',
      delivered_at: now,
      attempts: 2,
    });
    await expect(row).toHaveAttribute('aria-label', /Delivered/);

    await emit(page, 'message_status_changed', {
      conversation_id: CONVERSATION,
      message_id: id,
      status: 'sent',
      delivered_at: null,
      attempts: 3,
    });
    await expect(row).toHaveAttribute('aria-label', /Delivered/);
  });
});

test.describe('receiving late', () => {
  test('a message that answers an older one lands in causal order, marked', async ({ page }) => {
    await open(page, {
      ...oneConversation,
      messages: {
        [CONVERSATION]: [
          mockMessage({ id: '1'.repeat(32), lamport: 1, text: 'first' }),
          mockMessage({ id: '3'.repeat(32), lamport: 3, text: 'third' }),
        ],
      },
    });
    await expect(page.getByText('third')).toBeVisible();

    const late = mockMessage({
      id: '2'.repeat(32),
      lamport: 2,
      text: 'second, an hour late',
      arrived_late: true,
      sent_at: now - HOUR,
      received_at: now,
    });
    await emit(page, 'message_received', late);

    await expect(page.getByText('second, an hour late')).toBeVisible();
    await expect(page.getByText('arrived out of order')).toBeVisible();

    // Causal order, not arrival order.
    const texts = await page.locator('li.row p.text').allTextContents();
    expect(texts).toEqual(['first', 'second, an hour late', 'third']);
  });

  test('a late message does not move the reading position', async ({ page }) => {
    // The rule the implementation is most likely to break (docs/design.md §4).
    const many = Array.from({ length: 60 }, (_, i) =>
      mockMessage({
        id: String(i + 10)
          .repeat(16)
          .slice(0, 32),
        lamport: (i + 1) * 10,
        text: `message ${i}`,
      }),
    );
    await open(page, { ...oneConversation, messages: { [CONVERSATION]: many } });
    await expect(page.getByText('message 59')).toBeVisible();

    const thread = page.locator('.thread');
    await thread.evaluate((el) => {
      el.scrollTop = el.scrollHeight / 2;
    });
    const before = await thread.evaluate((el) => el.scrollTop);

    await emit(
      page,
      'message_received',
      mockMessage({
        id: 'f'.repeat(32),
        lamport: 5,
        text: 'very old, just arrived',
        arrived_late: true,
      }),
    );
    await expect(page.getByText('very old, just arrived')).toBeAttached();

    const after = await thread.evaluate((el) => el.scrollTop);
    // Inserting above the viewport grows the content; the position must move
    // with it so the same text stays under the user's eye.
    expect(after).toBeGreaterThan(before);
  });

  test('scrolling up stays where it was put', async ({ page }) => {
    // A regression guard. The first implementation read `atEnd` reactively
    // inside the effect that restores the anchor, so the act of scrolling up
    // re-ran the effect with a stale anchor and snapped the view back to the
    // bottom — the thread could not be scrolled at all.
    const many = Array.from({ length: 60 }, (_, i) =>
      mockMessage({
        id: String(i + 10)
          .repeat(16)
          .slice(0, 32),
        lamport: (i + 1) * 10,
        text: `message ${i}`,
      }),
    );
    await open(page, { ...oneConversation, messages: { [CONVERSATION]: many } });
    await expect(page.getByText('message 59')).toBeVisible();

    const thread = page.locator('.thread');
    await expect
      .poll(async () => {
        await thread.evaluate((el) => {
          el.scrollTop = 0;
        });
        return thread.evaluate((el) => el.scrollTop);
      })
      .toBeLessThan(10);

    // Still there a moment later, with nothing having pulled it back.
    await page.waitForTimeout(300);
    expect(await thread.evaluate((el) => el.scrollTop)).toBeLessThan(10);
  });

  test('a message arriving while scrolled up is offered, not forced', async ({ page }) => {
    const many = Array.from({ length: 60 }, (_, i) =>
      mockMessage({
        id: String(i + 10)
          .repeat(16)
          .slice(0, 32),
        lamport: (i + 1) * 10,
        text: `message ${i}`,
      }),
    );
    await open(page, { ...oneConversation, messages: { [CONVERSATION]: many } });
    await expect(page.getByText('message 59')).toBeVisible();
    const thread = page.locator('.thread');
    // The app scrolls to the end itself once loading finishes, so keep
    // scrolling up until it stays there; otherwise this races that.
    await expect
      .poll(
        async () => {
          await thread.evaluate((el) => {
            el.scrollTop = 0;
          });
          return thread.evaluate((el) => el.scrollTop);
        },
        { timeout: 5000 },
      )
      .toBeLessThan(10);
    // Let the scroll handler decide that the user is no longer at the end.
    await page.waitForTimeout(100);

    await emit(
      page,
      'message_received',
      mockMessage({ id: 'f'.repeat(32), lamport: 10_000, text: 'brand new' }),
    );
    await expect(page.getByRole('button', { name: /1 new message/ })).toBeVisible();
  });
});

test.describe('adding a contact', () => {
  test('explains what is wrong with a key rather than just refusing', async ({ page }) => {
    await open(page, oneConversation);
    await page.getByRole('button', { name: 'Add a contact' }).click();
    const field = page.getByLabel('Public key', { exact: true });
    await field.fill('a'.repeat(63));
    await expect(page.getByRole('alert')).toHaveText(/63 characters; a key is 64/);
    await expect(page.getByRole('button', { name: 'Add contact' })).toBeDisabled();

    await field.fill('z'.repeat(64));
    await expect(page.getByRole('alert')).toHaveText(/hexadecimal/);
  });

  test('tolerates whitespace in a pasted key and adds the contact', async ({ page }) => {
    await open(page, oneConversation);
    await page.getByRole('button', { name: 'Add a contact' }).click();
    await page.getByLabel('Public key', { exact: true }).fill(`  ${'ab'.repeat(32)}\n `);
    await page.getByLabel('Name').fill('Wren');
    // No complaint, and the action becomes available.
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Add contact' })).toBeEnabled();
    await page.getByRole('button', { name: 'Add contact' }).click();

    const issued = await calls(page);
    const add = issued.find((c) => c.cmd === 'add_contact');
    expect(add?.args.public_key).toBe('ab'.repeat(32));
    expect(add?.args.display_name).toBe('Wren');
  });

  test('shows your own key as a fingerprint, text and a QR code', async ({ page }) => {
    await open(page, oneConversation);
    await page.getByRole('button', { name: 'Add a contact' }).click();
    await expect(page.getByRole('img', { name: /QR code/ })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy key' })).toBeVisible();
    // The one sentence that explains the whole security model.
    await expect(page.getByText(/over a channel you already trust/).first()).toBeVisible();
  });
});

test.describe('a link going away', () => {
  test('is reported quietly and does not stop the user sending', async ({ page }) => {
    await open(page, oneConversation);
    await emit(page, 'link_status_changed', mockLink({ status: 'down', enabled: true }));
    await expect(page.getByRole('region', { name: 'Link health' })).toContainText('unavailable');
    await expect(page.getByRole('region', { name: 'Link health' })).not.toContainText(
      /disconnect|error|fail/i,
    );

    // The composer is untouched by any of it.
    const composer = page.getByLabel('Message');
    await expect(composer).toBeEnabled();
    await composer.fill('still writing');
    await composer.press('Enter');
    await expect(page.locator('li.row', { hasText: 'still writing' })).toHaveAttribute(
      'aria-label',
      /Queued/,
    );
  });

  test('a long silence from a contact is stated, not alarmed about', async ({ page }) => {
    await open(page, {
      ...oneConversation,
      conversations: [
        mockConversation({
          contact: {
            ...mockConversation().contact,
            last_packet_at: now - 4 * 24 * HOUR,
          },
        }),
      ],
    });
    const header = page.locator('.header');
    await expect(header).toContainText('no packets for 4d');
    await expect(header).not.toContainText(/offline|disconnect|error/i);
  });
});

test.describe('keyboard', () => {
  const two: MockSeed = {
    ...oneConversation,
    conversations: [
      mockConversation(),
      mockConversation({
        conversation_id: 'b'.repeat(32),
        contact: {
          ...mockConversation().contact,
          conversation_id: 'b'.repeat(32),
          display_name: 'Wren',
        },
      }),
    ],
    messages: { [CONVERSATION]: [], ['b'.repeat(32)]: [] },
  };

  test('focuses the composer on load', async ({ page }) => {
    await open(page, oneConversation);
    await expect(page.getByLabel('Message')).toBeFocused();
  });

  test('switches conversations with Ctrl+Arrow', async ({ page }) => {
    await open(page, two);
    await expect(page.locator('.header')).toContainText('Rook');
    await page.keyboard.press('Control+ArrowDown');
    await expect(page.locator('.header')).toContainText('Wren');
    await page.keyboard.press('Control+ArrowUp');
    await expect(page.locator('.header')).toContainText('Rook');
  });

  test('opens the add-contact dialog with Ctrl+N and closes it with Escape', async ({ page }) => {
    await open(page, oneConversation);
    await page.keyboard.press('Control+n');
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toBeHidden();
  });

  test('returns focus to the composer on Escape', async ({ page }) => {
    await open(page, oneConversation);
    await page.locator('.links button').first().focus();
    await page.keyboard.press('Escape');
    await expect(page.getByLabel('Message')).toBeFocused();
  });

  test('drops to the wordmark when the sidebar is too narrow for the lockup', async ({ page }) => {
    // The brand guidelines pick the file by rendered size: below 24px tall a
    // lockup becomes the wordmark alone rather than being shrunk.
    await open(page, oneConversation);
    const header = page.locator('nav header h1 .brand > svg');
    const wide = await header.getAttribute('viewBox');

    const resizer = page.getByRole('separator', { name: /Resize/ });
    await resizer.focus();
    for (let i = 0; i < 12; i += 1) await page.keyboard.press('Shift+ArrowLeft');

    await expect.poll(() => header.getAttribute('viewBox')).not.toBe(wide);
  });

  test('resizes the sidebar from the keyboard', async ({ page }) => {
    // A mouse-only resize is a quiet accessibility failure.
    await open(page, oneConversation);
    const resizer = page.getByRole('separator', { name: /Resize/ });
    await resizer.focus();
    const before = Number(await resizer.getAttribute('aria-valuenow'));
    await page.keyboard.press('ArrowRight');
    const after = Number(await resizer.getAttribute('aria-valuenow'));
    expect(after).toBeGreaterThan(before);
  });
});

test.describe('accessibility', () => {
  test('announces an incoming message politely, once', async ({ page }) => {
    await open(page, oneConversation);
    const region = page.locator('[role="status"][aria-live="polite"]');
    await emit(
      page,
      'message_received',
      mockMessage({ id: '9'.repeat(32), lamport: 9, text: 'hi' }),
    );
    await expect(region).toHaveText('Message from Rook');
  });

  test('does not announce a message merely leaving this device', async ({ page }) => {
    // A screen reader reciting retransmissions would make the app unusable.
    await open(page, oneConversation);
    const region = page.locator('[role="status"][aria-live="polite"]');
    await emit(page, 'message_status_changed', {
      conversation_id: CONVERSATION,
      message_id: '1'.repeat(32),
      status: 'sent',
      delivered_at: null,
      attempts: 9,
    });
    await expect(region).toHaveText('');
  });

  test('gives every message an accessible name carrying its state', async ({ page }) => {
    await open(page, oneConversation);
    const row = page.locator('li.row').first();
    await expect(row).toHaveAttribute('aria-label', /Rook/);
  });

  test('marks the open conversation as current', async ({ page }) => {
    await open(page, oneConversation);
    await expect(page.locator('nav button[aria-current="true"]')).toHaveCount(1);
  });

  test('names its landmarks', async ({ page }) => {
    await open(page, oneConversation);
    await expect(page.getByRole('navigation', { name: 'Conversations' })).toBeVisible();
    await expect(page.getByRole('main')).toBeVisible();
  });
});

test('a backend failure is shown, not swallowed', async ({ page }) => {
  await open(page, {
    failures: { get_identity: { kind: 'storage', message: 'the database is locked' } },
  });
  await expect(page.getByRole('alert')).toHaveText(/the database is locked/);
});
