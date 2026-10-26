import { expect, test, type Page } from '@playwright/test';

import {
  CONVERSATION,
  FINGERPRINT,
  mockBackendScript,
  mockConversation,
  mockMessage,
  type MockSeed,
} from './mock-backend';

/** Loads the app with a mocked backend. */
async function open(page: Page, seed: MockSeed = {}) {
  await page.addInitScript(mockBackendScript(seed));
  await page.goto('/');
}

/** The commands the page has issued so far. */
async function calls(page: Page): Promise<{ cmd: string; args: unknown }[]> {
  return page.evaluate(() => (window as unknown as { __calls: never[] }).__calls);
}

test('shows the identity fingerprint on launch', async ({ page }) => {
  await open(page);
  await expect(page.getByText(FINGERPRINT)).toBeVisible();
});

test('an account with no contacts explains itself rather than showing nothing', async ({
  page,
}) => {
  await open(page);
  await expect(page.getByText(/No contacts yet/i)).toBeVisible();
});

test('lists conversations and opens the first one', async ({ page }) => {
  await open(page, {
    conversations: [mockConversation()],
    messages: { [CONVERSATION]: [mockMessage({ text: 'are you there' })] },
  });
  await expect(page.getByRole('button', { name: /Rook/ })).toBeVisible();
  await expect(page.getByText('are you there')).toBeVisible();
});

test('sending clears the composer immediately and shows the message as queued', async ({
  page,
}) => {
  // The composer must never block: sending means "queued", and from the
  // user's point of view it always succeeds instantly.
  await open(page, {
    conversations: [mockConversation()],
    messages: { [CONVERSATION]: [] },
  });
  const composer = page.getByLabel('Message');
  await composer.fill('on my way');
  await page.getByRole('button', { name: 'Send' }).click();

  await expect(composer).toHaveValue('');
  await expect(page.getByText('on my way')).toBeVisible();
  await expect(page.getByText('(queued)')).toBeVisible();

  const issued = await calls(page);
  expect(issued.some((call) => call.cmd === 'send_message')).toBe(true);
});

test('a message that arrives later appears without a reload', async ({ page }) => {
  await open(page, {
    conversations: [mockConversation()],
    messages: { [CONVERSATION]: [mockMessage({ text: 'first', lamport: 1 })] },
  });
  await expect(page.getByText('first')).toBeVisible();

  // The backend stores it, then announces it. The frontend must react to the
  // event; it is never allowed to poll for this.
  await page.evaluate(
    ({ conversation, late }) => {
      const win = window as unknown as {
        __setState: (patch: unknown) => void;
        __emit: (event: string, payload: unknown) => void;
      };
      win.__setState({ messages: { [conversation]: late } });
      win.__emit('message_received', late[1]);
    },
    {
      conversation: CONVERSATION,
      late: [
        mockMessage({ text: 'first', lamport: 1 }),
        mockMessage({
          text: 'sent an hour ago',
          lamport: 2,
          id: '2'.repeat(32),
          arrived_late: true,
        }),
      ],
    },
  );

  await expect(page.getByText('sent an hour ago')).toBeVisible();
});

test('a link that is down is reported, calmly', async ({ page }) => {
  await open(page, {
    links: [
      {
        id: 1,
        label: 'Simulated link',
        kind: 'fake',
        enabled: true,
        status: 'down',
        mtu: 1200,
        config: { kind: 'fake', profile: 'clean' },
        packets_sent: 12,
        packets_received: 3,
        bytes_sent: 900,
        bytes_received: 210,
        recent_loss_permille: 400,
        last_sent_at: null,
        last_received_at: null,
        budget_blocked_until: null,
      },
    ],
  });
  await expect(page.getByText(/Simulated link.*down/)).toBeVisible();
});

test('a backend failure is shown to the user, not swallowed', async ({ page }) => {
  await open(page, {
    failures: { get_identity: { kind: 'storage', message: 'the database is locked' } },
  });
  await expect(page.getByRole('alert')).toHaveText(/the database is locked/);
});
