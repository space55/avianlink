/**
 * The only module that talks to the backend.
 *
 * Types come from `bindings.ts`, which is generated from `src-tauri/src/ipc.rs`
 * — never edit that file. This module adds the thin layer the generator does
 * not produce: the command names, the `{ args }` envelope the Rust side
 * expects, and typed event subscriptions.
 *
 * The contract, including what each command may fail with, is in
 * `apps/desktop/docs/ipc.md`.
 *
 * Everything the UI shows must be reachable through `commands`. `events` is a
 * cache-coherence mechanism on top: the app would still be correct, just
 * sleepier, if every event were dropped.
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

import type {
  AddContactArgs,
  ConfigureLinkArgs,
  Contact,
  ConversationSummary,
  GetMessagesArgs,
  Identity,
  IpcError,
  IpcErrorKind,
  Link,
  MarkReadArgs,
  Message,
  MessagePage,
  MessageStatusChanged,
  SendMessageArgs,
  SetContactVerifiedArgs,
  SetLinkEnabledArgs,
  SetSettingsArgs,
  Settings,
} from './bindings';

export type * from './bindings';

/** Every command name, matching the Rust `command_handlers!` list. */
export const COMMAND_NAMES = [
  'get_identity',
  'list_contacts',
  'add_contact',
  'list_conversations',
  'get_messages',
  'send_message',
  'list_links',
  'configure_link',
  'set_link_enabled',
  'mark_conversation_read',
  'set_contact_verified',
  'get_settings',
  'set_settings',
  'reset_local_data',
] as const;

/** Every event name, matching `events::ALL` in Rust. */
export const EVENT_NAMES = [
  'message_received',
  'message_status_changed',
  'link_status_changed',
  'contact_changed',
] as const;

const ERROR_KINDS: readonly IpcErrorKind[] = [
  'bad_request',
  'not_found',
  'conflict',
  'limit',
  'storage',
  'engine',
  'internal',
];

/** Whether a thrown value is a structured error from the backend. */
export function isIpcError(value: unknown): value is IpcError {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<IpcError>;
  return (
    typeof candidate.message === 'string' &&
    typeof candidate.kind === 'string' &&
    (ERROR_KINDS as readonly string[]).includes(candidate.kind)
  );
}

/**
 * Normalises anything the IPC layer can throw into an `IpcError`.
 *
 * A command can reject with a value that is not one of ours — a panic in the
 * backend, or a Tauri-level failure such as a command that is not registered.
 * Those must still reach the UI as something it can display, rather than as
 * `[object Object]`.
 */
export function toIpcError(value: unknown): IpcError {
  if (isIpcError(value)) return value;
  const message =
    value instanceof Error
      ? value.message
      : typeof value === 'string'
        ? value
        : JSON.stringify(value);
  return { kind: 'internal', message: message || 'the backend failed without an explanation' };
}

async function call<T>(command: string, args?: unknown): Promise<T> {
  try {
    // Commands with arguments take a single `args` object, so that adding an
    // optional field is never a breaking change (docs/ipc.md).
    return await invoke<T>(command, args === undefined ? undefined : { args });
  } catch (error) {
    throw toIpcError(error);
  }
}

export const commands = {
  getIdentity: () => call<Identity>('get_identity'),
  listContacts: () => call<Contact[]>('list_contacts'),
  addContact: (args: AddContactArgs) => call<Contact>('add_contact', args),
  listConversations: () => call<ConversationSummary[]>('list_conversations'),
  getMessages: (args: GetMessagesArgs) => call<MessagePage>('get_messages', args),
  sendMessage: (args: SendMessageArgs) => call<Message>('send_message', args),
  listLinks: () => call<Link[]>('list_links'),
  configureLink: (args: ConfigureLinkArgs) => call<Link>('configure_link', args),
  setLinkEnabled: (args: SetLinkEnabledArgs) => call<Link>('set_link_enabled', args),
  markConversationRead: (args: MarkReadArgs) => call<void>('mark_conversation_read', args),
  setContactVerified: (args: SetContactVerifiedArgs) => call<Contact>('set_contact_verified', args),
  getSettings: () => call<Settings>('get_settings'),
  setSettings: (args: SetSettingsArgs) => call<Settings>('set_settings', args),
  resetLocalData: () => call<void>('reset_local_data'),
};

/** Handlers for the backend's events. All optional. */
export interface EventHandlers {
  messageReceived?: (message: Message) => void;
  messageStatusChanged?: (change: MessageStatusChanged) => void;
  linkStatusChanged?: (link: Link) => void;
  contactChanged?: (contact: Contact) => void;
}

/**
 * Subscribes to backend events. Returns a function that unsubscribes all of
 * them.
 *
 * Subscriptions are set up concurrently but the returned disposer is safe to
 * call before they have finished attaching: a component that mounts and
 * unmounts quickly must not leak a listener.
 */
export function subscribe(handlers: EventHandlers): () => void {
  const pending: Promise<UnlistenFn>[] = [];
  let disposed = false;

  const add = <T>(name: string, handler: ((payload: T) => void) | undefined) => {
    if (!handler) return;
    pending.push(listen<T>(name, (event) => handler(event.payload)));
  };

  add<Message>('message_received', handlers.messageReceived);
  add<MessageStatusChanged>('message_status_changed', handlers.messageStatusChanged);
  add<Link>('link_status_changed', handlers.linkStatusChanged);
  add<Contact>('contact_changed', handlers.contactChanged);

  return () => {
    disposed = true;
    for (const subscription of pending) {
      void subscription.then((unlisten) => {
        if (disposed) unlisten();
      });
    }
  };
}
