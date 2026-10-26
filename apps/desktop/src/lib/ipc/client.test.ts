import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();
const listen = vi.fn();

vi.mock('@tauri-apps/api/core', () => ({ invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock('@tauri-apps/api/event', () => ({ listen: (...args: unknown[]) => listen(...args) }));

const { COMMAND_NAMES, EVENT_NAMES, commands, isIpcError, subscribe, toIpcError } =
  await import('./client');

beforeEach(() => {
  invoke.mockReset().mockResolvedValue(undefined);
  listen.mockReset().mockResolvedValue(() => {});
});

describe('command envelope', () => {
  it('wraps arguments in `args`, because the Rust side takes one named struct', async () => {
    await commands.sendMessage({ conversation_id: 'a'.repeat(32), text: 'hello' });
    expect(invoke).toHaveBeenCalledWith('send_message', {
      args: { conversation_id: 'a'.repeat(32), text: 'hello' },
    });
  });

  it('sends no envelope for commands that take no arguments', async () => {
    await commands.getIdentity();
    // `{ args: undefined }` is not the same as no second argument: Tauri would
    // try to deserialise an absent field into the command's parameter.
    expect(invoke).toHaveBeenCalledWith('get_identity', undefined);
  });

  it('exposes exactly the commands the backend registers', () => {
    const called = new Set<string>();
    invoke.mockImplementation((name: string) => {
      called.add(name);
      return Promise.resolve(undefined);
    });
    const args = { conversation_id: 'a'.repeat(32) } as never;
    void Promise.all(Object.values(commands).map((command) => command(args)));
    return Promise.resolve().then(() => {
      expect([...called].sort()).toEqual([...COMMAND_NAMES].sort());
    });
  });
});

describe('error normalisation', () => {
  it('passes a structured backend error through unchanged', async () => {
    const failure = { kind: 'limit', message: 'outbox full' };
    invoke.mockRejectedValue(failure);
    await expect(commands.listLinks()).rejects.toEqual(failure);
  });

  it('turns an unstructured failure into an internal error the UI can show', () => {
    expect(toIpcError(new Error('boom'))).toEqual({ kind: 'internal', message: 'boom' });
    expect(toIpcError('plain string')).toEqual({ kind: 'internal', message: 'plain string' });
    // The worst case: something with no message at all still has to render.
    expect(toIpcError(undefined).message).not.toBe('');
  });

  it('does not mistake an arbitrary object for a backend error', () => {
    expect(isIpcError({ kind: 'nonsense', message: 'x' })).toBe(false);
    expect(isIpcError({ kind: 'limit' })).toBe(false);
    expect(isIpcError(null)).toBe(false);
    expect(isIpcError({ kind: 'limit', message: 'x' })).toBe(true);
  });
});

describe('event subscription', () => {
  it('subscribes only to the events it was given a handler for', () => {
    subscribe({ messageReceived: () => {} });
    expect(listen).toHaveBeenCalledTimes(1);
    expect(listen.mock.calls[0][0]).toBe('message_received');
  });

  it('knows every event name the backend emits', () => {
    listen.mockClear();
    subscribe({
      messageReceived: () => {},
      messageStatusChanged: () => {},
      linkStatusChanged: () => {},
      contactChanged: () => {},
    });
    const names = listen.mock.calls.map((call) => call[0]);
    expect(names.sort()).toEqual([...EVENT_NAMES].sort());
  });

  it('delivers the payload rather than the event envelope', () => {
    const seen: unknown[] = [];
    subscribe({ messageReceived: (message) => seen.push(message) });
    const handler = listen.mock.calls[0][1] as (event: { payload: unknown }) => void;
    handler({ payload: { id: 'abc' } });
    expect(seen).toEqual([{ id: 'abc' }]);
  });

  it('unsubscribes a listener that attaches after the component has gone', async () => {
    // A component that mounts and unmounts in the same tick must not leak a
    // listener: `listen` is async, so the disposer usually runs first.
    const unlisten = vi.fn();
    let resolveListen: (value: () => void) => void = () => {};
    listen.mockReturnValue(
      new Promise<() => void>((resolve) => {
        resolveListen = resolve;
      }),
    );
    const dispose = subscribe({ messageReceived: () => {} });
    dispose();
    resolveListen(unlisten);
    await Promise.resolve();
    await Promise.resolve();
    expect(unlisten).toHaveBeenCalled();
  });
});
