<!--
  The app shell: layout, keyboard, and the wiring between backend events and
  the state object. Everything visual lives in `lib/components`.
-->
<script lang="ts">
  import { onMount, tick } from 'svelte';

  import AddContactDialog from './lib/components/AddContactDialog.svelte';
  import Composer from './lib/components/Composer.svelte';
  import SettingsDialog from './lib/components/SettingsDialog.svelte';
  import Sidebar from './lib/components/Sidebar.svelte';
  import Thread from './lib/components/Thread.svelte';
  import ThreadHeader from './lib/components/ThreadHeader.svelte';
  import Brand from './lib/components/Brand.svelte';
  import { commands, subscribe, type Settings } from './lib/ipc/client';
  import { AppState } from './lib/state.svelte';

  const SIDEBAR_MIN = 192;
  const SIDEBAR_MAX = 448;
  const SIDEBAR_KEY = 'avianlink.sidebarWidth';
  /** Below this the sidebar stops being a column (docs/design.md §2). */
  const NARROW_PX = 640;

  const app = new AppState();

  let sidebarWidth = $state(272);
  let windowWidth = $state(1040);
  let narrow = $derived(windowWidth < NARROW_PX);
  /** On narrow widths the sidebar is an overlay, shown on demand. */
  let showSidebar = $state(false);

  let addingContact = $state(false);
  let showSettings = $state(false);
  let atEnd = $state(true);

  let thread = $state<ReturnType<typeof Thread> | null>(null);
  let composer = $state<ReturnType<typeof Composer> | null>(null);

  let selected = $derived(app.selected);

  async function openConversation(conversationId: string) {
    await app.select(conversationId);
    showSidebar = false;
    await tick();
    thread?.scrollToEnd();
    composer?.focus();
  }

  async function send(text: string) {
    await app.send(text);
    // The user just acted, so their own message always comes into view.
    await tick();
    thread?.scrollToEnd('smooth');
    app.unseenBelow = 0;
  }

  async function addContact(publicKey: string, displayName: string, verified: boolean) {
    const contact = await app.guard(() =>
      commands.addContact({ public_key: publicKey, display_name: displayName, verified }),
    );
    if (!contact) return false;
    await app.refreshSummaries();
    await openConversation(contact.conversation_id);
    addingContact = false;
    return true;
  }

  async function addSimulatedContact(displayName: string) {
    const contact = await app.guard(() =>
      commands.addSimulatedContact({ display_name: displayName, history: 3 }),
    );
    if (!contact) return false;
    await app.refreshSummaries();
    await openConversation(contact.conversation_id);
    addingContact = false;
    return true;
  }

  async function saveSettings(settings: Settings) {
    const stored = await app.guard(() => commands.setSettings({ settings }));
    if (stored) app.settings = stored;
    showSettings = false;
  }

  async function resetLocalData() {
    await app.guard(() => commands.resetLocalData());
    showSettings = false;
    app.selectedId = null;
    app.messages = [];
    await app.load();
  }

  async function setVerified(verified: boolean) {
    if (!selected) return;
    const contact = await app.guard(() =>
      commands.setContactVerified({ conversation_id: selected.conversation_id, verified }),
    );
    if (contact) app.onContactChanged(contact);
  }

  async function toggleLink(id: number, enabled: boolean) {
    const link = await app.guard(() => commands.setLinkEnabled({ id, enabled }));
    if (link) app.onLinkChanged(link);
  }

  /** Moves the selection by `delta` conversations, wrapping at neither end. */
  function step(delta: number) {
    const index = app.conversations.findIndex((c) => c.conversation_id === app.selectedId);
    const next = Math.min(Math.max(index + delta, 0), app.conversations.length - 1);
    const target = app.conversations[next];
    if (target && target.conversation_id !== app.selectedId) {
      void openConversation(target.conversation_id);
    }
  }

  function onKeydown(event: KeyboardEvent) {
    const modifier = event.metaKey || event.ctrlKey;
    if (modifier && event.key === 'ArrowUp') {
      event.preventDefault();
      step(-1);
    } else if (modifier && event.key === 'ArrowDown') {
      event.preventDefault();
      step(1);
    } else if (modifier && event.key.toLowerCase() === 'n') {
      event.preventDefault();
      addingContact = true;
    } else if (modifier && event.key === ',') {
      event.preventDefault();
      showSettings = true;
    } else if (event.key === 'Escape' && !addingContact && !showSettings) {
      composer?.focus();
    }
  }

  /** Keyboard-operable sidebar resize; a mouse-only one is an a11y failure. */
  function onResizerKeydown(event: KeyboardEvent) {
    const step = event.shiftKey ? 48 : 16;
    if (event.key === 'ArrowLeft') {
      event.preventDefault();
      setSidebarWidth(sidebarWidth - step);
    } else if (event.key === 'ArrowRight') {
      event.preventDefault();
      setSidebarWidth(sidebarWidth + step);
    }
  }

  function setSidebarWidth(px: number) {
    sidebarWidth = Math.min(Math.max(px, SIDEBAR_MIN), SIDEBAR_MAX);
    try {
      localStorage.setItem(SIDEBAR_KEY, String(sidebarWidth));
    } catch {
      // A WebView with storage disabled is not a reason to fail a drag.
    }
  }

  function startResize(event: PointerEvent) {
    event.preventDefault();
    const move = (moveEvent: PointerEvent) => setSidebarWidth(moveEvent.clientX);
    const stop = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', stop);
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', stop);
  }

  onMount(() => {
    windowWidth = window.innerWidth;
    const onResize = () => (windowWidth = window.innerWidth);
    window.addEventListener('resize', onResize);

    try {
      const stored = Number(localStorage.getItem(SIDEBAR_KEY));
      if (Number.isFinite(stored) && stored > 0) sidebarWidth = stored;
    } catch {
      // Ignore; the default is fine.
    }

    app.startClock();
    void app.load().then(async () => {
      await tick();
      thread?.scrollToEnd();
      composer?.focus();
    });

    const unsubscribe = subscribe({
      messageReceived: (message) => {
        app.onMessageReceived(message, atEnd);
        if (atEnd && message.conversation_id === app.selectedId) {
          void tick().then(() => thread?.scrollToEnd('smooth'));
        }
      },
      messageStatusChanged: (change) => app.onStatusChanged(change),
      linkStatusChanged: (link) => app.onLinkChanged(link),
      contactChanged: (contact) => app.onContactChanged(contact),
    });

    return () => {
      window.removeEventListener('resize', onResize);
      app.stopClock();
      unsubscribe();
    };
  });
</script>

<svelte:window onkeydown={onKeydown} />

<div class="app" class:narrow>
  {#if !narrow || showSidebar}
    <div class="sidebar-slot" style={narrow ? '' : `width:${sidebarWidth}px`}>
      <Sidebar
        conversations={app.conversations}
        links={app.links}
        selectedId={app.selectedId}
        now={app.now}
        onSelect={openConversation}
        onAddContact={() => (addingContact = true)}
        onSettings={() => (showSettings = true)}
        onToggleLink={toggleLink}
        width={narrow ? windowWidth : sidebarWidth}
      />
    </div>
  {/if}

  {#if !narrow}
    <!-- A focusable separator is the ARIA splitter pattern: it is operable
         with the arrow keys, so it is interactive by design. -->
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div
      class="resizer"
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize the conversation list"
      aria-valuenow={sidebarWidth}
      aria-valuemin={SIDEBAR_MIN}
      aria-valuemax={SIDEBAR_MAX}
      tabindex="0"
      onpointerdown={startResize}
      onkeydown={onResizerKeydown}
    ></div>
  {/if}

  <main class="main">
    {#if app.problem}
      <p class="problem" role="alert">{app.problem.message}</p>
    {/if}

    {#if selected}
      <ThreadHeader
        contact={selected.contact}
        now={app.now}
        {narrow}
        onBack={() => (showSidebar = true)}
        onVerifiedChange={setVerified}
      />
      <Thread
        bind:this={thread}
        messages={app.messages}
        senderName={selected.contact.display_name}
        receiveThresholdMs={app.receiveTimeThresholdMs}
        now={app.now}
        hasMore={app.hasMore}
        insertedAbove={app.insertedAbove}
        unseenBelow={app.unseenBelow}
        onLoadOlder={() => void app.loadOlder()}
        onAtEndChange={(value) => {
          atEnd = value;
          if (value) {
            app.unseenBelow = 0;
            void app.markRead();
          }
        }}
      />
      <Composer bind:this={composer} onSend={send} />
    {:else if app.loading}
      <div class="placeholder"><p>Loading…</p></div>
    {:else}
      <div class="placeholder">
        <!-- 112px wide: the full mark's 14 fine lines need 96px or more
             before they stop blurring into each other. -->
        <Brand variant="mark" size={112} />
        <h2>No conversation open</h2>
        <p>
          Add a contact to start one. Messages are saved here and go out whenever a link can carry
          them.
        </p>
        <button type="button" class="primary" onclick={() => (addingContact = true)}>
          Add a contact
        </button>
      </div>
    {/if}
  </main>
</div>

<!-- One polite live region for the whole app (docs/design.md §10). -->
<div class="visually-hidden" role="status" aria-live="polite">{app.announcement}</div>

{#if addingContact}
  <AddContactDialog
    open={addingContact}
    identity={app.identity}
    simulated={app.simulated}
    onClose={() => (addingContact = false)}
    onAdd={addContact}
    onAddSimulated={addSimulatedContact}
  />
{/if}

{#if showSettings}
  <SettingsDialog
    open={showSettings}
    identity={app.identity}
    settings={app.settings}
    links={app.links}
    onClose={() => (showSettings = false)}
    onSave={saveSettings}
    onReset={resetLocalData}
  />
{/if}

<style>
  .app {
    display: flex;
    height: 100%;
    min-height: 0;
  }

  .sidebar-slot {
    flex: none;
    min-width: 0;
    height: 100%;
  }

  .narrow .sidebar-slot {
    position: absolute;
    inset: 0;
    width: 100%;
    z-index: 2;
  }

  .resizer {
    flex: none;
    width: 5px;
    margin-left: -3px;
    cursor: col-resize;
    background: transparent;
  }

  .resizer:hover,
  .resizer:focus-visible {
    background: var(--accent-soft);
  }

  .main {
    position: relative;
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    min-height: 0;
  }

  .problem {
    margin: var(--space-3) var(--space-5) 0;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--status-failed);
    border-radius: var(--radius-md);
    color: var(--status-failed);
    font-size: var(--text-sm);
  }

  .placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--space-3);
    flex: 1;
    padding: var(--space-6);
    color: var(--text-muted);
    text-align: center;
  }

  .placeholder h2 {
    color: var(--text);
  }

  /* The mark sits quietly above the text rather than competing with it. */
  .placeholder :global(.brand) {
    color: var(--text-faint);
    margin-bottom: var(--space-2);
  }

  .placeholder p {
    max-width: 26rem;
    margin: 0;
  }

  .primary {
    padding: var(--space-2) var(--space-4);
    background: var(--accent);
    color: var(--accent-text);
    border: 0;
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }
</style>
