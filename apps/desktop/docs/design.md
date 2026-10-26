# Interface design

What the app looks like, and why. This document is written before the
interface it describes, and the interface is built from it.

The three documents divide like this: `ipc.md` is the contract between the
halves, `decisions.md` records choices and rejected alternatives, and this one
is about what a person sees and what it means.

---

## 1. The problem this interface actually has

Every messaging app people already know is built on an assumption this one
cannot make: that a message you send arrives in under a second, and that if it
does not, something is wrong.

Here, a message may take an hour. A contact may be unreachable for days. Half
the packets may not arrive. **None of that is a fault**, and an interface that
treats it as one — spinners, red badges, "failed to send", "reconnecting…" —
would be lying to the user several times an hour, and would make a working
system feel broken.

So the whole design follows from one rule:

> **Say what is true, quietly.** The interface's job is to be accurate about
> what has and has not happened, and calm about it. The user decides whether
> that is a problem.

Three consequences that drive most of the decisions below:

1. **Sending cannot be an operation that can fail.** It is a local, durable
   write. The composer never blocks and never shows an error about a link.
2. **Time is not a single number.** When a message was written and when it
   arrived are different facts, and both are sometimes interesting.
3. **Silence is information, not an error state.** "Nothing heard for two
   days" is a sentence the interface must be able to say without alarm.

## 2. Layout

```
┌────────────────────┬──────────────────────────────────────────────┐
│ avianlink      [+] │ Rook                      heard from 3h ago  │  ← thread header
│                    ├──────────────────────────────────────────────┤
│ ● Rook       2h    │                                              │
│   the repeater…    │     are you there                14:02       │
│                    │                                              │
│   Wren       1d    │              yes, on the ridge   14:05  ✓✓   │  ← own message
│   understood       │                                              │
│                    │     the repeater is back up      14:09       │
│                    │     ╰ arrived out of order, 15:21            │
│                    │                                              │
│                    ├──────────────────────────────────────────────┤
│                    │ ┌──────────────────────────────────────────┐ │
│ ─────────────────  │ │ Message                                  │ │  ← composer
│ ▸ Simulated link   │ └──────────────────────────────────────────┘ │
│   up · 32% loss    │                        Enter to send         │
└────────────────────┴──────────────────────────────────────────────┘
```

**Three regions.** A conversation sidebar, the active thread, and a composer
pinned to the bottom of the thread. The link-health panel lives at the bottom
of the sidebar, below a rule — it is ambient information, not a control, and
it belongs where the eye goes last.

**Resizable sidebar.** Dragged by the divider, 12rem to 28rem, remembered
between launches. The divider is also keyboard-operable (focusable, arrow keys
move it 16px at a time), because a mouse-only resize is a quiet accessibility
failure.

**Minimum window 520 × 420.** Below ~640px wide the sidebar stops being a
column and becomes an overlay: the thread fills the window and a back control
appears in its header. There is no separate mobile design — the same layout
narrows, which is what keeps the Tauri mobile targets a port rather than a
rewrite.

**Why not a three-column layout** with contact details on the right: there is
one contact per conversation and about six facts about them. A permanent
column for six facts is a column of mostly whitespace. They go in a popover
from the thread header instead.

## 3. Message state

The single most important thing this interface does differently.

| State     | Icon               | Means                                       | Hover / screen reader                               |
| --------- | ------------------ | ------------------------------------------- | --------------------------------------------------- |
| Queued    | `○` open circle    | Saved on this device. Nothing has gone out. | "Queued — saved on this device, waiting for a link" |
| Sent      | `✓` one tick       | At least one transmission left this device. | "Sent at 14:05 · 3 attempts"                        |
| Delivered | `✓✓` two ticks     | Rook's device acknowledged it.              | "Delivered 14:05 → 15:17, 1h 12m"                   |
| Failed    | `⊘` slashed circle | The engine gave up.                         | "Not sent — it was retried for too long"            |

**Distinguishable without colour.** Each state differs in _shape_, not just in
tone: nothing in the set is distinguished only by colour, and the set still
reads correctly in greyscale. Colour is a second, redundant channel (failed is
the only one that gets a hue, and even then it also has a distinct glyph).

**Why ticks.** They are a chat-app convention and the brief is sceptical of
those. They earn their place: one tick versus two is read at a glance, at
12px, by people who have never read this app's documentation, and the
distinction they encode — left here, versus known to have arrived — is exactly
the distinction that matters most on these links. The restraint is in how
they are drawn: 1.5px strokes in `currentColor`, at the text's own size, with
no fill and no badge.

**Queued is not a failure and must not look like one.** It gets the quietest
treatment of the four: an open circle in `--status-queued`, the faintest tone
in the palette. A message sitting queued for six hours is a normal Tuesday.

**Failed is deliberately almost unreachable.** `avianlink-core` has no "gave
up" event (api-requests AR-003) and arguably should never give up by default,
since a peer silent for days is normal. The state is designed, built and
tested because `FakeEngine` can produce it and because the library may add it;
against the real engine today it will not appear. The interface does not
invent it from a timeout — a message that has been queued for a week is still
_queued_, and saying otherwise would be the exact lie this design exists to
avoid.

**Attempts are available but never shouted.** The retransmission count is in
the hover detail and the accessible name. It is not on screen, because a
number that climbs on its own draws the eye to something the user cannot act
on.

**Announcements.** A single `aria-live="polite"` region announces incoming
messages ("Message from Rook") and terminal status changes (delivered,
failed). It does **not** announce `queued → sent`, and it never announces
attempt counts: a screen reader reciting retransmissions would make the app
unusable on a bad link.

## 4. Order, and messages that arrive late

**Messages are ordered by the library's causal order**, not by arrival time —
`order_key`, which is `(lamport, id)` (see `ipc.md`). A message that overtook
others in the network still sorts where it belongs in the conversation.

**The late marker.** When a message is stored behind messages that were
already in the thread, it carries `arrived_late` and renders a second line
under it, in the faintest tone at `--text-xs`:

```
     the repeater is back up          14:09
     ╰ arrived out of order, 15:21
```

It is a statement of fact placed where the discrepancy is, not a badge. It is
computed once at insert time and never recomputed, because it records _"this
appeared behind something you were looking at"_ — a fact about history, not
about the current sort. A message that was late stays marked after a reload;
a message that merely has a low Lamport value does not acquire the marker.

**`missing_before`.** The library reports how many earlier messages from this
sender have not arrived yet. Where it is non-zero, the thread shows a gap
marker above the message:

```
     ┄┄ 2 earlier messages still on their way ┄┄
```

This is the forward-looking counterpart to the late marker, and it is the
difference between a thread that looks complete-but-odd and one that is honest
about having holes in it.

**Scroll must not move.** This is the rule the implementation is most likely
to break. When content is inserted _above_ the viewport, the user's reading
position must not shift by a pixel.

The implementation anchors from the bottom: before the DOM updates, record
`scrollHeight - scrollTop`; after it, restore `scrollTop = scrollHeight -
recorded`. CSS `overflow-anchor` is not relied on — it is inconsistent across
the WebViews this app ships on, and this behaviour is too important to leave
to a hint.

Two exceptions, both requiring that the user is _already_ at the bottom:

- a message arriving at the end scrolls into view;
- the user's own message always scrolls into view, because they just acted.

If the user has scrolled up, neither happens; instead a quiet "3 new
messages ↓" control appears above the composer. It is a button, so it is
keyboard-reachable.

## 5. Two times

`sent_at` is when the sender says they wrote it. `received_at` is when it got
here. On these links they can differ by hours.

**The rule:**

- Show `sent_at` alone when the gap is below the threshold (default 5 minutes,
  a setting because the right value depends entirely on the link).
- Show both when the gap is above it: `14:09 · arrived 15:21`.
- Show `received_at` alone, labelled "arrived", when the sender has no wall
  clock at all (`sent_at` is null — the library allows a host with no RTC to
  omit it entirely). Hovering explains that the sender's device has no clock,
  because "arrived 15:21" with no send time is otherwise just confusing.
- Our own messages show their queue time, which is the only time we have.

**Relative or absolute?** Absolute times in the thread (`14:09`), relative
times in the sidebar and link panel (`2h`, `3 days`). The thread is a record
and wants stable values that do not change while you look at them; the sidebar
is a status display and wants "how stale is this". Full absolute timestamps,
with the date, are in the hover detail everywhere.

Day separators (`Tuesday 14 October`) break the thread up. With hour-scale
delivery, a thread can contain a day boundary between two messages that were
_written_ minutes apart, so separators use the send time and the out-of-order
marker carries the rest of the story.

## 6. Link health

A small panel at the bottom of the sidebar. **The tone is the whole design
problem here**: this panel will spend most of its life reporting things that
would read as catastrophic in any other app, and it has to not do that.

```
  ▸ Simulated link
    up · 32% loss · sent 2m ago
```

Per link: a state glyph, the label, and a short clause. The vocabulary:

| Situation                   | Says                | Never says              |
| --------------------------- | ------------------- | ----------------------- |
| Usable                      | "up"                | "connected", "online"   |
| Bind failed, interface gone | "unavailable"       | "disconnected", "error" |
| User switched it off        | "off"               | "disabled", "inactive"  |
| Pacing budget exhausted     | "paced until 14:02" | "blocked", "throttled"  |
| Loss measured               | "32% loss"          | —                       |
| Loss not measurable         | _omitted_           | "0% loss"               |

That last row matters. `recent_loss_permille` is `null` against the real
engine (AR-007) and `null` must render as _absent_, never as zero — claiming a
perfect link because nothing measured it is the worst available failure.

**Expanding a link** reveals packets and bytes in and out, MTU, and the last
send and receive times. Collapsed by default: six numbers per link is a
diagnostic, not a dashboard.

**Per-contact silence** belongs in the thread header, not here, because it is a
fact about a person rather than about a radio: "heard from Rook 3h ago". After
a day it becomes "heard from Rook yesterday", and after that "no packets for
4 days" — still neutral, still just a statement.

**Nothing in this panel animates, blinks, or changes colour to attract
attention.** A link going down is a text change.

## 7. Adding a contact

One dialog, two halves, because the operation is inherently two-sided.

**Your key.** A QR code, the full key as selectable monospace text with a copy
button, and the fingerprint in its five groups. The QR encodes the bare
64-character hex key — not a URL, not JSON. Anything cleverer is a
compatibility problem with the CLI and with whatever reads it on a phone.

**Their key.** A textarea that accepts a pasted key, tolerating surrounding
whitespace and newlines, with live validation that says what is wrong
("that is 63 characters; a key is 64") rather than just refusing. A name
field. And a checkbox:

> ☐ I compared the fingerprint with Rook directly

**The one sentence.** Above the fingerprint:

> Read these five groups aloud to each other over a channel you already
> trust — anyone who can change messages in transit can also swap the key.

That is the entire security model of contact addition, stated once, where the
decision is being made.

**Verification is not a gate.** An unverified contact works exactly like a
verified one and shows a small, neutral "unverified" marker in the thread
header, with the checkbox reachable from there. On these links, arranging an
out-of-band comparison may genuinely take days, and an app that refused to
queue messages until then would be useless. Verification is a claim the user
records, not a permission the app grants.

**QR scanning is not here.** It needs a camera, which is a mobile concern. The
dialog is laid out so that a "Scan" control fits beside "Paste" later without
rearrangement.

## 8. Settings

Three sections, one page, no tabs.

**Identity** — fingerprint, the public key with a copy button, the QR code,
and a display name that is explicitly local ("only you see this; it is never
sent").

**Links** — per link: on/off, and for UDP, the local port and a list of peer
addresses mapped to contacts. For the simulated link: the impairment profile
and its knobs, which is how a reviewer drives the interface through every
state on demand.

**Reset local data** — last, under a rule, in the quietest styling the app
has. It deletes history, contacts, settings and the identity key. Confirmation
is a dialog that states exactly what is lost including _"your identity key —
your contacts will no longer recognise you"_, and requires typing `reset`.
Type-to-confirm rather than a second button, because this is the one action in
the app with no undo.

## 9. Keyboard

Everything is reachable without a mouse.

| Key                | Does                                          |
| ------------------ | --------------------------------------------- |
| `Enter`            | Send                                          |
| `Shift+Enter`      | Newline                                       |
| `Esc`              | Close a dialog; otherwise focus the composer  |
| `Ctrl/Cmd+↑` / `↓` | Previous / next conversation                  |
| `Ctrl/Cmd+N`       | Add a contact                                 |
| `Ctrl/Cmd+,`       | Settings                                      |
| `Tab`              | Sidebar → thread → composer, in reading order |

`Ctrl/Cmd+↑/↓` rather than bare arrows: bare arrows belong to whatever has
focus, and stealing them from the composer or the thread would be worse than
having no shortcut.

The composer holds focus by default, because that is what the user is almost
always about to use.

## 10. Accessibility

- **Semantic structure.** `<nav>` for the sidebar, `<main>` for the thread,
  `<form>` for the composer. The conversation list is a `<ul>` of buttons with
  `aria-current="true"` on the active one. The thread is an `<ol>` of `<li>`.
- **Accessible names carry the meaning that is visually encoded.** A message's
  name is "From Rook, 14:09, arrived out of order at 15:21" or "You, 14:05,
  delivered after 1 hour 12 minutes". The tick glyphs are `aria-hidden`; the
  state reaches a screen reader as words.
- **One polite live region**, used sparingly (§3).
- **Focus is always visible**: one 2px outline rule, applied globally via
  `:focus-visible`, never removed.
- **Contrast meets WCAG AA** in both themes, including the muted and faint
  text tones against both `--bg` and `--bg-raised`. The token pairs are
  checked by a test rather than by eye, because "faint" is exactly the token
  most likely to drift below 4.5:1.
- **Reduced motion** is honoured globally; there is very little motion to
  reduce.
- **Text selection** is off for chrome and on for content — message text,
  keys, fingerprints and addresses are all selectable.

## 11. Visual style

One sans-serif stack (the platform's own UI face), one monospace stack for
keys and fingerprints. Three sizes, two weights. No gradients, no shadows
beyond a single 1px card edge, no emoji, no avatars, no bubbles.

**Why no bubbles.** Alignment already encodes direction — own messages are
right-aligned with a tighter left margin, incoming are left-aligned. Bubbles
would add a border and a fill around every message to encode the same thing
twice, and they cost horizontal space that long text and the out-of-order
markers need. The one thing bubbles do well — making a long run of alternating
short messages scannable — is handled by the alignment and the timestamp
column instead.

**One accent**, used for exactly two things: the focus ring, and the active
conversation. Status colours are desaturated by design (§3).

**Light and dark follow the OS**, defined entirely by the tokens in
`app.css`. No manual theme switch: the OS already has one, and a second one
that disagrees with it is a bug generator.

## 12. What is deliberately not in Phase 1

- **Virtualized thread and backend pagination** — Phase 2. Phase 1 loads the
  most recent page and the design above is written so that virtualizing it
  later changes no visual decision.
- **Search.** Not in the brief, and it is a backend feature (full-text over
  SQLite) more than an interface one.
- **Group conversations.** The library is one-to-one.
- **Attachments.** The library carries text.
