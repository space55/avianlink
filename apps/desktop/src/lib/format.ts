/**
 * Time and number formatting.
 *
 * `docs/design.md` §5 is specific about this, because on these links the
 * difference between "when it was written" and "when it got here" is often
 * hours and the interface has to be exact about which one it is showing.
 *
 * The split: **absolute** times in the thread, which is a record and wants
 * values that do not change while you look at them; **relative** times in the
 * sidebar and link panel, which are status displays and want "how stale is
 * this".
 *
 * Relative labels are terse English and are not localised. The app is
 * English-only for now; `Intl.RelativeTimeFormat` produces "2 hours ago",
 * which is the wrong register and too wide for the sidebar.
 */

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Formatting options, so tests are not at the mercy of the host timezone. */
export interface TimeOptions {
  locale?: string;
  timeZone?: string;
}

/** `14:09` — the time of day, for the thread. */
export function clockTime(ms: number, options: TimeOptions = {}): string {
  return new Date(ms).toLocaleTimeString(options.locale ?? undefined, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: options.timeZone,
  });
}

/** `Tuesday 14 October` — a day separator. */
export function daySeparator(ms: number, now: number, options: TimeOptions = {}): string {
  if (isSameDay(ms, now, options)) return 'Today';
  if (isSameDay(ms, now - DAY, options)) return 'Yesterday';
  const sameYear = new Date(ms).getFullYear() === new Date(now).getFullYear();
  return new Date(ms).toLocaleDateString(options.locale ?? undefined, {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: sameYear ? undefined : 'numeric',
    timeZone: options.timeZone,
  });
}

/** The full stamp used in hover detail: date, time and seconds. */
export function fullTime(ms: number, options: TimeOptions = {}): string {
  return new Date(ms).toLocaleString(options.locale ?? undefined, {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZone: options.timeZone,
  });
}

/** Whether two instants fall on the same calendar day. */
export function isSameDay(a: number, b: number, options: TimeOptions = {}): boolean {
  const key = (ms: number) =>
    new Date(ms).toLocaleDateString('en-CA', { timeZone: options.timeZone });
  return key(a) === key(b);
}

/**
 * `2m`, `3h`, `yesterday`, `4d` — how long ago, tersely.
 *
 * Under a minute reads "just now" rather than "0m", because a counter that
 * sits at zero for sixty seconds looks broken. Beyond a week it switches to
 * weeks: on these links "23d" is a number nobody reads, and "3w" is the
 * actual fact being communicated.
 */
export function relativeTime(ms: number, now: number): string {
  const elapsed = now - ms;
  if (elapsed < 0) return 'just now';
  if (elapsed < MINUTE) return 'just now';
  if (elapsed < HOUR) return `${Math.floor(elapsed / MINUTE)}m`;
  if (elapsed < DAY) return `${Math.floor(elapsed / HOUR)}h`;
  if (elapsed < 2 * DAY) return 'yesterday';
  if (elapsed < 7 * DAY) return `${Math.floor(elapsed / DAY)}d`;
  return `${Math.floor(elapsed / (7 * DAY))}w`;
}

/**
 * `1h 12m` — an elapsed duration, for time-to-delivery.
 *
 * Two units at most. "1h 12m 33s" is a stopwatch reading, and the question
 * being answered is "roughly how long did that take".
 */
export function duration(ms: number): string {
  if (ms < 0) return '0s';
  if (ms < MINUTE) return `${Math.max(1, Math.round(ms / SECOND))}s`;
  if (ms < HOUR) {
    const minutes = Math.floor(ms / MINUTE);
    const seconds = Math.floor((ms % MINUTE) / SECOND);
    return seconds > 0 ? `${minutes}m ${seconds}s` : `${minutes}m`;
  }
  if (ms < DAY) {
    const hours = Math.floor(ms / HOUR);
    const minutes = Math.floor((ms % HOUR) / MINUTE);
    return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
  }
  const days = Math.floor(ms / DAY);
  const hours = Math.floor((ms % DAY) / HOUR);
  return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
}

/**
 * How long ago we last heard from a contact, phrased so that a long silence
 * does not read as a fault.
 *
 * `docs/design.md` §6: being unreachable for a day is normal here, and the
 * wording has to be able to say so without alarm.
 */
export function lastHeard(at: number | null, now: number): string {
  if (at === null) return 'nothing heard yet';
  const elapsed = now - at;
  if (elapsed < MINUTE) return 'heard from just now';
  if (elapsed < DAY) return `heard from ${relativeTime(at, now)} ago`;
  if (elapsed < 2 * DAY) return 'heard from yesterday';
  return `no packets for ${relativeTime(at, now)}`;
}

/** `32% loss`, or nothing at all when loss was never measured. */
export function lossLabel(permille: number | null): string | null {
  // `null` means not measured. Rendering it as 0% would claim a perfect link
  // on no evidence, which is the worst available failure (docs/design.md §6).
  if (permille === null) return null;
  return `${Math.round(permille / 10)}% loss`;
}

/** Truncates to `max` characters, with an ellipsis, counting code points. */
export function truncate(text: string, max: number): string {
  const characters = [...text];
  if (characters.length <= max) return text;
  return `${characters.slice(0, max - 1).join('')}…`;
}
