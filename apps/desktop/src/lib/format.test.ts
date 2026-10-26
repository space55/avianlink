import { describe, expect, it } from 'vitest';

import {
  clockTime,
  daySeparator,
  duration,
  isSameDay,
  lastHeard,
  lossLabel,
  relativeTime,
  truncate,
} from './format';

const UTC = { timeZone: 'UTC', locale: 'en-GB' };
const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

// 2023-11-14T22:13:20Z, a Tuesday.
const T0 = 1_700_000_000_000;

describe('clockTime', () => {
  it('is 24-hour and zero-padded, so the column does not jump', () => {
    expect(clockTime(T0, UTC)).toBe('22:13');
    expect(clockTime(T0 - 20 * HOUR, UTC)).toBe('02:13');
  });
});

describe('daySeparator', () => {
  it('names today and yesterday rather than dating them', () => {
    expect(daySeparator(T0, T0, UTC)).toBe('Today');
    expect(daySeparator(T0 - DAY, T0, UTC)).toBe('Yesterday');
  });

  it('spells out older days, with the year only when it differs', () => {
    expect(daySeparator(T0 - 5 * DAY, T0, UTC)).toMatch(/November/);
    expect(daySeparator(T0 - 5 * DAY, T0, UTC)).not.toMatch(/2023/);
    expect(daySeparator(T0 - 400 * DAY, T0, UTC)).toMatch(/2022/);
  });
});

describe('relativeTime', () => {
  it('does not sit at zero for a minute', () => {
    expect(relativeTime(T0, T0)).toBe('just now');
    expect(relativeTime(T0 - 59 * SECOND, T0)).toBe('just now');
  });

  it('steps through minutes, hours, days and weeks', () => {
    expect(relativeTime(T0 - 2 * MINUTE, T0)).toBe('2m');
    expect(relativeTime(T0 - 3 * HOUR, T0)).toBe('3h');
    expect(relativeTime(T0 - 25 * HOUR, T0)).toBe('yesterday');
    expect(relativeTime(T0 - 4 * DAY, T0)).toBe('4d');
    // Beyond a week, "23d" is a number nobody reads.
    expect(relativeTime(T0 - 23 * DAY, T0)).toBe('3w');
  });

  it('treats a future timestamp as now rather than showing a negative', () => {
    // A peer's clock can be ahead of ours; the library says so explicitly.
    expect(relativeTime(T0 + HOUR, T0)).toBe('just now');
  });
});

describe('duration', () => {
  it('shows at most two units', () => {
    expect(duration(45 * SECOND)).toBe('45s');
    expect(duration(3 * MINUTE)).toBe('3m');
    expect(duration(3 * MINUTE + 20 * SECOND)).toBe('3m 20s');
    expect(duration(HOUR + 12 * MINUTE)).toBe('1h 12m');
    expect(duration(2 * HOUR)).toBe('2h');
    expect(duration(3 * DAY + 4 * HOUR)).toBe('3d 4h');
  });

  it('never reports zero for something that took a moment', () => {
    expect(duration(400)).toBe('1s');
    expect(duration(0)).toBe('1s');
  });
});

describe('lastHeard', () => {
  it('says nothing has arrived yet without implying a fault', () => {
    expect(lastHeard(null, T0)).toBe('nothing heard yet');
  });

  it('stays neutral as the silence lengthens', () => {
    expect(lastHeard(T0 - 3 * HOUR, T0)).toBe('heard from 3h ago');
    expect(lastHeard(T0 - 30 * HOUR, T0)).toBe('heard from yesterday');
    expect(lastHeard(T0 - 4 * DAY, T0)).toBe('no packets for 4d');
    // The vocabulary from docs/design.md §6: never "disconnected", never
    // "error", never an exclamation mark.
    for (const at of [null, T0 - HOUR, T0 - 9 * DAY]) {
      expect(lastHeard(at, T0)).not.toMatch(/disconnect|error|fail|!/i);
    }
  });
});

describe('lossLabel', () => {
  it('renders measured loss as a percentage', () => {
    expect(lossLabel(320)).toBe('32% loss');
    expect(lossLabel(0)).toBe('0% loss');
  });

  it('renders unmeasured loss as nothing at all, never as zero', () => {
    // Claiming a perfect link because nothing measured it is the worst
    // available failure (docs/design.md §6).
    expect(lossLabel(null)).toBeNull();
  });
});

describe('truncate', () => {
  it('counts code points, not UTF-16 units', () => {
    expect(truncate('ééééé', 3)).toBe('éé…');
    expect(truncate('short', 50)).toBe('short');
  });
});

describe('isSameDay', () => {
  it('compares calendar days in the display timezone', () => {
    expect(isSameDay(T0, T0 + HOUR, UTC)).toBe(true);
    expect(isSameDay(T0, T0 + 2 * HOUR, UTC)).toBe(false);
  });
});
