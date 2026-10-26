import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// Read from disk rather than imported: these are the tokens as written, not
// as a bundler resolved them. (`?raw` is not an option — Vitest's CSS
// pipeline returns an empty string for it.)
const css = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '../src/app.css'),
  'utf8',
);

/**
 * Contrast checks on the design tokens (docs/design.md §10).
 *
 * Checked by a test rather than by eye, because "faint" is exactly the token
 * most likely to drift below the threshold: it is the one a designer keeps
 * nudging quieter, and it carries timestamps and link health — small text
 * that WCAG holds to the full 4.5:1.
 */

/** Pulls the custom properties out of one `:root` block. */
function tokens(blockStart: RegExp): Record<string, string> {
  const start = css.search(blockStart);
  if (start === -1) throw new Error(`no block matching ${blockStart}`);
  const open = css.indexOf('{', start);
  const close = css.indexOf('}', open);
  const body = css.slice(open + 1, close);
  const out: Record<string, string> = {};
  for (const line of body.split('\n')) {
    const match = /^\s*(--[\w-]+):\s*([^;]+);/.exec(line);
    if (match) out[match[1]] = match[2].trim();
  }
  return out;
}

const light = tokens(/^:root \{/m);
const dark = tokens(/@media \(prefers-color-scheme: dark\) \{\s*:root/m);

function channel(value: number): number {
  const srgb = value / 255;
  return srgb <= 0.03928 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  const match = /^#([0-9a-f]{6})$/i.exec(hex.trim());
  if (!match) throw new Error(`not a six-digit hex colour: ${hex}`);
  const n = Number.parseInt(match[1], 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

/** Every foreground that carries text, against every surface it sits on. */
const FOREGROUNDS = ['--text', '--text-muted', '--text-faint'];
const SURFACES = ['--bg', '--bg-raised', '--bg-sunken'];

/** WCAG AA for text below 18pt. Everything here is below 18pt. */
const AA = 4.5;

describe.each([
  ['light', light],
  ['dark', dark],
])('%s theme', (_name, palette) => {
  it('defines every token the components use', () => {
    for (const token of [...FOREGROUNDS, ...SURFACES]) {
      expect(palette[token], `${token} is missing`).toBeTruthy();
    }
  });

  it.each(FOREGROUNDS)('%s meets WCAG AA on every surface', (foreground) => {
    for (const surface of SURFACES) {
      const ratio = contrast(palette[foreground], palette[surface]);
      expect(
        ratio,
        `${foreground} on ${surface} is ${ratio.toFixed(2)}:1, below ${AA}:1`,
      ).toBeGreaterThanOrEqual(AA);
    }
  });

  it('keeps the message-state colours legible', () => {
    // These carry the glyphs that say whether a message arrived.
    for (const status of [
      '--status-delivered',
      '--status-sent',
      '--status-queued',
      '--status-failed',
    ]) {
      const ratio = contrast(palette[status], palette['--bg']);
      expect(ratio, `${status} on --bg is ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(3);
    }
  });

  it('keeps accent text readable on the accent', () => {
    const ratio = contrast(palette['--accent-text'], palette['--accent']);
    expect(ratio, `accent pair is ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(AA);
  });

  it('gives the focus ring enough contrast against every surface', () => {
    // A focus ring is a non-text indicator: WCAG asks for 3:1.
    for (const surface of SURFACES) {
      const ratio = contrast(palette['--focus-ring'], palette[surface]);
      expect(ratio, `focus ring on ${surface} is ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(3);
    }
  });
});
