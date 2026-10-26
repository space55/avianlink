/**
 * Renders the supplied app-icon SVG to the 1024x1024 PNG that `tauri icon`
 * expands into the platform icon set.
 *
 * Chromium does the rendering, via the Playwright the test suite already
 * depends on. The alternative — reimplementing the SVG's rounded rectangles
 * and their per-line opacity in a script — would be an approximation of the
 * brand asset rather than the asset itself, and the guidelines are explicit
 * that the supplied files are to be used as they are.
 *
 *   node src-tauri/icons/render-source.mjs
 *   npx tauri icon src-tauri/icons/source.png
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from '@playwright/test';

const here = dirname(fileURLToPath(import.meta.url));
const source = resolve(here, 'source.svg');
const target = resolve(here, 'source.png');
const SIZE = 1024;

const svg = readFileSync(source, 'utf8');

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: SIZE, height: SIZE },
  deviceScaleFactor: 1,
});
// `background: transparent` plus `omitBackground` keeps the icon's own
// rounded corners transparent rather than filling them with white.
await page.setContent(
  `<!doctype html><style>
     html,body{margin:0;padding:0;background:transparent}
     svg{display:block;width:${SIZE}px;height:${SIZE}px}
   </style>${svg}`,
);
await page.screenshot({ path: target, omitBackground: true });
await browser.close();

console.log(`wrote ${target} (${SIZE}x${SIZE})`);
