import { render } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';

import Brand from './Brand.svelte';

/** The rendered `<svg>`, which comes verbatim from the asset package. */
function svg(): SVGElement | null {
  return document.querySelector('.brand > svg');
}

describe('brand tiers', () => {
  it('renders the supplied file rather than a rebuilt one', () => {
    render(Brand, { props: { variant: 'lockup', size: 24 } });
    // The asset package ships every file with its own title and label; if
    // this is missing, something has been reconstructed from parts, which
    // the guidelines forbid.
    expect(svg()?.querySelector('title')?.textContent).toBe('avianlink');
  });

  it('uses a different file for each tier', () => {
    const seen = new Set<string>();
    for (const variant of ['lockup', 'wordmark', 'mark'] as const) {
      const { unmount } = render(Brand, { props: { variant, size: 32 } });
      seen.add(svg()?.getAttribute('viewBox') ?? '');
      unmount();
    }
    expect(seen.size).toBe(3);
  });

  it('inherits the surrounding colour, so one file serves both themes', () => {
    render(Brand, { props: { variant: 'mark', size: 112 } });
    const fills = [...(svg()?.querySelectorAll('[fill]') ?? [])].map((node) =>
      node.getAttribute('fill'),
    );
    expect(fills.length).toBeGreaterThan(0);
    expect(fills.every((fill) => fill === 'currentColor')).toBe(true);
  });

  it('never stretches: only one dimension is constrained', () => {
    // The guidelines forbid stretching or squashing, so the height is set and
    // the width follows, or vice versa for the mark.
    render(Brand, { props: { variant: 'lockup', size: 24 } });
    const style = document.querySelector('.brand')?.getAttribute('style') ?? '';
    expect(style).toContain('--brand-size: 24px');
  });

  it('reserves clear space of half the rendered height on every side', () => {
    render(Brand, { props: { variant: 'lockup', size: 40 } });
    const style = document.querySelector('.brand')?.getAttribute('style') ?? '';
    expect(style).toContain('--brand-clearance: 20px');
  });

  it('takes its accessible name from the supplied file, not a second one', () => {
    // The files already carry `role="img"` and a label; wrapping them in
    // another would nest two identical image roles.
    render(Brand, { props: { variant: 'lockup', size: 24 } });
    expect(svg()).toHaveAttribute('role', 'img');
    expect(svg()).toHaveAttribute('aria-label', 'avianlink');
    expect(document.querySelector('.brand')).not.toHaveAttribute('role');
  });
});
