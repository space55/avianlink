# Brand assets

Copied verbatim from the `avianlink-logo` asset package (v1.0, October 2026);
see its `avianlink-logo-guidelines.pdf` for the full rules. Do not edit these
files or rebuild the lockup from its parts — the guidelines are explicit about
both.

What the app uses, and why that variant:

| File                                        | Used by                 | Tier rule it satisfies           |
| ------------------------------------------- | ----------------------- | -------------------------------- |
| `avianlink-lockup-compact-currentcolor.svg` | sidebar header, wide    | lockup 24–47px tall → compact    |
| `avianlink-wordmark-currentcolor.svg`       | sidebar header, narrow  | below 24px tall → wordmark alone |
| `avianlink-mark-full-currentcolor.svg`      | empty-state placeholder | mark ≥96px wide → full           |
| `favicon.svg`                               | `index.html`            | micro mark, adapts to dark mode  |
| `../../src-tauri/icons/source.svg`          | app icon                | icon ≥128px → full               |

`-currentcolor` variants inherit the surrounding text colour, which is what
keeps the mark correct in both themes without a second file.
