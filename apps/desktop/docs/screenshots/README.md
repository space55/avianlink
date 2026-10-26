# Screenshots

Captured from the real frontend in Chromium with the Tauri IPC mocked, not
from the native window: the window chrome belongs to the platform, and
everything inside it is exactly what these show.

Regenerate with:

```sh
cd apps/desktop && CAPTURE=1 npx playwright test screenshots
```

They are committed so that `docs/` shows what each phase actually produced.
