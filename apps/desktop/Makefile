# Build and packaging for the avianlink desktop app.
#
#   make            list the targets
#   make dist       the final, release application bundle
#
# `dist` is the one that matters: it refuses to package anything that has not
# passed the full gate first, because an installer is the worst place to
# discover that the tests were red.
#
# Everything here runs from `apps/desktop`. The Rust workspace is shared with
# the library crates, so build output lands in the workspace-wide
# `../../target`, not in a directory of this app's own.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
MAKEFLAGS += --no-builtin-rules

APP     := avianlink
ROOT    := $(abspath $(CURDIR)/../..)
TARGET  := $(ROOT)/target
BUNDLE  := $(TARGET)/release/bundle
TAURI   := npx --no-install tauri
UNAME   := $(shell uname -s)

ifeq ($(UNAME),Darwin)
  PLATFORM        := macos
  NATIVE_BUNDLES  := dmg app
else ifeq ($(UNAME),Linux)
  PLATFORM        := linux
  NATIVE_BUNDLES  := deb appimage
else
  PLATFORM        := unsupported
  NATIVE_BUNDLES  :=
endif

# Signing is configured entirely by environment, never by editing the
# committed config, so an unsigned developer build and a signed release build
# are the same build (see README.md "Signing").
ifdef APPLE_SIGNING_IDENTITY
  MACOS_SIGNED := yes
else
  MACOS_SIGNED := no
endif
ifdef APPLE_ID
  MACOS_NOTARIZED := yes
else
  MACOS_NOTARIZED := no
endif

##@ Getting started

.PHONY: help
help: ## List the targets
	@awk 'BEGIN {FS = ":.*##"; printf "\navianlink desktop\n"} \
		/^[a-zA-Z0-9_.-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@printf "\nplatform: %s   native bundles: %s\n\n" "$(PLATFORM)" "$(if $(NATIVE_BUNDLES),$(NATIVE_BUNDLES),none)"

.PHONY: setup
setup: node_modules ## Install the Node dependencies

# An order-only-style guard: `npm ci` is re-run only when the lockfile is
# newer than the installed tree, so the other targets can depend on it
# without paying for it every time.
node_modules: package-lock.json package.json
	npm ci
	@touch node_modules

##@ Developing

.PHONY: dev
dev: node_modules ## Run the app with hot reload
	$(TAURI) dev

.PHONY: web
web: node_modules ## Run only the frontend, in a browser
	npm run dev

##@ Checking

.PHONY: check
check: node_modules ## Run the full gate: fmt, clippy, tests, lint, types, build, e2e
	$(ROOT)/scripts/desktop-ci.sh

.PHONY: test
test: node_modules ## Rust and Vitest tests, without the browser suite
	cargo test -p avianlink-desktop --locked
	npm run test

.PHONY: e2e
e2e: node_modules ## Playwright, against the frontend with the IPC mocked
	npm run test:e2e

.PHONY: lint
lint: node_modules ## Clippy, ESLint, svelte-check and tsc
	cargo clippy -p avianlink-desktop --all-targets --locked --no-deps -- -D warnings
	npm run lint
	npm run check

.PHONY: fmt
fmt: node_modules ## Rewrite files to the canonical formatting
	cargo fmt -p avianlink-desktop
	npm run format

.PHONY: fmt-check
fmt-check: node_modules ## Fail if anything is not canonically formatted
	cargo fmt -p avianlink-desktop -- --check
	npm run format:check

##@ Generated artefacts

.PHONY: bindings
bindings: ## Regenerate src/lib/ipc/bindings.ts from the Rust IPC types
	cargo test -p avianlink-desktop --locked >/dev/null
	@printf "regenerated src/lib/ipc/bindings.ts\n"

.PHONY: icons
icons: node_modules ## Re-render the icon set from the brand SVG
	node src-tauri/icons/render-source.mjs
	$(TAURI) icon src-tauri/icons/source.png

.PHONY: screenshots
screenshots: node_modules ## Re-capture the screenshots in docs/screenshots
	CAPTURE=1 npx playwright test screenshots

##@ Packaging

.PHONY: build
build: node_modules ## Build the frontend into dist/
	npm run build

.PHONY: bundle
bundle: node_modules ## Package for this platform, without running the gate
	@if [ "$(PLATFORM)" = "unsupported" ]; then \
		printf "cannot package on %s: supported hosts are macOS and Linux\n" "$(UNAME)" >&2; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory signing-report
	$(TAURI) build
	@$(MAKE) --no-print-directory artefacts

.PHONY: dist
dist: check bundle ## The final application bundle, gate first
	@printf "\n==> packaged from a green tree\n"

# Tauri names its bundle targets the same on every host, so these are thin
# aliases rather than separate recipes. Each fails loudly on the wrong host
# instead of silently producing nothing.
.PHONY: dmg app deb appimage rpm
dmg app: platform-macos node_modules ## macOS: .dmg installer / .app bundle
	@$(MAKE) --no-print-directory signing-report
	$(TAURI) build --bundles $@
	@$(MAKE) --no-print-directory artefacts

deb appimage rpm: platform-linux node_modules ## Linux: .deb / AppImage / .rpm
	$(TAURI) build --bundles $@
	@$(MAKE) --no-print-directory artefacts

.PHONY: platform-macos platform-linux
platform-macos:
	@[ "$(PLATFORM)" = "macos" ] || { printf "this target needs a macOS host (this is %s)\n" "$(UNAME)" >&2; exit 1; }

platform-linux:
	@[ "$(PLATFORM)" = "linux" ] || { printf "this target needs a Linux host (this is %s)\n" "$(UNAME)" >&2; exit 1; }

.PHONY: artefacts
artefacts: ## List what was produced, with sizes
	@printf "\n==> artefacts in %s\n" "$(BUNDLE)"
	@if [ -d "$(BUNDLE)" ]; then \
		find "$(BUNDLE)" -maxdepth 2 \
			\( -name '*.dmg' -o -name '*.deb' -o -name '*.AppImage' -o -name '*.rpm' -o -name '*.app' \) \
			-exec du -sh {} \; | sed 's|$(BUNDLE)/||'; \
	else \
		printf "  (nothing yet)\n"; \
	fi
	@printf "\n"

.PHONY: signing-report
signing-report: ## Say whether this build will be signed
	@if [ "$(PLATFORM)" != "macos" ]; then exit 0; fi; \
	if [ "$(MACOS_SIGNED)" = "yes" ]; then \
		printf "==> signing as: %s\n" "$$APPLE_SIGNING_IDENTITY"; \
		if [ "$(MACOS_NOTARIZED)" = "yes" ]; then \
			printf "==> will submit for notarization as %s\n" "$$APPLE_ID"; \
		else \
			printf "==> NOT notarizing: APPLE_ID is unset, so Gatekeeper will still warn\n"; \
		fi; \
	else \
		printf "==> UNSIGNED build: APPLE_SIGNING_IDENTITY is unset.\n"; \
		printf "    Usable locally; macOS will refuse it on another machine.\n"; \
		printf "    See README.md \"Signing\".\n"; \
	fi

.PHONY: verify
verify: ## Report the signature and Gatekeeper status of the built .app
	@$(MAKE) --no-print-directory platform-macos
	@app="$(BUNDLE)/macos/$(APP).app"; \
	if [ ! -d "$$app" ]; then printf "no bundle at %s; run make bundle\n" "$$app" >&2; exit 1; fi; \
	info=$$(codesign -dvv "$$app" 2>&1 || true); \
	printf "==> signature\n"; \
	if grep -q "Signature=adhoc" <<<"$$info"; then \
		printf "    ad-hoc: this bundle is NOT signed with a Developer ID.\n"; \
		printf "    It runs on this machine and nowhere else. Set\n"; \
		printf "    APPLE_SIGNING_IDENTITY and rebuild to sign it.\n"; \
	elif grep -q "Signature=" <<<"$$info"; then \
		grep -E "^(Identifier|Authority|TeamIdentifier|Timestamp)=" <<<"$$info" | sed 's/^/    /'; \
		printf "\n==> integrity\n"; \
		codesign --verify --strict --verbose=2 "$$app" 2>&1 | sed 's/^/    /'; \
	else \
		printf "    no signature at all\n"; \
	fi; \
	printf "\n==> Gatekeeper\n"; \
	if spctl --assess --type execute "$$app" >/dev/null 2>&1; then \
		printf "    accepted: this would open on another Mac without a warning\n"; \
	else \
		printf "    rejected: another Mac would refuse to open this.\n"; \
		printf "    Expected for an unsigned or un-notarized build.\n"; \
	fi; \
	printf "\n"

##@ Housekeeping

.PHONY: clean
clean: ## Remove build output, keeping the Cargo cache
	rm -rf dist test-results playwright-report
	rm -rf "$(TARGET)/release/bundle"

.PHONY: clean-all
clean-all: clean ## Also remove node_modules and the whole Cargo target directory
	rm -rf node_modules
	cargo clean
