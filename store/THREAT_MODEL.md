# VOLTRIS Browser Shield — Threat Model

Scope: the extension itself and the browser it runs in. We model what an attacker
controls (the web page, the network path is TLS-protected, the feed server) and what
we control (the extension process and its local storage).

---

## 1. Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| User settings | `chrome.storage.local` | Low |
| Per-site exceptions | `chrome.storage.local` | Medium — reveals browsing intent |
| Event history | `chrome.storage.local` | Medium — domains the user visited |
| Threat dataset | `chrome.storage.local` | None — public data |
| Credentials a user supplies for a provider | `chrome.storage.local` | **High** |
| Block-record tokens (interstitial) | `chrome.storage.session` | Low — ephemeral |
| Compiled rule set | DNR engine | None |

## 2. Trust boundaries

```
  ┌──────────────────────────────────────────────────────────────┐
  │ BROWSER PROCESS                                                 │
  │  ┌──────────────┐   runtime messaging   ┌──────────────────┐  │
  │  │ Extension UI │ ────────────────────► │ Service worker   │  │
  │  │ (popup,      │ ◄──────────────────── │ (trusted core)   │  │
  │  │  dashboard,  │                       │                  │  │
  │  │  options)    │                       │  DNR rules       │  │
  │  └──────────────┘                       │  storage         │  │
  │                                         └──────────────────┘  │
  │  ┌──────────────┐   validated subset    ┌──────────────────┐  │
  │  │ Content      │ ────────────────────► │                  │  │
  │  │ script       │  of messages only     │                  │  │
  │  │ (ISOLATED)   │                       │                  │  │
  │  └──────┬───────┘                       └──────────────────┘  │
  └─────────┼────────────────────────────────────────────────────┘
            │  UNTRUSTED: the page and everything it can influence
            ▼
      ┌──────────────────────────────────┐
      │  Hostile web page / its content  │
      └──────────────────────────────────┘
```

Four boundaries matter:

1. **Page → content script.** The page is hostile. The content script is isolated and
   treats everything it reads as hostile.
2. **Content script → service worker.** Only two message types are accepted. Anything
   else is rejected regardless of the declared sender.
3. **Any extension page → service worker.** Trusted, but the payload is still
   whitelisted and sanitised — a buggy or compromised UI page must not be able to
   write arbitrary storage keys.
4. **Extension → feed servers.** Data only, HTTPS only, schema-validated, size-capped,
   atomically applied.

---

## 3. Threats and mitigations

### T1 — Page extracts credentials or session data
**Adversary:** hostile page. **Impact:** account takeover.

The content script never reads `input.value`, `document.cookie`, `localStorage`,
`sessionStorage` or `indexedDB`. It reads tag names, `type`, `placeholder`,
`aria-label`, `name` and a bounded sample of text nodes.
**Enforced by:** `tests/unit/privacy-lint.test.ts`, which fails the build on any of
these patterns. Verified end to end by a Playwright test that types a password into a
fixture page and asserts the value never appears in extension storage.

### T2 — Page forges a message to the service worker
**Adversary:** hostile page. **Impact:** disabled protection or privileged actions.

No `externally_connectable` is declared, so a page cannot call our API at all. On top
of that, senders are classified by `sender.url` (`src/background/messages.ts`):
extension pages are trusted, content scripts are restricted to two whitelisted types,
anything else is rejected. A page cannot spoof `sender.url`.

### T3 — DOM XSS in our own interface
**Impact:** script execution in the extension origin (which holds `storage` and DNR).

There is **no `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write`** in
the UI layer. Every node is created programmatically and every user-visible string is
written through `textContent` (`src/ui/shared/components.ts`). Untrusted values — URLs,
domain names, provider names, error messages — all flow through that path.
**Enforced by:** privacy lint over sources and static analysis over the built package.

### T4 — Refused URL reaches a page through the query string
**Impact:** injection via `blocked.html?...`.

The blocked page reads **only an opaque token** from `location.search`. The token is
resolved to a record in `chrome.storage.session`, and the verdict is **recomputed** by
the service worker from the recorded URL. Nothing from the query string is rendered,
trusted or used as a verdict. The token format is validated at the message boundary.
`blocked.html` is not web-accessible, so no other page can load or frame it.

### T5 — Malicious or malformed feed data
**Impact:** blocking legitimate sites, memory exhaustion, arbitrary rule injection.

- Payload capped at 32 MB and read with a streaming byte ceiling.
- Every host validated (length, label count, hyphen rules, charset, IP-literal
  rejection).
- Rule construction rejects any host containing `||`/`^`/`|` — the `urlFilter`
  metacharacters — so a feed entry cannot inject pattern syntax.
- Entry count capped at 500,000 per provider; dataset capped at 6 MB, below the
  storage quota.
- **No `regexFilter` and no header modification anywhere**, which removes regex
  backtracking and header tampering as classes of risk.
- The swap is atomic: the previous valid dataset survives any failure and the revision
  never decreases.

### T6 — Rule flooding degrades the browser
**Impact:** slowdown for the user and for every other extension.

Budget is 90% of the limit the browser actually reports, split per category, with
malware and phishing first. Every drop is counted and reported. Zero static rulesets
are used, so we do not compete with other extensions for the shared static quota.

### T7 — Extension misbehaves in the host page
**Impact:** measurable slowdown on every site.

No `setInterval`, no permanent `MutationObserver`, no polling. The DOM walk is bounded
and runs once at `document_idle` plus on explicit user request. Hover handling is a
single delegated listener with a 250 ms throttle. The service worker does no work at
import time beyond registering listeners, and the Public Suffix List is loaded lazily
on first use rather than at startup.

### T8 — Settings corruption widens permissions
**Impact:** the user silently gets weaker protection, or a crash loop.

Every settings value read from storage is re-validated against the shipped defaults:
booleans must be booleans, enums must be in the enum, the update interval is clamped.
Unknown keys are dropped. The result is cached per context and re-primed on change.

### T9 — Prototype pollution through a message
**Impact:** arbitrary behaviour in the service worker.

`validatePayload` builds a fresh object and copies only known keys with primitive
values; it never spreads the raw payload. Keys named `__proto__`, `constructor` and
`prototype` are dropped because they are not in the known-key set.
**Enforced by:** `tests/unit/messaging.test.ts`.

### T10 — Concurrent updates lose counted events
**Impact:** statistics under-report real blocks.

`webNavigation.onErrorOccurred` can fire several times in quick succession. Counter
mutations run through a serialised promise queue and `flushStats` awaits that queue
before writing, so two concurrent events cannot both read the same snapshot.

### T10b — Statistics driven by an API absent from published builds
**Impact:** every block counter silently reads zero after a store install, and the
explanatory block page never appears.

The first build counted matches through `declarativeNetRequest.onRuleMatchedDebug`.
Chrome documents that event — and the `declarativeNetRequestFeedback` permission that
gates it — as available **only to unpacked extensions**, intended for debugging. Tests
run against an unpacked build, so they passed and the fault was invisible until
publication.

Mitigations:
- The permission was removed and every dependency on the API was deleted. The build
  fails if the symbol reappears in shipped code (`scripts/static-analysis.mjs`).
- Observation is rebuilt on `webNavigation.onErrorOccurred`, which is available to
  published extensions.
- The E2E suite asserts the debug API is genuinely absent, then asserts blocking,
  counting and the interstitial all still work — so the tests exercise the production
  configuration rather than a development superset.
- Statistics that cannot be obtained in production (per-request sub-resource blocks)
  are declared unavailable in `METRIC_CAPABILITIES` and rendered as such in the
  dashboard, never as a zero.

### T11 — Provider key disclosure
**Impact:** a third-party account key stored in plaintext locally.

Keys are supplied by the user, stored only in local extension storage, never echoed
back in any response, never logged, and never sent anywhere except to that provider's
own documented endpoint. VOLTRIS embeds no third-party key.

### T12 — Supply-chain compromise of the extension itself
**Impact:** full access to browsing behaviour for anyone who installs it.

No remote code is ever executed. Updates are data-only, enforced by static analysis of
the built package. No telemetry, no analytics and no obfuscation. `npm audit` runs in
CI; runtime dependencies are **zero** (only TypeScript sources are shipped).

---

## 4. Out of scope

- Attacks on the browser itself (Chrome/Edge rendering, sandbox, updater).
- Physical access to the device.
- Attacks on the **feed provider's** infrastructure — we cannot verify their integrity
  beyond HTTPS and the SHA-256 we record.
- Malware that already runs on the user's machine with the user's privileges.

## 5. Residual risk

- A feed could list a legitimate site by mistake. Mitigated by per-site exceptions with
  **scoped** privileges, and by never letting a privacy exception disable malware
  blocking.
- Heuristics can be evaded by a patient attacker. This is why heuristics never produce
  a block on their own.
- Threat intelligence is inherently behind the curve. Stated plainly in
  `store/LIMITATIONS.md`.
