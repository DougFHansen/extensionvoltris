# Threat Intelligence Sources — Source, Licence and Verification Record

**Verification date: 2026-10-13 / 2026-10-14.** Every row below was checked against
the publisher's own terms page or licence file, not against a third-party summary.

The same information is shown to the user at runtime in **Settings → Updates**, so it
is never a claim made only in documentation.

---

## 1. Shipped and enabled

### 1.1 Phishing.Database — active domains

| Field | Value |
|---|---|
| Source | <https://github.com/Phishing-Database/Phishing.Database> |
| Feed | `phishing-domains-ACTIVE.txt` (raw.githubusercontent.com) |
| Licence | **MIT** — verified at `.../blob/master/LICENSE` |
| Copyright | Phishing.Database contributors, 2018–2026 |
| Commercial use | **Permitted** |
| Frequency | Several times per day (automated validation with PyFunceble) |
| Format | Plain domain list, one hostname per line |
| Categories | `phishing` |
| Precision | **High** — entries are actively re-tested for reachability |
| Notes | The single highest-signal feed we can ship without credentials. |

### 1.2 Phishing.Database — active links

| Field | Value |
|---|---|
| Source | Same project as 1.1 |
| Feed | `phishing-links-ACTIVE-today.txt` |
| Licence | **MIT** |
| Commercial use | **Permitted** |
| Categories | `phishing` |
| Notes | Full phishing URLs. We extract **only the host**; paths are never stored. |

### 1.3 StevenBlack unified hosts

| Field | Value |
|---|---|
| Source | <https://github.com/StevenBlack/hosts> |
| Feed | `hosts` |
| Licence | **MIT** — verified at `.../blob/master/license.txt` ("The MIT License (MIT), Copyright © 2023 Steven Black") |
| Commercial use | **Permitted** by the published licence file |
| Frequency | Daily |
| Format | hosts file (`0.0.0.0 host`) |
| Categories | `malware`, `ad` |
| Caveat | This file **aggregates upstream sources**. The publisher ships a single MIT `license.txt` covering the artefact, but individual upstream lists carry their own terms. We treat the file as malware/advertising data, cap how many rules we install from it, and it is individually disableable. If a future audit of upstream terms is required for a commercial release, this provider can be swapped for a single-source alternative without architectural change. |

### 1.4 EasyList

| Field | Value |
|---|---|
| Source | <https://easylist.to/> |
| Feed | `https://easylist.to/easylist/easylist.txt` |
| Licence | Dual licensed **GPL-3.0 OR CC BY-SA 3.0** — verified at <https://easylist.to/pages/licence.html> |
| Our election | **CC BY-SA 3.0** |
| Commercial use | **Permitted** under CC BY-SA 3.0 |
| Attribution | "The EasyList authors (https://easylist.to/)" |
| Frequency | Several times per day |
| Format | Adblock Plus filter list |
| Categories | `ad` |
| Consequence of the licence choice | The **derived rule dataset** we compile and ship is licensed CC BY-SA 3.0. The extension **source code** is not a derivative work of the filter list and keeps its own licence. Both statements are kept separate deliberately. |

### 1.5 EasyPrivacy

| Field | Value |
|---|---|
| Source | <https://easylist.to/> |
| Feed | `https://easylist.to/easylist/easyprivacy.txt` |
| Licence | **CC BY-SA 3.0** (same election as 1.4) |
| Commercial use | **Permitted** |
| Frequency | Several times per day |
| Categories | `tracker` |

---

## 2. Registered but NOT enabled — and why

These providers appear in the interface marked `NOT_CONFIGURED` or `Excluded by
licence`. **They are not downloaded, and no result is simulated for them.**

### 2.1 URLhaus (abuse.ch) — EXCLUDED BY COMMERCIAL TERMS

| Field | Value |
|---|---|
| Source | <https://urlhaus.abuse.ch/> |
| Licence / terms | abuse.ch **Fair Use Principles / enhanced commercial API** |
| Verified at | <https://urlhaus.abuse.ch/api/> (2026-10-13) |
| Commercial use | **Restricted** |
| Reason excluded | The documentation states the Community API "requires an Auth-Key" and that use "by companies, networks, or individuals with commercial or for-profit needs may require a paid subscription for the enhanced abuse.ch commercial API". Shipping it inside a store product without an executed agreement is not permitted. |
| Integration state | Registered, **disabled**, no key embedded. |

### 2.2 OpenPhish — EXCLUDED BY COMMERCIAL TERMS

| Field | Value |
|---|---|
| Source | <https://openphish.com/> |
| Terms | <https://openphish.com/terms.html> (verified 2026-10-13) |
| Commercial use | **Prohibited** |
| Verbatim clause | *"You agree not to use any part of the Services for any commercial purposes, including, but not limited to, security operations, threat intelligence, detection, enrichment, product development, automation, customer protection, or other business functions of any organization you are affiliated with without the prior written consent of OpenPhish."* |
| Integration state | Registered, **excluded**, never contacted. |

### 2.3 PhishTank — NOT_CONFIGURED (needs your own key)

| Field | Value |
|---|---|
| Source | <https://phishtank.org/> |
| Format | JSON dump of online-valid entries |
| Commercial use | Permitted with attribution under the project's data usage terms |
| Blocker | Requires a **free registered app key**. |
| Our position | We never embed a third-party key. The provider is visible in Settings → Updates with a field for **your own** key. Until you supply one it reports `NOT_CONFIGURED` — it does not pretend to work. |

---

## 3. Conversion policy: what we accept and what we refuse

Adblock-style lists are converted to `declarativeNetRequest` with a deliberately
narrow, conservative parser. Anything we cannot express faithfully is **counted and
reported** in Settings → Diagnostics rather than approximated.

| Input | Action | Reason |
|---|---|---|
| `\|\|host^` domain anchor | Converted | Exact DNR equivalent |
| Plain hostname | Converted | Exact |
| `\|\|host/path` | **Skipped** (`unsupported_pattern`) | Poor value, unbounded rule growth |
| `/regex/` filters | **Skipped** (`regex_filter`) | Regex rules fall into the "unsafe" 5,000-rule bucket and a separate 1,000-rule regex quota. Staying regex-free keeps every rule in the 30,000 safe bucket and removes ReDoS exposure. |
| `##.selector` cosmetic filters | **Skipped** (`cosmetic_filter`) | No network equivalent |
| `domain=`, `removeparam=`, `$popup`, `$app=`, `$csp=` … | **Skipped** (`unsupported_option`) | Not expressible as a DNR rule |
| `~script`, `~image`, `third-party`, `important` | Honoured | Expressible |

This policy is locked in by `tests/unit/feed-parsers.test.ts`.

---

## 4. Chrome / Edge rule limits we plan against

Verified against
<https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest>
on 2026-10-13, and re-read from the running browser at runtime where the API exposes
the constants.

| Limit | Value | Our use |
|---|---|---|
| Dynamic rules (safe) | 30,000 | Budget capped at **90% = 27,000** |
| Dynamic rules (unsafe) | 5,000 | **0** — we emit no regex and no header modification |
| Session rules | 5,000 | Allowlist exceptions only |
| Regex rules | 1,000 | **0** |
| Static rulesets | 50 enabled | **0** — we use dynamic rules only, to avoid competing with other extensions for the shared static quota |

Per-category caps are applied on top of the global budget
(`src/blocking/controller.ts`):

| Category | Cap |
|---|---|
| malware | 4,000 |
| phishing | 14,000 |
| malware_distribution | 2,000 |
| scam | 2,000 |
| tracker | 4,000 |
| ad | 2,000 |

Anything dropped is counted and shown as **"Dropped for quota"** with the affected
categories named. We never imply that a truncated list is complete.

---

## 5. Integrity

- Only **data** is downloaded. We never download or execute JavaScript, WASM or any
  code to update the extension. Enforced by static analysis of the built package.
- Every fetch must be `https:`. Enforced in code, not by convention.
- Each validated payload's **SHA-256** is computed and stored, and the prefix is shown
  in Settings → Updates.
- **No bundled source publishes per-file cryptographic signatures.** We therefore do
  not claim signature verification. This limitation is stated rather than papered over.
  The build vendors the Public Suffix List in `vendor/public_suffix_list.dat` and
  records its hash, so at least one input is reproducible and auditable.
- Updates are **atomic**: the previous valid dataset survives any failure, and the
  revision number never decreases.

---

## 6. If a source disappears

A provider that fails keeps its **last known good copy**, marked `Stale` in the
interface. Protection degrades to the previous list rather than switching off, and the
error is reported in Diagnostics. If a provider has never succeeded, its state is
`error` / `not_configured` and it contributes nothing.
