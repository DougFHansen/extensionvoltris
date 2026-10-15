# Third-Party Notices

VOLTRIS Browser Shield bundles or derives from the following third-party components.
The extension's own source code is proprietary to VOLTRIS and is **not** a derivative
work of any filter list.

---

## Runtime components shipped in the package

### Public Suffix List
- **Licence:** Mozilla Public License 2.0
- **Copyright:** Mozilla Foundation and contributors
- **Use:** registrable-domain extraction (`src/generated/psl.json`)
- **Attribution notice:** "This Source Code Form is subject to the terms of the
  Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/."
- **Provenance:** generated from <https://publicsuffix.org/list/public_suffix_list.dat>.
  The raw list is vendored at `vendor/public_suffix_list.dat` and its SHA-256 is
  recorded in the generated artefact.

### Phishing.Database
- **Licence:** MIT
- **Copyright:** Copyright (c) 2018-2026 Mitchell Krog, Nissar Chababy (funilrys),
  Phishing.Database Contributors
- **Use:** phishing domain and link intelligence
- **Permission notice:** "The MIT License (MIT) … Permission is hereby granted, free of
  charge, to any person obtaining a copy of this software and associated documentation
  files (the "Software"), to deal in the Software without restriction…"
- **Source:** <https://github.com/Phishing-Database/Phishing.Database>

### StevenBlack hosts
- **Licence:** MIT
- **Copyright:** Copyright (c) 2023 Steven Black
- **Use:** malware and advertising host intelligence
- **Permission notice:** "The MIT License (MIT) … Permission is hereby granted, free of
  charge, to any person obtaining a copy…"
- **Source:** <https://github.com/StevenBlack/hosts>
- **Caveat:** this artefact aggregates upstream sources; see
  `store/FEEDS_AND_LICENSES.md` §1.3.

### The EasyList authors — EasyList and EasyPrivacy
- **Licence elected:** Creative Commons Attribution-ShareAlike 3.0 Unported
- **Attribution:** "The EasyList authors (https://easylist.to/)"
- **Source:** <https://easylist.to/>
- **Use:** advertising and tracker filter rules
- **ShareAlike notice:** the EasyList repository is dual licensed under
  **GPL-3.0 or CC BY-SA 3.0**, at the user's option. We elect **CC BY-SA 3.0**.
  Accordingly, the **derived rule dataset** compiled from these lists and redistributed
  with this extension is licensed under **Creative Commons Attribution-ShareAlike
  3.0 Unported** (<https://creativecommons.org/licenses/by-sa/3.0/>).
  The extension's **source code** is a separate work and is not covered by that
  licence.

---

## Build-time and development dependencies

These are **not shipped** in the extension package. They are listed for a complete
software bill of materials.

| Package | Licence |
|---|---|
| `vite` | MIT |
| `typescript` | Apache-2.0 |
| `vitest` | MIT |
| `@vitest/coverage-v8` | MIT |
| `@playwright/test` | Apache-2.0 |
| `@types/chrome` | MIT |
| `@types/node` | MIT |

Run `npm audit --audit-level=high` to review them. The extension has **zero runtime
dependencies**.

---

## Design-time reference material

Consulted but not redistributed:

- Chrome Extensions documentation — <https://developer.chrome.com/docs/extensions>
- `declarativeNetRequest` API reference and rule limits
- Chromium Web Store and Microsoft Edge Add-ons distribution policies

---

## Trademarks

"VOLTRIS" is a trademark of its owner. Third-party names referenced in threat data
(and in the brand-impersonation reference list) belong to their respective owners and
are used **only to identify them as impersonation targets**. No affiliation or
endorsement is implied.
