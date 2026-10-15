/**
 * Threat intelligence provider registry.
 *
 * Every entry here was verified against the publisher's own terms and license
 * file. The verification date, the exact URL checked and the resulting decision
 * are recorded in `store/FEEDS_AND_LICENSES.md`.
 *
 * Rules encoded in this file:
 *  - A provider whose terms forbid commercial use is NOT bundled and NOT
 *    downloaded. It is listed as `excludedFromProduct` with a reason.
 *  - A provider that requires a credential or paid infrastructure is registered
 *    but reported as `not_configured` until the user supplies their own key.
 *    We never pretend such an integration works.
 */
import type { ProviderDescriptor } from '../core/types';

export const FEED_REGISTRY: readonly ProviderDescriptor[] = [
  // ---------------------------------------------------------------- phishing
  {
    id: 'phishing-database-domains',
    name: 'Phishing.Database (active domains)',
    homepage: 'https://github.com/Phishing-Database/Phishing.Database',
    feedUrl: 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    format: 'domain-list',
    license: {
      id: 'MIT',
      name: 'MIT License',
      url: 'https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE',
      commercialUseAllowed: true,
      attribution: 'Phishing.Database contributors (c) 2018-2026',
    },
    categories: ['phishing'],
    updateFrequency: 'Several times per day (automated PyFunceble validation)',
    requiresCredential: false,
    excludedFromProduct: false,
    dataVersion: 'daily (AAAAMMDD suffix in file name / header)',
    notes:
      'Domains actively validated as reachable phishing pages. Highest precision feed we can ship without credentials. MIT license, verified.',
  },
  {
    id: 'phishing-database-links',
    name: 'Phishing.Database (active links)',
    homepage: 'https://github.com/Phishing-Database/Phishing.Database',
    feedUrl: 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-today.txt',
    format: 'domain-list',
    license: {
      id: 'MIT',
      name: 'MIT License',
      url: 'https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE',
      commercialUseAllowed: true,
      attribution: 'Phishing.Database contributors (c) 2018-2026',
    },
    categories: ['phishing'],
    updateFrequency: 'Continuous',
    requiresCredential: false,
    excludedFromProduct: false,
    dataVersion: 'daily',
    notes:
      'Full phishing URLs. We only extract the host portion; paths are never stored, which keeps the dataset small and avoids storing browsing-relevant detail.',
  },

  // ----------------------------------------------------------------- malware
  {
    id: 'stevenblack-hosts',
    name: 'StevenBlack unified hosts',
    homepage: 'https://github.com/StevenBlack/hosts',
    feedUrl: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    format: 'hosts',
    license: {
      id: 'MIT',
      name: 'MIT License',
      url: 'https://github.com/StevenBlack/hosts/blob/master/license.txt',
      commercialUseAllowed: true,
      attribution: 'StevenBlack and the hosts project contributors',
    },
    categories: ['malware', 'ad'],
    updateFrequency: 'Daily',
    requiresCredential: false,
    excludedFromProduct: false,
    dataVersion: 'daily',
    notes:
      'Aggregate hosts file. Publisher ships an MIT license.txt. The file aggregates upstream sources; see THIRD_PARTY_NOTICES.md for the caveat. We treat entries as MALWARE for blocking only when the host is not already allowlisted, and cap the number of rules we install.',
  },

  // ------------------------------------------------------- ads and trackers
  {
    id: 'easylist',
    name: 'EasyList',
    homepage: 'https://easylist.to/',
    feedUrl: 'https://easylist.to/easylist/easylist.txt',
    format: 'adblock',
    license: {
      id: 'CC-BY-SA-3.0',
      name: 'Creative Commons Attribution-ShareAlike 3.0 Unported',
      url: 'https://easylist.to/pages/licence.html',
      commercialUseAllowed: true,
      attribution: 'The EasyList authors (https://easylist.to/)',
    },
    categories: ['ad'],
    updateFrequency: 'Several times per day',
    requiresCredential: false,
    excludedFromProduct: false,
    dataVersion: 'rolling',
    notes:
      'Dual licensed GPL-3.0 OR CC BY-SA 3.0. We elect the CC BY-SA 3.0 option. The derived rule dataset is therefore distributed under CC BY-SA 3.0; the extension code is NOT a derivative of the list and keeps its own license.',
  },
  {
    id: 'easyprivacy',
    name: 'EasyPrivacy',
    homepage: 'https://easylist.to/',
    feedUrl: 'https://easylist.to/easylist/easyprivacy.txt',
    format: 'adblock',
    license: {
      id: 'CC-BY-SA-3.0',
      name: 'Creative Commons Attribution-ShareAlike 3.0 Unported',
      url: 'https://easylist.to/pages/licence.html',
      commercialUseAllowed: true,
      attribution: 'The EasyList authors (https://easylist.to/)',
    },
    categories: ['tracker'],
    updateFrequency: 'Several times per day',
    requiresCredential: false,
    excludedFromProduct: false,
    dataVersion: 'rolling',
    notes: 'Tracker/analytics rules. Same CC BY-SA 3.0 election as EasyList.',
  },

  // ------------------------------------------------- NOT AVAILABLE / NOT USED
  {
    id: 'urlhaus',
    name: 'URLhaus (abuse.ch)',
    homepage: 'https://urlhaus.abuse.ch/',
    feedUrl: 'https://urlhaus-api.abuse.ch/v2/urls/recent/',
    format: 'domain-list',
    license: {
      id: 'abuse.ch-fair-use',
      name: 'abuse.ch Fair Use Principles / enhanced commercial API',
      url: 'https://urlhaus.abuse.ch/api/',
      commercialUseAllowed: false,
      attribution: 'abuse.ch / Spamhaus',
    },
    categories: ['malware'],
    updateFrequency: 'Continuous',
    requiresCredential: true,
    excludedFromProduct: true,
    exclusionReason:
      'abuse.ch documents that the Community API requires an Auth-Key and that commercial or for-profit use may require a paid subscription. Shipping it in a store product without an executed agreement is not permitted. Provider stays NOT_CONFIGURED.',
    dataVersion: 'n/a',
    notes: 'Excluded from the product. The integration point exists but is disabled by default.',
  },
  {
    id: 'openphish',
    name: 'OpenPhish',
    homepage: 'https://openphish.com/',
    feedUrl: 'https://openphish.com/feed.txt',
    format: 'domain-list',
    license: {
      id: 'proprietary-non-commercial',
      name: 'OpenPhish Terms of Use (personal / academic only)',
      url: 'https://openphish.com/terms.html',
      commercialUseAllowed: false,
      attribution: 'OpenPhish',
    },
    categories: ['phishing'],
    updateFrequency: 'Every 5 minutes on the paid feed',
    requiresCredential: false,
    excludedFromProduct: true,
    exclusionReason:
      'Terms of Use state: "You agree not to use any part of the Services for any commercial purposes, including ... product development ... customer protection ... without the prior written consent of OpenPhish." Excluded.',
    dataVersion: 'n/a',
    notes: 'Excluded. Verified against https://openphish.com/terms.html on 2026-10-13.',
  },
  {
    id: 'phishtank',
    name: 'PhishTank',
    homepage: 'https://phishtank.org/',
    feedUrl: 'https://data.phishtank.com/data/online-valid.json',
    format: 'domain-list',
    license: {
      id: 'CC-BY-3.0',
      name: 'PhishTank data usage terms',
      url: 'https://phishtank.org/phish-tank-info/',
      commercialUseAllowed: true,
      attribution: 'PhishTank',
    },
    categories: ['phishing'],
    updateFrequency: 'Hourly',
    requiresCredential: true,
    excludedFromProduct: false,
    dataVersion: 'hourly',
    notes:
      'Requires a free registered app key. Reported as NOT_CONFIGURED until the user supplies their own key in Settings > Updates. We never embed a third-party key.',
  },
];

export const PROVIDER_INDEX: ReadonlyMap<string, ProviderDescriptor> = new Map(
  FEED_REGISTRY.map((p) => [p.id, p]),
);

export function providerById(id: string): ProviderDescriptor | undefined {
  return PROVIDER_INDEX.get(id);
}

/** Providers that may be downloaded and compiled in this build. */
export function enabledProviders(): readonly ProviderDescriptor[] {
  return FEED_REGISTRY.filter((p) => !p.excludedFromProduct);
}

/** Providers registered but intentionally not part of the product. */
export function excludedProviders(): readonly ProviderDescriptor[] {
  return FEED_REGISTRY.filter((p) => p.excludedFromProduct);
}
