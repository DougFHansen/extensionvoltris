/**
 * declarativeNetRequest rule compiler.
 *
 * Responsibilities:
 *  - Translate the local dataset into DNR rules.
 *  - Enforce every documented Chrome/Edge limit with headroom.
 *  - Report exactly what was installed, what was dropped and why.
 *
 * Deliberate constraints:
 *  - NO `regexFilter` anywhere. Regex rules fall into the "unsafe" dynamic
 *    bucket (5000) and into a separate 1000-rule regex quota. Staying regex-free
 *    keeps every rule in the 30,000 safe bucket and removes a whole class of
 *    ReDoS exposure.
 *  - No header modification, so the extension does not interfere with browser
 *    security headers or site isolation.
 *  - Explicit `priority` per category (see RULE_PRIORITY) because the relative
 *    ordering of static/dynamic/session rules is NOT documented and differs
 *    between Chrome and Edge.
 */
import { DNR_BUDGET_HEADROOM, DNR_LIMITS, RULE_CATEGORY_ORDINAL, RULE_CATEGORY_STRIDE, RULE_ID, RULE_PRIORITY } from '../core/constants';
import type { ThreatCategory } from '../core/types';

export interface CompiledRule {
  id: number;
  priority: number;
  action: chrome.declarativeNetRequest.RuleAction;
  condition: chrome.declarativeNetRequest.RuleCondition;
}

export interface CompileInput {
  readonly category: ThreatCategory;
  readonly host: string;
  /** Provenance, used by the dataset assembler; not part of the rule itself. */
  readonly providerId?: string;
  /** Third-party only (used for trackers/ads). */
  readonly thirdParty?: boolean;
  readonly initiatorDomains?: readonly string[];
  readonly excludedResourceTypes?: readonly string[];
  /** Main-frame only rules redirect to the interstitial instead of blocking. */
  readonly mainFrameOnly?: boolean;
  /** Explicit override of the priority band. */
  readonly priority?: number;
}

const PRIORITY_BY_CATEGORY: Record<ThreatCategory, number> = {
  malware: RULE_PRIORITY.BLOCK_MALWARE,
  phishing: RULE_PRIORITY.BLOCK_PHISHING,
  malware_distribution: RULE_PRIORITY.BLOCK_MALWARE,
  scam: RULE_PRIORITY.BLOCK_SCAM,
  tracker: RULE_PRIORITY.BLOCK_TRACKERS,
  ad: RULE_PRIORITY.BLOCK_ADS,
};

/**
 * Resource types we are willing to block for privacy categories.
 * `main_frame` is intentionally excluded: blocking a top-level navigation
 * because it is an ad would break the web.
 *
 * Types are derived from the official `RuleCondition` definition rather than
 * re-declared, so an API change surfaces at compile time.
 */
type ResourceTypeName = NonNullable<chrome.declarativeNetRequest.RuleCondition['resourceTypes']>[number];
type ActionTypeName = NonNullable<chrome.declarativeNetRequest.RuleAction['type']>;
type DomainTypeName = NonNullable<chrome.declarativeNetRequest.RuleCondition['domainType']>;

const PRIVACY_RESOURCE_TYPES: ResourceTypeName[] = [
  'script',
  'image',
  'xmlhttprequest',
  'sub_frame',
  'media',
  'font',
  'stylesheet',
  'ping',
  'websocket',
  'other',
];

/** Resource types blocked for threat categories (everything, incl. main_frame). */
const THREAT_RESOURCE_TYPES: ResourceTypeName[] = [
  'main_frame',
  'sub_frame',
  'script',
  'image',
  'xmlhttprequest',
  'media',
  'font',
  'stylesheet',
  'ping',
  'websocket',
  'other',
  'object',
];

export function isThreatCategory(c: ThreatCategory): boolean {
  return c === 'malware' || c === 'phishing' || c === 'malware_distribution' || c === 'scam';
}

/**
 * Builds the `urlFilter` for a host.
 *
 * `||host^` anchors at the scheme-or-host boundary, which - per the Chrome
 * documentation - matches the host and all of its subdomains but NOT
 * `host.evil.tld`. That is exactly the semantic we want for a domain blocklist
 * and it is immune to the `"google.com"` substring problem the docs warn about.
 */
export function buildUrlFilter(host: string): string | null {
  if (host.length === 0 || host.length > 253) return null;
  // `^` and `|` are urlFilter metacharacters; they must not reach the filter.
  if (/[\^|*]/.test(host)) return null;
  if (!/^[a-z0-9.-]+$/.test(host)) return null;
  return `||${host}^`;
}

let sequence = 0;

/**
 * Allocates a rule id whose high digits encode the category, so a matched rule
 * can be classified from the feedback event alone (see RULE_CATEGORY_ORDINAL).
 */
export function allocateRuleId(category: ThreatCategory): number {
  const ordinal = RULE_CATEGORY_ORDINAL[category];
  sequence += 1;
  if (sequence >= RULE_CATEGORY_STRIDE) sequence = 0;
  return ordinal * RULE_CATEGORY_STRIDE + sequence;
}

export function resetRuleIdAllocator(start = 0): void {
  sequence = start;
  void RULE_ID.MIN_DYNAMIC;
}

export function compileRule(input: CompileInput, id: number): CompiledRule | null {
  const urlFilter = buildUrlFilter(input.host);
  if (urlFilter === null) return null;

  const threat = isThreatCategory(input.category);
  const baseResourceTypes = threat ? THREAT_RESOURCE_TYPES : PRIVACY_RESOURCE_TYPES;

  const resourceTypes = input.excludedResourceTypes
    ? baseResourceTypes.filter((t) => !input.excludedResourceTypes!.includes(t))
    : baseResourceTypes;

  if (resourceTypes.length === 0) return null;

  const condition: chrome.declarativeNetRequest.RuleCondition = {
    urlFilter,
    resourceTypes,
  };

  if (input.thirdParty) condition.domainType = 'thirdParty' as DomainTypeName;
  if (input.initiatorDomains && input.initiatorDomains.length > 0) {
    condition.initiatorDomains = [...input.initiatorDomains].slice(0, 100);
  }

  const priority =
    input.priority ?? (input.mainFrameOnly ? RULE_PRIORITY.REDIRECT_NAV : PRIORITY_BY_CATEGORY[input.category]);

  return { id, priority, action: { type: 'block' as ActionTypeName }, condition };
}

/**
 * Allow rule for an allowlist entry.
 *
 * Scope semantics (specification Section 3: "Garantir que exceções para anuncios
 * nao desativem inadvertidamente protecao contra malware"):
 *  - `all`      -> allowAllRequests, the user explicitly opted out of everything.
 *  - `threats`  -> `allow` for every resource type EXCEPT main_frame, at a
 *                  priority ABOVE every threat block band. Clicks through a
 *                  malware/phishing list entry stop being blocked, but you still
 *                  cannot land on the site itself.
 *  - `privacy`  -> `allow` for sub-resources only, at a priority below every
 *                  threat band, so ad/tracker exceptions never touch malware.
 */
export function compileAllowRule(
  domain: string,
  scope: 'all' | 'threats' | 'privacy',
  id: number,
): CompiledRule | null {
  if (!/^[a-z0-9.-]+$/.test(domain) || domain.length === 0 || domain.length > 253) return null;

  if (scope === 'all') {
    return {
      id,
      priority: RULE_PRIORITY.ALLOW_ALL,
      action: { type: 'allowAllRequests' as ActionTypeName },
      condition: {
        urlFilter: `||${domain}^`,
        resourceTypes: ['main_frame', 'sub_frame'],
      },
    };
  }

  const resourceTypes = (scope === 'threats'
    ? [...THREAT_RESOURCE_TYPES]
    : [...PRIVACY_RESOURCE_TYPES]
  ).filter((t) => t !== 'main_frame');

  return {
    id,
    priority: scope === 'threats' ? RULE_PRIORITY.ALLOW_THREATS : RULE_PRIORITY.ALLOW_PRIVACY,
    action: { type: 'allow' as ActionTypeName },
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes,
    },
  };
}

export interface QuotaPlan {
  /** Total rules we are allowed to install. */
  readonly budget: number;
  /** Rules reserved for allowlist entries. */
  readonly reservedForAllowlist: number;
  /** Rules available for dataset rules. */
  readonly datasetBudget: number;
}

export interface RuntimeLimits {
  readonly dynamicSafe: number;
  readonly dynamicUnsafe: number;
  readonly session: number;
}

/** Reads the real limits from the running browser, with documented fallbacks. */
export function readRuntimeLimits(): RuntimeLimits {
  const dnr = chrome.declarativeNetRequest as unknown as Record<string, number | undefined>;
  const dynamicSafe = typeof dnr.MAX_NUMBER_OF_DYNAMIC_RULES === 'number' && dnr.MAX_NUMBER_OF_DYNAMIC_RULES > 0
    ? dnr.MAX_NUMBER_OF_DYNAMIC_RULES
    : DNR_LIMITS.DYNAMIC_SAFE;
  const dynamicUnsafe = typeof dnr.MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES === 'number' && dnr.MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES > 0
    ? dnr.MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES
    : DNR_LIMITS.DYNAMIC_UNSAFE;
  const session = typeof dnr.MAX_NUMBER_OF_SESSION_RULES === 'number' && dnr.MAX_NUMBER_OF_SESSION_RULES > 0
    ? dnr.MAX_NUMBER_OF_SESSION_RULES
    : DNR_LIMITS.SESSION;
  return { dynamicSafe, dynamicUnsafe, session };
}

export function planQuota(limits: RuntimeLimits, allowlistCount: number): QuotaPlan {
  const budget = Math.floor(limits.dynamicSafe * DNR_BUDGET_HEADROOM);
  const reservedForAllowlist = Math.min(Math.max(allowlistCount, 1) * 2, Math.floor(limits.dynamicUnsafe / 2));
  return { budget, reservedForAllowlist, datasetBudget: Math.max(0, budget - reservedForAllowlist) };
}

export interface CompileReport {
  readonly compiled: number;
  readonly rejectedInvalidHost: number;
  readonly droppedForQuota: number;
  readonly duplicatesRemoved: number;
  readonly perCategory: Readonly<Record<string, number>>;
  readonly quota: QuotaPlan;
}

export class RuleCompiler {
  private readonly rules: CompiledRule[] = [];
  private readonly seen = new Set<string>();
  private readonly perCategory = new Map<string, number>();
  private rejectedInvalidHost = 0;
  private duplicatesRemoved = 0;
  private droppedForQuota = 0;
  private readonly datasetBudget: number;

  constructor(quota: QuotaPlan) {
    this.datasetBudget = quota.datasetBudget;
  }

  add(input: CompileInput): boolean {
    const key = `${input.category}|${input.host}|${input.thirdParty ? '3p' : ''}|${(input.initiatorDomains ?? []).join(',')}|${(input.excludedResourceTypes ?? []).join(',')}`;
    if (this.seen.has(key)) {
      this.duplicatesRemoved += 1;
      return false;
    }

    const rule = compileRule(input, allocateRuleId(input.category));
    if (rule === null) {
      this.rejectedInvalidHost += 1;
      return false;
    }

    if (this.rules.length >= this.datasetBudget) {
      this.droppedForQuota += 1;
      return false;
    }

    this.seen.add(key);
    this.rules.push(rule);
    this.perCategory.set(input.category, (this.perCategory.get(input.category) ?? 0) + 1);
    return true;
  }

  report(): CompileReport {
    return {
      compiled: this.rules.length,
      rejectedInvalidHost: this.rejectedInvalidHost,
      droppedForQuota: this.droppedForQuota,
      duplicatesRemoved: this.duplicatesRemoved,
      perCategory: Object.fromEntries(this.perCategory),
      quota: { budget: 0, reservedForAllowlist: 0, datasetBudget: this.datasetBudget },
    };
  }

  get size(): number {
    return this.rules.length;
  }

  drain(): CompiledRule[] {
    return this.rules.slice();
  }
}
