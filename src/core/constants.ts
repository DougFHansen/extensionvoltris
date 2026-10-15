/**
 * Limites verificados na documentacao oficial do Chrome (declarativeNetRequest).
 * Fonte: https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest
 * Verificado em: 2026-10-13
 *
 * Estes valores sao usados APENAS como fallback defensivo. Em tempo de execucao a
 * extensao le as constantes reais expostas pela API e por `getDynamicRules()`.
 */
import type { ThreatCategory } from './types';

export const DNR_LIMITS = {
  /** Chrome 121+: 30.000 regras dinamicas "seguras". */
  DYNAMIC_SAFE: 30_000,
  /** Chrome 120-: 5.000 regras dinamicas "nao seguras" (regex / header modification). */
  DYNAMIC_UNSAFE: 5_000,
  /** Regras de sessao (limpa a cada reinicio do navegador). */
  SESSION: 5_000,
  /** Regras com regexFilter, por tipo de ruleset. */
  REGEX: 1_000,
  /** Rulesets estaticos habilitados simultaneamente. */
  ENABLED_STATIC_RULESETS: 50,
  /** Rulesets estaticos declarados no manifesto. */
  DECLARED_STATIC_RULESETS: 100,
  /** Minimo garantido de regras estaticas, coletivo a todas as extensions. */
  GUARANTEED_STATIC_MINIMUM: 30_000,
} as const;

/**
 * Reserva de seguranca aplicada sobre o limite real da API. Nunca publicamos
 * mais regras do que o que sobra, mesmo que a constante mude entre versoes.
 */
export const DNR_BUDGET_HEADROOM = 0.9;

/**
 * Precedencia de regras confirmada na documentacao oficial:
 *
 *   "Chrome finds a matching rule, by ordering all matching rules by priority.
 *    Rules with the same priority are ordered by action
 *    (allow or allowAllRequests > block > upgradeScheme > redirect)."
 *
 * Portanto NAO confiamos na ordem entre static/dynamic/session (nao documentada e
 * diferente entre Chrome e Edge). Cada faixa logica usa um `priority` explicito,
 * o que torna o comportamento deterministico nos dois navegadores.
 */
export const RULE_PRIORITY = {
  /** allowAllRequests - usuario desativou toda protecao para o site. */
  ALLOW_ALL: 1_000_000,
  /** allow sem main_frame - excecao explicita de malware/phishing. */
  ALLOW_THREATS: 50_000,
  /** allow sem main_frame - excecao de rastreadores e anuncios. */
  ALLOW_PRIVACY: 10_000,
  BLOCK_MALWARE: 40_000,
  BLOCK_PHISHING: 35_000,
  BLOCK_SCAM: 30_000,
  /** redirect main_frame -> pagina de alerta da extensao. */
  REDIRECT_NAV: 28_000,
  BLOCK_TRACKERS: 8_000,
  BLOCK_ADS: 6_000,
  /** Regra de diagnostico/rotulo (nao deve existir em producao). */
  RESERVED_TEST: 1,
} as const;

/**
 * Rule ids encode their category.
 *
 * WHY: when a request is blocked we must name the category that caused it, and
 * in a published extension the only evidence available is the URL itself. A
 * self-describing id means an id can always be read back to a category without
 * a storage lookup and without relying on an API that exists only in
 * development builds. The mapping is deterministic, so it survives a service
 * worker restart.
 *
 * Layout: `id = CATEGORY_STRIDE * categoryOrdinal + sequence`
 *   1 malware, 2 malware_distribution, 3 phishing, 4 scam, 5 tracker, 6 ad
 *
 * The largest id is 6 * 100_000_000 + 99_999 = 600_099_999, comfortably below the
 * 2^31-1 upper bound Chrome enforces on rule ids.
 *
 * NOTE: production attribution uses the threat dataset, not this function (see
 * `src/background/observation.ts`). The encoding is retained because it keeps
 * the installed rule set self-describing for diagnostics and for `getMatchedRules`
 * during local development.
 */
export const RULE_CATEGORY_ORDINAL = {
  malware: 1,
  malware_distribution: 2,
  phishing: 3,
  scam: 4,
  tracker: 5,
  ad: 6,
} as const satisfies Record<ThreatCategory, number>;

export const RULE_CATEGORY_STRIDE = 100_000_000;

/** Rule id ranges. */
export const RULE_ID = {
  MIN_DYNAMIC: RULE_CATEGORY_STRIDE,
  MAX_DYNAMIC: 7 * RULE_CATEGORY_STRIDE - 1,
  /** Allowlist session rules use a small, separate range. */
  SESSION_BASE: 1_000,
  /** Reserved for tests and diagnostics. */
  MIN_TEST: 1,
  MAX_TEST: 999,
} as const;

/** Recovers the category from a rule id, or null for an unknown bucket. */
export function categoryFromRuleId(ruleId: number): ThreatCategory | null {
  const ordinal = Math.floor(ruleId / RULE_CATEGORY_STRIDE);
  for (const [category, value] of Object.entries(RULE_CATEGORY_ORDINAL)) {
    if (value === ordinal) return category as ThreatCategory;
  }
  return null;
}

/**
 * Default `chrome.storage.local` quota, without the `unlimitedStorage`
 * permission. Chrome documents the limit as 10 MB and states it "can be
 * increased by requesting the unlimitedStorage permission".
 */
export const STORAGE_QUOTA_BYTES = 10 * 1024 * 1024;

/**
 * Ceiling for the packed threat dataset.
 *
 * WHY THIS IS NOT THE STORAGE QUOTA
 * --------------------------------
 * This used to be 90% of the 10 MB storage quota. Measured against the real
 * feeds on 2026-10-15, the packed dataset is:
 *
 *   phishing-database-domains  386,093 entries  20.83 MiB
 *   stevenblack-hosts            73,278 entries   2.90 MiB
 *   easylist                     50,327 entries   1.84 MiB
 *   easyprivacy                  47,235 entries   1.91 MiB
 *   ------------------------------------------------
 *   total                                   27.47 MiB
 *
 * The old limit tripped on every fresh install. Because a fresh install has no
 * previous dataset to preserve, the update returned "previous preserved", the
 * rules were never built, and the extension ran with ZERO protection while
 * reporting success. Every user, every install. The end-to-end suite never saw
 * it because it seeds threats directly into storage, bypassing this path.
 *
 * With `unlimitedStorage` the browser quota is no longer the binding
 * constraint, so the ceiling is a real engineering budget instead.
 *
 * WHY NOT TRUNCATE INSTEAD
 * ------------------------
 * Cutting the dataset down to fit an arbitrary byte budget was rejected. The
 * feeds are sorted ASCII, not by date, so keeping the first N entries would
 * retain only domains beginning with a few letters - a biased, arbitrary
 * subset presented as complete. Silently dropping known phishing domains is the
 * exact failure mode this project refuses elsewhere. 64 MiB is comfortably
 * under the ~27 MiB real size and far below any plausible disk budget.
 */
export const DATASET_MAX_BYTES = 64 * 1024 * 1024;

/**
 * Defensive ceiling on local storage overall, well above the dataset, so a
 * runaway write cannot fill the user's disk without bound.
 */
export const STORAGE_SOFT_LIMIT_BYTES = Math.floor(STORAGE_QUOTA_BYTES * 0.9);

/** Numero maximo de eventos mantidos no historico local. */
export const HISTORY_MAX_ITEMS = 300;

/** Tamanho maximo aceito para qualquer payload de mensagem interno. */
export const MESSAGE_MAX_LENGTH = 64 * 1024;

/** Duracao minima entre atualizacoes de feed (chrome.alarms). */
export const FEED_MIN_UPDATE_INTERVAL_MIN = 30;

/** Duracao maxima entre atualizacoes de feed. */
export const FEED_MAX_UPDATE_INTERVAL_MIN = 24 * 60;
