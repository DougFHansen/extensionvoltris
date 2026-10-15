/**
 * Modelo de dominio do VOLTRIS Browser Shield.
 *
 * Regra de design: nenhuma string de interface e definida aqui. Cada campo que
 * chega a UI carrega uma chave i18n; o texto e resolvido em runtime por
 * `chrome.i18n`. Isso garante que toda string visivel esteja internacionalizada.
 */

/** Categorias de bloqueio exigidas pela especificacao. */
export type ThreatCategory =
  | 'phishing'
  | 'malware'
  | 'malware_distribution'
  | 'scam'
  | 'tracker'
  | 'ad';

/** Categorias que representam risco de dano ao usuario (nao privacidade). */
export const SAFETY_CATEGORIES: readonly ThreatCategory[] = [
  'phishing',
  'malware',
  'malware_distribution',
  'scam',
];

export function isSafetyCategory(c: ThreatCategory): boolean {
  return SAFETY_CATEGORIES.includes(c);
}

/** Categorias de privacidade (rastreadores e anuncios). */
export const PRIVACY_CATEGORIES: readonly ThreatCategory[] = ['tracker', 'ad'];

export function isPrivacyCategory(c: ThreatCategory): boolean {
  return PRIVACY_CATEGORIES.includes(c);
}

/**
 * Classificacao exigida pela especificacao.
 *
 * - `known-malicious`    evidencia de fonte confiavel (feed verificado).
 * - `suspicious`         heuristicas com evidencia relevante.
 * - `no-threat-found`    nenhuma evidencia encontrada. NAO significa seguro.
 * - `not-analyzed`       cobertura ou dados insuficientes para concluir.
 */
export type RiskVerdict = 'known-malicious' | 'suspicious' | 'no-threat-found' | 'not-analyzed';

export type Confidence = 'high' | 'medium' | 'low';

/** Motivo estruturado de uma deteccao. Renderizado via i18n, nunca concat. */
export interface RiskReason {
  /** Identificador estavel, usado em testes e telemetria local. */
  readonly code: RiskReasonCode;
  /** Peso da evidencia (0-100). Usado no calculo de risco. */
  readonly weight: number;
  /** Confianca nesta evidencia especifica. */
  readonly confidence: Confidence;
  /** Categoria e severidade operacional do motivo. */
  readonly severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Dados estruturados adicionais (dominio alvo, provedor, etc.). */
  readonly data?: Readonly<Record<string, string | number | boolean>>;
}

export type RiskReasonCode =
  | 'feed.known_malicious'
  | 'feed.known_phishing'
  | 'feed.known_scam'
  | 'feed.known_malware_distribution'
  | 'punycode_homograph'
  | 'unicode_mixed_script'
  | 'unicode_confusable'
  | 'unicode_bidi_control'
  | 'brand_impersonation_subdomain'
  | 'brand_impersonation_domain'
  | 'deceptive_host_label'
  | 'brand_keyword_in_host'
  | 'suspicious_url_shape'
  | 'suspicious_tld_risk'
  | 'ip_literal_host'
  | 'credential_brand_on_lookalike'
  | 'shortener_unresolved'
  | 'redirect_to_threat'
  | 'scam.browser_update_claim'
  | 'scam.fake_virus_alert'
  | 'scam.software_install_prompt'
  | 'scam.credential_form'
  | 'downloads.double_extension'
  | 'downloads.dangerous_extension'
  | 'downloads.from_known_malicious'
  | 'feed.list_truncated'
  | 'coverage.no_reputation_data'
  | 'coverage.allowlisted'
  | 'coverage.disabled_module';

export interface ThreatSourceInfo {
  readonly providerId: string;
  readonly providerName: string;
  readonly url: string;
  readonly license: string;
  /** Data da informacao no feed (epoch ms). */
  readonly observedAt?: number;
}

/** Resultado completo da analise de uma URL ou dominio. */
export interface AnalysisResult {
  readonly verdict: RiskVerdict;
  readonly score: number;
  readonly confidence: Confidence;
  /** Dominio registravel (PSL) ou `null` quando nao aplicavel. */
  readonly registrableDomain: string | null;
  /** Host normalizado em punycode/ASCII lowercase. */
  readonly hostname: string | null;
  readonly categories: readonly ThreatCategory[];
  readonly reasons: readonly RiskReason[];
  readonly sources: readonly ThreatSourceInfo[];
  /** `true` quando o usuario adicionou o site a lista de permissao. */
  readonly allowlisted: boolean;
  /** Modulos efetivamente ativos (podem desabilitar a analise). */
  readonly modulesActive: readonly string[];
  readonly analyzedAt: number;
}

/** Registro de dominio con malicioso vindo de feed verificado. */
export interface ThreatRecord {
  readonly category: ThreatCategory;
  readonly providerId: string;
  /** epoch ms da primeira observacao no feed. */
  readonly since: number;
  /** Dia do feed no formato AAAAMMDD quando disponivel. */
  readonly feedDay?: string;
}

/** Um host bloqueado em nivel de rede (trackers/ads). */
export interface NetworkBlockRecord {
  readonly category: ThreatCategory;
  readonly providerId: string;
  /** Filtro de origem em sintaxe ABP, preservado para diagnostico. */
  readonly sourceFilter: string;
  /** true se a regra foi restringida a third-party. */
  readonly thirdParty: boolean;
}

export type ProviderStatus =
  | 'active'
  | 'not_configured'
  | 'excluded_license'
  | 'bundled_snapshot'
  | 'stale'
  | 'error'
  | 'disabled';

export interface ProviderDescriptor {
  readonly id: string;
  readonly name: string;
  readonly homepage: string;
  readonly feedUrl: string;
  readonly format: 'hosts' | 'domain-list' | 'adblock';
  readonly license: {
    readonly id: string;
    readonly name: string;
    readonly url: string;
    /** `true` quando verificamos que permite uso comercial. */
    readonly commercialUseAllowed: boolean;
    readonly attribution: string;
  };
  readonly categories: readonly ThreatCategory[];
  /** Frequencia observada de publicacao. */
  readonly updateFrequency: string;
  /** `true` quando exige API key, login ou infraestrutura propria. */
  readonly requiresCredential: boolean;
  /** `true` quando os termos nao autorizam uso comercial. */
  readonly excludedFromProduct: boolean;
  readonly exclusionReason?: string;
  /** Versao do formato de dados consumida. */
  readonly dataVersion: string;
  readonly notes: string;
}

export interface ProviderState {
  readonly id: string;
  readonly status: ProviderStatus;
  readonly lastSuccessAt: number | null;
  readonly lastAttemptAt: number | null;
  readonly lastError: string | null;
  readonly entryCount: number;
  readonly ruleCount: number;
  /** SHA-256 do conteudo bruto validado. */
  readonly contentHash: string | null;
  readonly feedVersion: string | null;
  /** Quantidade de entradas descartadas na conversao (formato nao suportado). */
  readonly skipped: number;
  readonly skippedByReason: Readonly<Record<string, number>>;
}

/** Metadados do conjunto de dados completo. */
export interface DatasetMeta {
  readonly revision: number;
  readonly generatedAt: number;
  readonly providers: readonly ProviderState[];
  /** Versao do formato do dataset (para migração). */
  readonly schemaVersion: number;
}

/** Lista completa de dominios maliciosos, indexada por host. */
export type ThreatIndex = Readonly<Record<string, ThreatRecord>>;

/** Regras de rede compiladas, indexadas por host de destino. */
export type NetworkBlockIndex = Readonly<Record<string, NetworkBlockRecord>>;

/** Escopo de uma excecao (allowlist). */
export type AllowlistScope =
  | 'all'
  | 'threats'
  | 'privacy';

export interface AllowlistEntry {
  /** Dominio registravel (ASCII, lowercase, punycode). */
  readonly domain: string;
  readonly scope: AllowlistScope;
  readonly addedAt: number;
  readonly enabled: boolean;
  /** Ultima URL bloqueada que motivou a adicao (apenas dominio, nunca caminho). */
  readonly addedFrom?: string;
}

export type HistoryKind =
  | 'threat_blocked'
  | 'suspicious_detected'
  | 'tracker_blocked'
  | 'ad_blocked'
  | 'download_flagged'
  | 'scam_signals'
  | 'list_updated'
  | 'list_error'
  | 'allowlist_changed';

export interface HistoryEvent {
  readonly id: string;
  readonly kind: HistoryKind;
  readonly at: number;
  /** Dominio afetado. Nunca armazenamos o caminho completo por padrao. */
  readonly domain: string;
  readonly category?: ThreatCategory;
  readonly verdict?: RiskVerdict;
  /** Chave i18n do motivo principal. */
  readonly reasonCode?: RiskReasonCode;
  readonly providerId?: string;
  /** Caminho completo, somente se o usuario habilitou `storeFullUrls`. */
  readonly url?: string;
}

/**
 * Local statistics.
 *
 * METRIC HONESTY CONTRACT
 * -----------------------
 * Every field here is incremented ONLY from an event we genuinely observed
 * through an API that is available in a PUBLISHED extension.
 *
 * Specifically, we do NOT count matched rules via
 * `declarativeNetRequest.onRuleMatchedDebug`. That API is documented as
 * "only available for unpacked extensions ... intended to be used for debugging
 * purposes only", so a counter built on it would read 0 in a store install and
 * silently under-report. See `src/background/observation.ts`.
 *
 * What we CAN and CANNOT count is declared explicitly in `METRIC_CAPABILITIES`
 * and surfaced in the dashboard, so the interface never implies a number it
 * cannot substantiate.
 */
export interface Stats {
  /** Top-level navigations we verified were blocked by one of our rules. */
  readonly blockedNavigations: number;
  /** Same, split by threat category. */
  readonly blockedNavigationsByCategory: Readonly<Partial<Record<ThreatCategory, number>>>;
  /** Detections made by the analysis engine (independent of any block). */
  readonly suspiciousDetected: number;
  readonly downloadsFlagged: number;
  readonly downloadsCancelled: number;
  /** Sites the user added to the allowlist. */
  readonly allowlisted: number;
  /** Derived from `blockedNavigations`. */
  readonly blockedByDay: Readonly<Record<string, number>>;
  /** Derived from `blockedNavigations`. */
  readonly topBlockedDomains: Readonly<Record<string, number>>;
  readonly updatedAt: number;
}

export function emptyStats(): Stats {
  return {
    blockedNavigations: 0,
    blockedNavigationsByCategory: {},
    suspiciousDetected: 0,
    downloadsFlagged: 0,
    downloadsCancelled: 0,
    allowlisted: 0,
    blockedByDay: {},
    topBlockedDomains: {},
    updatedAt: 0,
  };
}

/**
 * What this build can actually measure.
 *
 * Published in the dashboard so the user sees exactly which numbers are real
 * observations and which are simply not available, rather than being shown a
 * plausible-looking figure that we cannot substantiate.
 */
export interface MetricCapability {
  readonly id: string;
  readonly available: boolean;
  /** Why it is unavailable, when it is. */
  readonly reason?: string;
}

/**
 * Metric inventory.
 *
 * `available` is decided at runtime, never assumed.
 */
export const METRIC_CAPABILITIES = {
  /** Top-level navigations blocked by our own rules. Available everywhere. */
  blockedNavigations: true,
  /** Detections produced by the URL analysis engine. Available everywhere. */
  detections: true,
  /** Download warnings, from `chrome.downloads`. Available everywhere. */
  downloadWarnings: true,
  /**
   * Installed and active rule count. This is STATE, not an event count: it says
   * how much protection is installed, never how many times it fired.
   */
  rulesInstalled: true,
  /**
   * Per-request block counts for sub-resources (images, scripts, trackers).
   *
   * Requires `declarativeNetRequest.onRuleMatchedDebug`, which Chrome documents
   * as unpacked-only. We therefore report it as unavailable instead of
   * inventing a number.
   */
  subResourceRequestsBlocked: false,
} as const satisfies Record<string, boolean>;

/** Configuracoes do usuario. Toda chave tem valor padrao e validacao. */
export interface Settings {
  readonly version: number;

  // -- Protecao web
  readonly protectionEnabled: boolean;
  readonly blockMalware: boolean;
  readonly blockPhishing: boolean;
  readonly blockScam: boolean;
  readonly blockMalwareDistribution: boolean;

  // -- Phishing e golpes
  readonly phishingEngineEnabled: boolean;
  readonly showHoverWarnings: boolean;
  readonly scamPageAnalysis: boolean;

  // -- Privacidade
  readonly blockTrackers: boolean;
  readonly blockAds: boolean;
  readonly blockThirdPartyOnly: boolean;

  // -- Downloads
  readonly downloadProtection: boolean;
  /** `alert` = apenas notifica; `cancel` = cancela quando a confianca for alta. */
  readonly downloadAction: 'alert' | 'cancel';
  readonly warnDangerousExtensions: boolean;
  readonly warnDoubleExtensions: boolean;

  // -- Privacidade dos dados
  readonly storeHistory: boolean;
  readonly storeFullUrls: boolean;
  readonly showNotifications: boolean;

  // -- Atualizacao
  readonly autoUpdate: boolean;
  readonly updateIntervalHours: number;

  // -- Aparencia
  readonly theme: 'system' | 'light' | 'dark';
  /** Reduz animacoes para usuarios sensiveis. */
  readonly reducedMotion: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  version: 1,

  protectionEnabled: true,
  blockMalware: true,
  blockPhishing: true,
  blockScam: true,
  blockMalwareDistribution: true,

  phishingEngineEnabled: true,
  showHoverWarnings: true,
  scamPageAnalysis: true,

  blockTrackers: true,
  blockAds: false,
  blockThirdPartyOnly: true,

  downloadProtection: true,
  downloadAction: 'alert',
  warnDangerousExtensions: true,
  warnDoubleExtensions: true,

  storeHistory: true,
  storeFullUrls: false,
  showNotifications: true,

  autoUpdate: true,
  updateIntervalHours: 12,

  theme: 'system',
  reducedMotion: false,
};

/** Deteccao de sinais de golpe na pagina (content script). */
export interface PageSignals {
  readonly url: string;
  readonly hostname: string | null;
  readonly signals: readonly ScamSignal[];
  readonly formsAnalyzed: number;
  readonly linksAnalyzed: number;
  readonly analyzedAt: number;
}

export interface ScamSignal {
  readonly code:
    | 'scam.fake_browser_update'
    | 'scam.fake_virus_alert'
    | 'scam.software_install_prompt'
    | 'scam.credential_form'
    | 'scam.lookalike_link_domain';
  readonly confidence: Confidence;
  /** Rótulos textuais encontrados (placeholders/labels), nunca valores digitados. */
  readonly evidence: readonly string[];
}

export type DownloadRiskVerdict = 'safe' | 'caution' | 'dangerous';

export interface DownloadAnalysis {
  readonly verdict: DownloadRiskVerdict;
  readonly confidence: Confidence;
  readonly filename: string;
  readonly extension: string;
  readonly reasons: readonly RiskReason[];
  readonly sourceDomain: string | null;
  readonly sourceVerdict: RiskVerdict | null;
  /** true quando a acao esta tecnicamente disponivel na API escolhida. */
  readonly cancellable: boolean;
}

export interface LinkInspection {
  readonly url: string;
  readonly hostname: string | null;
  readonly result: AnalysisResult;
}
