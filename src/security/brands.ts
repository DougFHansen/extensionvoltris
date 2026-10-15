/**
 * Brand reference data used by the impersonation engine.
 *
 * Purpose: detect hosts that try to *look* like a trusted brand without being
 * that brand. We match on two independent signals:
 *
 *   1. `PROTECTED_DOMAINS` - the brand's real registrable domain. A host that is
 *      NOT this domain but CONTAINS it as a label or as a leftmost subdomain
 *      prefix is impersonation (for example `paypal.com.br-login.tk`).
 *
 *   2. `BRAND_KEYWORDS` - bare brand words used inside a registrable domain that
 *      the brand does not own (for example `paypal-verificacao.tk`). Only fires
 *      in combination with other evidence; a keyword alone is a weak signal.
 *
 * This file is intentionally compact and fully auditable. It is NOT a complete
 * brand registry and the engine never claims to be exhaustive.
 */

export interface BrandEntry {
  /** Registrable domain owned by the brand. */
  readonly domain: string;
  /** i18n key describing the brand for the UI. */
  readonly nameKey: string;
  /** Higher weight means the impersonation is more damaging. */
  readonly weight: 'critical' | 'high';
}

const CRITICAL = 'critical';
const HIGH = 'high';

export const PROTECTED_DOMAINS: readonly BrandEntry[] = [
  // -- Authentication / identity
  { domain: 'google.com', nameKey: 'brand_google', weight: CRITICAL },
  { domain: 'accounts.google.com', nameKey: 'brand_google', weight: CRITICAL },
  { domain: 'microsoft.com', nameKey: 'brand_microsoft', weight: CRITICAL },
  { domain: 'live.com', nameKey: 'brand_microsoft', weight: CRITICAL },
  { domain: 'apple.com', nameKey: 'brand_apple', weight: CRITICAL },
  { domain: 'icloud.com', nameKey: 'brand_apple', weight: CRITICAL },
  { domain: 'mozilla.org', nameKey: 'brand_mozilla', weight: HIGH },
  { domain: 'dropbox.com', nameKey: 'brand_dropbox', weight: HIGH },
  { domain: 'lastpass.com', nameKey: 'brand_lastpass', weight: CRITICAL },

  // -- Finance
  { domain: 'paypal.com', nameKey: 'brand_paypal', weight: CRITICAL },
  { domain: 'bankofamerica.com', nameKey: 'brand_bankofamerica', weight: CRITICAL },
  { domain: 'chase.com', nameKey: 'brand_chase', weight: CRITICAL },
  { domain: 'wellsfargo.com', nameKey: 'brand_wellsfargo', weight: CRITICAL },
  { domain: 'citibank.com', nameKey: 'brand_citibank', weight: CRITICAL },
  { domain: 'bradesco.com.br', nameKey: 'brand_bradesco', weight: CRITICAL },
  { domain: 'bb.com.br', nameKey: 'brand_bb', weight: CRITICAL },
  { domain: 'itau.com.br', nameKey: 'brand_itau', weight: CRITICAL },
  { domain: 'santander.com.br', nameKey: 'brand_santander', weight: CRITICAL },
  { domain: 'nubank.com.br', nameKey: 'brand_nubank', weight: CRITICAL },
  { domain: 'inter.com.br', nameKey: 'brand_inter', weight: CRITICAL },
  { domain: 'mercadopago.com', nameKey: 'brand_mercadopago', weight: CRITICAL },
  { domain: 'pagseguro.com.br', nameKey: 'brand_pagseguro', weight: CRITICAL },
  { domain: 'visa.com', nameKey: 'brand_visa', weight: CRITICAL },
  { domain: 'mastercard.com', nameKey: 'brand_mastercard', weight: CRITICAL },
  { domain: 'payoneer.com', nameKey: 'brand_payoneer', weight: HIGH },
  { domain: 'westernunion.com', nameKey: 'brand_westernunion', weight: CRITICAL },

  // -- Retail / commerce / delivery
  { domain: 'amazon.com', nameKey: 'brand_amazon', weight: CRITICAL },
  { domain: 'amazon.com.br', nameKey: 'brand_amazon', weight: CRITICAL },
  { domain: 'mercadolivre.com.br', nameKey: 'brand_mercadolivre', weight: HIGH },
  { domain: 'shopify.com', nameKey: 'brand_shopify', weight: HIGH },
  { domain: 'aliexpress.com', nameKey: 'brand_aliexpress', weight: HIGH },
  { domain: 'fedex.com', nameKey: 'brand_fedex', weight: HIGH },
  { domain: 'ups.com', nameKey: 'brand_ups', weight: HIGH },
  { domain: 'dhl.com', nameKey: 'brand_dhl', weight: HIGH },
  { domain: 'correios.com.br', nameKey: 'brand_correios', weight: HIGH },

  // -- Telecom / utilities / government (BR)
  { domain: 'claro.com.br', nameKey: 'brand_claro', weight: HIGH },
  { domain: 'vivo.com.br', nameKey: 'brand_vivo', weight: HIGH },
  { domain: 'tim.com.br', nameKey: 'brand_tim', weight: HIGH },
  { domain: 'oi.com.br', nameKey: 'brand_oi', weight: HIGH },
  { domain: 'net.com.br', nameKey: 'brand_net', weight: HIGH },
  { domain: 'gov.br', nameKey: 'brand_gov_br', weight: CRITICAL },
  { domain: 'receita.fazenda.gov.br', nameKey: 'brand_receita', weight: CRITICAL },
  { domain: 'inss.gov.br', nameKey: 'brand_inss', weight: CRITICAL },
  { domain: 'banco.gov.br', nameKey: 'brand_bcb', weight: CRITICAL },

  // -- Technology / developer
  { domain: 'github.com', nameKey: 'brand_github', weight: HIGH },
  { domain: 'gitlab.com', nameKey: 'brand_gitlab', weight: HIGH },
  { domain: 'microsoftonline.com', nameKey: 'brand_microsoft', weight: CRITICAL },
  { domain: 'office.com', nameKey: 'brand_office', weight: CRITICAL },
  { domain: 'outlook.com', nameKey: 'brand_outlook', weight: CRITICAL },
  { domain: 'adobe.com', nameKey: 'brand_adobe', weight: HIGH },
  { domain: 'amazonaws.com', nameKey: 'brand_aws', weight: HIGH },
  { domain: 'cloudflare.com', nameKey: 'brand_cloudflare', weight: HIGH },
];

/** Fast lookup: registrable domain -> entry. */
export const BRAND_DOMAIN_INDEX: ReadonlyMap<string, BrandEntry> = new Map(
  PROTECTED_DOMAINS.map((b) => [b.domain, b]),
);

/**
 * Domains that legitimately embed third-party brands as subdomains. Used to
 * avoid false positives such as `googleadservices.com` or `paypalobjects.com`.
 */
export const BRAND_ALLOW_EXCEPTIONS: ReadonlySet<string> = new Set([
  'googleadservices.com',
  'googleapis.com',
  'googleusercontent.com',
  'gstatic.com',
  'googletagmanager.com',
  'doubleclick.net',
  'paypalobjects.com',
  'paypal.com.br',
  'microsoftonline-p.com',
  'office.net',
  'live.com.cn',
  'amazonaws.com.cn',
  'awsstatic.com',
  'cloudfront.net',
  'akamaized.net',
  'akamaihd.net',
]);

/**
 * Bare brand words. Matched ONLY as a whole label segment inside a registrable
 * domain the brand does not own, and always combined with another signal.
 */
export const BRAND_KEYWORDS: readonly string[] = [
  'paypal', 'apple', 'icloud', 'itunes', 'netflix', 'facebook', 'instagram',
  'whatsapp', 'telegram', 'linkedin', 'twitter', 'tiktok', 'snapchat',
  'microsoft', 'office', 'outlook', 'hotmail', 'onedrive', 'sharepoint',
  'google', 'gmail', 'youtube', 'chrome', 'android', 'playstore',
  'amazon', 'aws', 'prime', 'bin', 'shopee', 'aliexpress', 'ebay',
  'nubank', 'itau', 'bradesco', 'santander', 'bb', 'inter', 'caixa',
  'visa', 'mastercard', 'elo', 'payoneer', 'westernunion', 'remessa',
  'netflix', 'disney', 'spotify', 'hulu', 'roku', 'kindle',
  'gov', 'receita', 'inss', 'serpro', 'cpf', 'pix', 'bacen',
  'steam', 'epicgames', 'roblox', 'fortnite', 'minecraft', 'playstation',
  'xbox', 'nintendo', 'samsung', 'lg', 'sony', 'dyson', 'tesla',
  'dropbox', 'onedrive', 'wetransfer', 'mega', 'degoo',
];
