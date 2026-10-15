/**
 * DOM scam-signal scanner.
 *
 * PRIVACY CONTRACT (enforced by tests/unit/privacy-lint.test.ts):
 *  - This function NEVER reads `input.value`, `textarea.value`, or any
 *    `HTMLInputElement` value property.
 *  - It never touches `document.cookie`, `localStorage`, `sessionStorage` or
 *    `indexedDB`.
 *  - It reads only tag names, attribute values (placeholder/aria-label/title),
 *    `textContent` of a bounded number of nodes, and link hrefs.
 *  - Everything stays local: findings are sent to our own service worker and are
 *    never transmitted to a third party.
 *
 * PERFORMANCE CONTRACT:
 *  - Bounded query counts and text sampling.
 *  - No permanent MutationObserver. One pass per invocation.
 *  - Runs at `document_idle` and on explicit user request only.
 */

/* eslint-disable no-restricted-globals -- documented above */
export function SCAM_SCAN_FUNCTION(): void {
  const MAX_TEXT_CHARS = 60_000;
  const MAX_EVIDENCE = 5;
  const MAX_LINKS = 400;

  interface Signal {
    code: string;
    confidence: 'high' | 'medium' | 'low';
    evidence: string[];
  }

  const signals: Signal[] = [];
  const seen = new Set<string>();

  const add = (code: string, confidence: 'high' | 'medium' | 'low', evidence: string[]): void => {
    if (seen.has(code)) return;
    seen.add(code);
    signals.push({ code, confidence, evidence: evidence.slice(0, MAX_EVIDENCE) });
  };

  /**
   * Strips diacritics so the keyword tables below stay ASCII-only and still
   * match Portuguese text such as "atualize" / "virus" / "versao".
   */
  const deaccent = (value: string): string =>
    value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();

  // ---- Page text sample (structure only, no form values) --------------------
  const body = document.body;
  let raw = '';
  if (body) {
    const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
    let node = walker.nextNode() as Text | null;
    while (node !== null && raw.length < MAX_TEXT_CHARS) {
      const value = node.nodeValue ?? '';
      if (value.length > 0) raw += value;
      node = walker.nextNode() as Text | null;
    }
  }
  const text = deaccent(raw).slice(0, MAX_TEXT_CHARS);

  const title = deaccent(document.title ?? '');
  const metaDescription = deaccent(
    document.querySelector('meta[name="description"]')?.getAttribute('content') ?? '',
  );
  const headerText = `${title} ${metaDescription}`;

  const countOf = (needles: string[]): number => {
    let n = 0;
    for (const needle of needles) if (text.includes(needle) || headerText.includes(needle)) n += 1;
    return n;
  };

  // ---- Anchor inventory (hrefs only) --------------------------------------
  const anchors = document.querySelectorAll('a[href]');
  const linkCount = Math.min(anchors.length, MAX_LINKS);
  const externalHosts: string[] = [];
  let executableLinks = 0;

  for (let i = 0; i < linkCount; i += 1) {
    const anchor = anchors[i] as HTMLAnchorElement;
    const href = anchor.getAttribute('href') ?? '';
    if (href.length === 0 || href.startsWith('#') || href.startsWith('javascript:')) continue;
    if (/\.(exe|msi|bat|scr|apk|dmg|pkg|jar|zip)(\?|#|$)/i.test(href)) executableLinks += 1;
    try {
      const url = new URL(anchor.href, window.location.href);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
      if (url.hostname !== window.location.hostname) externalHosts.push(url.hostname);
    } catch {
      /* malformed href */
    }
  }

  // ---- Forms (structure only; never read values) ---------------------------
  const forms = document.querySelectorAll('form');
  const formCount = Math.min(forms.length, 50);
  let credentialForms = 0;
  let brandCredentialForms = 0;

  const BRAND_TOKENS = [
    'paypal', 'apple', 'icloud', 'itunes', 'google', 'gmail', 'microsoft', 'outlook',
    'hotmail', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'banco',
    'itau', 'bradesco', 'santander', 'nubank', 'bb', 'visa', 'mastercard', 'receita',
    'inss', 'gov.br', 'login', 'signin', 'conta',
  ];

  for (let i = 0; i < formCount; i += 1) {
    const form = forms[i] as HTMLFormElement;
    const passwordInputs = form.querySelectorAll('input[type="password"]');
    if (passwordInputs.length === 0) continue;
    credentialForms += 1;

    // Read only ATTRIBUTE metadata - never `.value`.
    const metadata: string[] = [];
    const inputs = form.querySelectorAll('input');
    for (let j = 0; j < Math.min(inputs.length, 24); j += 1) {
      const input = inputs[j] as HTMLInputElement;
      const label = input.getAttribute('placeholder') ?? input.getAttribute('aria-label') ?? input.getAttribute('name') ?? '';
      if (label) metadata.push(label.toLowerCase());
      const type = (input.getAttribute('type') ?? '').toLowerCase();
      if (type === 'tel' || /card|cc|credit|cvv|cvc|cpf|cnpj/i.test(label)) metadata.push('financial-field');
    }
    const formText = ((form.getAttribute('aria-label') ?? '') + ' ' + metadata.join(' ')).toLowerCase();
    if (BRAND_TOKENS.some((token) => formText.includes(token))) brandCredentialForms += 1;
  }

  // ---- Signal 1: fake browser / OS update ----------------------------------
  const updateWords = countOf(['update', 'atualiz', 'upgrade', 'nova vers', 'new version', 'versao mais recente']);
  const browserWords = countOf(['chrome', 'firefox', 'edge', 'safari', 'browser', 'navegador', 'windows', 'android']);
  if (updateWords > 0 && browserWords > 0 && (executableLinks > 0 || countOf(['clique', 'click', 'download', 'baixar', 'instalar']) > 0)) {
    add('scam.fake_browser_update', executableLinks > 0 ? 'high' : 'medium', [
      title.slice(0, 90),
      `update:${updateWords}`,
      `browser:${browserWords}`,
      `exeLinks:${executableLinks}`,
    ]);
  }

  // ---- Signal 2: fake virus / malware alert --------------------------------
  const infectionWords = countOf(['infectad', 'infectado', 'virus', 'malware', 'trojan', 'spyware', 'ameaca']);
  const infectedDevice = /seu (computador|dispositivo|celular|iphone|pc|celular) (esta|esta|foi) infectad/.test(text);
  const fakeCount = /(\d{1,4})\s+(virus|malware|ameaca|threats?)/.test(text) || /foram encontrados/.test(text);
  const fakeScanUi = /(scan|verific|analis)(ando|ei| de seguranca)/.test(text);
  if ((infectedDevice || (infectionWords >= 2 && fakeCount)) && fakeScanUi) {
    add('scam.fake_virus_alert', infectedDevice ? 'high' : 'medium', [
      infectedDevice ? 'device-infected-claim' : 'infection-claims',
      fakeCount ? 'fabricated-count' : '',
      'scan-ui',
    ].filter(Boolean));
  }

  // ---- Signal 3: forced software installation ------------------------------
  const installWords = countOf(['instalar', 'instale', 'install now', 'baixe agora', 'download now', 'clique aqui para instalar']);
  const softwareWords = countOf(['extens', 'extension', 'plugin', 'aplicativo', 'software', 'programa', 'antivirus', 'limpeza']);
  if (installWords > 0 && softwareWords > 0 && (executableLinks > 0 || credentialForms === 0)) {
    add('scam.software_install_prompt', 'medium', [`install:${installWords}`, `software:${softwareWords}`, `exeLinks:${executableLinks}`]);
  }

  // ---- Signal 4: credential form on an unexpected context -------------------
  // A login form is normal. A password field sitting next to financial fields,
  // or a brand name inside the form, is worth a look.
  if (credentialForms > 0 && brandCredentialForms > 0) {
    add('scam.credential_form', brandCredentialForms > credentialForms ? 'medium' : 'low', [
      `forms:${formCount}`,
      `passwordForms:${credentialForms}`,
      `brandForms:${brandCredentialForms}`,
    ]);
  }

  // ---- Signal 5: links pointing at many unrelated external hosts -----------
  const uniqueHosts = [...new Set(externalHosts)];
  if (uniqueHosts.length > 25) {
    add('scam.lookalike_link_domain', 'low', [`externalHosts:${uniqueHosts.length}`, ...uniqueHosts.slice(0, 4)]);
  }

  try {
    chrome.runtime.sendMessage({
      v: 1,
      t: 'content.scamSignals',
      p: {
        url: window.location.href,
        signals,
        formsAnalyzed: forms.length,
        linksAnalyzed: anchors.length,
      },
    });
  } catch {
    // The extension may have been reloaded; the page scan is best-effort.
  }
}
