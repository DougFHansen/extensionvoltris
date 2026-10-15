/**
 * Unicode deception detection: homographs, mixed scripts, confusables and
 * bidirectional control characters.
 *
 * Threat model: an attacker registers `pаypal.com` (Cyrillic `a`) or
 * `paypaI.com` (capital I) so the domain renders like a trusted brand while the
 * real registrable domain is entirely attacker-controlled.
 *
 * We deliberately use a SMALL curated skeleton table rather than the full
 * Unicode confusables.txt. A curated table keeps the bundle small, is fully
 * auditable, and avoids the false-positive storm that the full table causes on
 * legitimate non-Latin domains.
 *
 * Every non-ASCII literal in this file is written as a \u escape so the source
 * stays ASCII-only and reviewable in any editor.
 */

/**
 * ASCII letters that are commonly substituted in homograph attacks, mapped to
 * the skeleton letter they impersonate. Covers Latin/Cyrillic/Greek look-alikes.
 */
const SKELETON: Readonly<Record<string, string>> = {
  // Cyrillic lowercase
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u04bb': 'h',
  '\u0456': 'i', '\u0458': 'j', '\u0455': 's', '\u0453': 'g',
  // Cyrillic uppercase (the subset that renders as Latin capitals)
  '\u0410': 'a', '\u0412': 'b', '\u0415': 'e', '\u041a': 'k',
  '\u041c': 'm', '\u041d': 'h', '\u041e': 'o', '\u0420': 'p',
  '\u0421': 'c', '\u0422': 't', '\u0423': 'y', '\u0425': 'x',
  '\u0401': 'yo', '\u0405': 's', '\u0406': 'i', '\u0408': 'j',
  // Cyrillic supplements
  '\u04cf': 'l', '\u051b': 'q', '\u04af': 'l', '\u04e3': 'g',
  // Greek lowercase
  '\u03b1': 'a', '\u03b5': 'e', '\u03b9': 'i', '\u03bf': 'o',
  '\u03c1': 'p', '\u03c5': 'u', '\u03c7': 'x', '\u03bd': 'v',
  '\u03ba': 'k', '\u03c3': 'o', '\u03bc': 'u', '\u03a9': 'o',
  // Greek uppercase
  '\u0391': 'a', '\u0395': 'e', '\u0399': 'i', '\u039f': 'o',
  '\u03a1': 'p', '\u03a5': 'u', '\u03a7': 'x',
  // Armenian / Cherokee / other frequent abuse
  '\u0570': 'h', '\u0585': 'o', '\u13a0': 'a', '\u13c2': 'b',
  '\u13ac': 'g', '\u13b3': 'h', '\u13ce': 'z', '\ua4d7': 'a',
  // Fullwidth Latin -> ASCII (upper and lower case)
  '\uff21': 'a', '\uff22': 'b', '\uff23': 'c', '\uff24': 'd',
  '\uff25': 'e', '\uff26': 'f', '\uff27': 'g', '\uff28': 'h',
  '\uff29': 'i', '\uff2a': 'j', '\uff2B': 'k', '\uff2C': 'l',
  '\uff2D': 'm', '\uff2E': 'n', '\uff2F': 'o', '\uff30': 'p',
  '\uff31': 'q', '\uff32': 'r', '\uff33': 's', '\uff34': 't',
  '\uff35': 'u', '\uff36': 'v', '\uff37': 'w', '\uff38': 'x',
  '\uff39': 'y', '\uff3A': 'z',
  '\uff41': 'a', '\uff42': 'b', '\uff43': 'c', '\uff44': 'd',
  '\uff45': 'e', '\uff46': 'f', '\uff47': 'g', '\uff48': 'h',
  '\uff49': 'i', '\uff4A': 'j', '\uff4B': 'k', '\uff4C': 'l',
  '\uff4D': 'm', '\uff4E': 'n', '\uff4F': 'o', '\uff50': 'p',
  '\uff51': 'q', '\uff52': 'r', '\uff53': 's', '\uff54': 't',
  '\uff55': 'u', '\uff56': 'v', '\uff57': 'w', '\uff58': 'x',
  '\uff59': 'y', '\uff5A': 'z',
  // Latin-1 / Latin Extended look-alikes
  '\u00e9': 'e', '\u00e8': 'e', '\u00ea': 'e', '\u00eb': 'e',
  '\u00e0': 'a', '\u00e1': 'a', '\u00e3': 'a', '\u00e2': 'a',
  '\u00ed': 'i', '\u00ee': 'i', '\u00ef': 'i', '\u00ec': 'i',
  '\u00f3': 'o', '\u00f4': 'o', '\u00f5': 'o', '\u00f6': 'o',
  '\u00fa': 'u', '\u00fb': 'u', '\u00fc': 'u', '\u00f9': 'u',
  '\u00e7': 'c', '\u00f1': 'n', '\u00df': 's',
  '\u0161': 's', '\u010d': 'c', '\u010f': 'd', '\u0111': 'e',
  '\u0142': 'l', '\u0131': 'i', '\u0130': 'i', '\u017f': 's',
  '\u0153': 'oe', '\u0152': 'oe', '\u0138': 'k', '\u00fe': 'p',
};

/**
 * Unicode scripts we are willing to see ALONE in a hostname. A label that mixes
 * two of these scripts is suspicious (e.g. Latin + Cyrillic in `pаypal`).
 */
const ALLOWED_SOLO_SCRIPTS = new Set(['Latin', 'Common', 'Inherited', 'Han', 'Arabic', 'Hebrew', 'Hiragana', 'Katakana', 'Hangul', 'Thai', 'Devanagari', 'Greek']);

/**
 * Bidirectional formatting and other invisible control characters. These have no
 * legitimate use in a hostname and are a classic way to hide the real
 * registrable domain from a human reading the address bar.
 */
const BIDI_AND_INVISIBLE = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u00ad\u200b\u200c\u200d\u2060\ufeff\u180e]/;

/** Zero-width and invisible characters. */
const ZERO_WIDTH_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

const PUNYCODE_RE = /^xn--/;

export interface UnicodeFinding {
  readonly kind: 'homograph' | 'mixed_script' | 'confusable' | 'bidi' | 'zero_width' | 'punycode';
  /** Confianca da deteccao. */
  readonly confidence: 'high' | 'medium' | 'low';
  /** Label do hostname onde a evidencia foi encontrada. */
  readonly label: string;
  /** Detalhes estruturados para exibicao (nunca concatenados em HTML). */
  readonly data: Readonly<Record<string, string | number | boolean>>;
}

/**
 * Coarse Unicode script detection using range tables.
 * This is intentionally pragmatic: full UAX #24 script resolution would add a
 * large table for marginal benefit in this threat model.
 */
export function scriptOf(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  if (cp >= 0x41 && cp <= 0x5a) return 'Latin';
  if (cp >= 0x61 && cp <= 0x7a) return 'Latin';
  if (cp >= 0xc0 && cp <= 0x24f) return 'Latin';
  if (cp >= 0x1e00 && cp <= 0x1eff) return 'Latin';
  if (cp >= 0x2c60 && cp <= 0x2c7f) return 'Latin';
  if (cp >= 0x400 && cp <= 0x4ff) return 'Cyrillic';
  if (cp >= 0x500 && cp <= 0x52f) return 'Cyrillic';
  if (cp >= 0x2de0 && cp <= 0x2dff) return 'Cyrillic';
  if (cp >= 0xa640 && cp <= 0xa69f) return 'Cyrillic';
  if (cp >= 0x370 && cp <= 0x3ff) return 'Greek';
  if (cp >= 0x1f00 && cp <= 0x1fff) return 'Greek';
  if (cp >= 0x590 && cp <= 0x5ff) return 'Hebrew';
  if (cp >= 0x600 && cp <= 0x6ff) return 'Arabic';
  if (cp >= 0x750 && cp <= 0x77f) return 'Arabic';
  if (cp >= 0x3040 && cp <= 0x309f) return 'Hiragana';
  if (cp >= 0x30a0 && cp <= 0x30ff) return 'Katakana';
  if (cp >= 0xac00 && cp <= 0xd7af) return 'Hangul';
  if (cp >= 0x1100 && cp <= 0x11ff) return 'Hangul';
  if (cp >= 0x4e00 && cp <= 0x9fff) return 'Han';
  if (cp >= 0x3040 && cp <= 0x30ff) return 'Han';
  if (cp >= 0x0e00 && cp <= 0x0e7f) return 'Thai';
  if (cp >= 0x0900 && cp <= 0x097f) return 'Devanagari';
  if (cp >= 0x0530 && cp <= 0x058f) return 'Armenian';
  if (cp >= 0x13a0 && cp <= 0x13ff) return 'Cherokee';
  if (cp >= 0x3040 && cp <= 0x30ff) return 'Kana';
  if (cp >= 0xff00 && cp <= 0xffef) return 'Fullwidth';
  if (cp >= 0x2000 && cp <= 0x206f) return 'Common';
  if (cp >= 0x2190 && cp <= 0x2bff) return 'Common';
  if (cp >= 0x3000 && cp <= 0x303f) return 'Common';
  return 'Common';
}

/** Reduces a label to its confusable skeleton for comparison. */
export function skeletonize(label: string): string {
  let out = '';
  for (const ch of label) {
    const mapped = SKELETON[ch];
    if (mapped !== undefined) {
      out += mapped;
    } else {
      out += ch.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
    }
  }
  return out;
}

export interface UnicodeAnalysisInput {
  /** Host as typed by the user (may contain Unicode). */
  readonly unicodeHost: string | null;
  /** Host in punycode/ASCII form. */
  readonly asciiHost: string | null;
  /** Rótulos do domínio registrável (exclui o sufixo público). */
  readonly labels: readonly string[];
}

export interface UnicodeAnalysis {
  readonly findings: readonly UnicodeFinding[];
  /** Rótulo com maior pontuação de confusão (skeleton + marcas). */
  readonly worstLabel: string | null;
  /** 0-100. Acima de ~60 tratamos como forte evidência de homografia. */
  readonly homographScore: number;
  readonly hasNonAscii: boolean;
}

/** Analyze a host for Unicode deception signals. Pure and side-effect free. */
export function analyzeUnicode(input: UnicodeAnalysisInput): UnicodeAnalysis {
  const findings: UnicodeFinding[] = [];
  const unicodeHost = input.unicodeHost ?? '';
  const asciiHost = input.asciiHost ?? '';

  const hasNonAscii = /[^\x00-\x7F]/.test(unicodeHost);

  // 1. Bidi / invisible controls: never legitimate in a hostname.
  if (BIDI_AND_INVISIBLE.test(unicodeHost)) {
    const match = BIDI_AND_INVISIBLE.exec(unicodeHost);
    findings.push({
      kind: 'bidi',
      confidence: 'high',
      label: '',
      data: { codePoint: match ? (match[0].codePointAt(0) ?? 0).toString(16) : '' },
    });
  }

  // 2. Punycode labels.
  for (const label of input.labels) {
    if (PUNYCODE_RE.test(label)) {
      findings.push({ kind: 'punycode', confidence: 'medium', label, data: {} });
    }
  }

  // 3. Zero-width characters used to break up a brand name.
  if (ZERO_WIDTH_RE.test(unicodeHost)) {
    findings.push({ kind: 'zero_width', confidence: 'high', label: '', data: {} });
  }

  // 4. Mixed scripts + confusable skeleton, evaluated per label.
  let worstLabel: string | null = null;
  let worstScore = 0;

  for (const label of input.labels) {
    const scripts = new Set<string>();
    let confusableHits = 0;
    let asciiLetterCount = 0;

    for (const ch of label) {
      const mapped = SKELETON[ch];
      if (mapped !== undefined) confusableHits += 1;
      scripts.add(scriptOf(ch));
      if (/[a-z]/i.test(ch)) asciiLetterCount += 1;
    }

    // Digits, hyphens and pure-ASCII contribute no script signal.
    const meaningful = [...scripts].filter((s) => s !== 'Common' && s !== 'Inherited');

    if (meaningful.length > 1) {
      findings.push({
        kind: 'mixed_script',
        confidence: 'high',
        label,
        data: { scripts: meaningful.sort().join('+') },
      });
      worstLabel = worstLabel ?? label;
    }

    if (confusableHits > 0) {
      const ratio = confusableHits / Math.max(1, label.length);
      findings.push({
        kind: 'confusable',
        confidence: ratio >= 0.4 ? 'high' : 'medium',
        label,
        data: { count: confusableHits, skeleton: skeletonize(label) },
      });
      const score = Math.min(100, Math.round(ratio * 120) + 30);
      if (score > worstScore) {
        worstScore = score;
        worstLabel = label;
      }
    }

    // 5. Homograph verdict: the label is pure non-ASCII but its skeleton is a
    //    pure-ASCII word, e.g. `xn--pypal-4ve.com`.
    if (hasNonAscii && !/^[\x00-\x7F]*$/.test(label)) {
      const skel = skeletonize(label);
      if (/^[a-z0-9-]+$/.test(skel) && skel.length >= 4 && asciiLetterCount === 0) {
        findings.push({
          kind: 'homograph',
          confidence: 'high',
          label,
          data: { skeleton: skel },
        });
        if (worstScore < 80) {
          worstScore = 80;
          worstLabel = label;
        }
      }
    }
  }

  // 6. Punycode labels whose decoded form contains non-Latin characters are a
  //    strong signal on their own.
  if (asciiHost.includes('xn--') && findings.every((f) => f.kind !== 'punycode')) {
    findings.push({ kind: 'punycode', confidence: 'medium', label: '', data: {} });
  }

  return { findings, worstLabel, homographScore: worstScore, hasNonAscii };
}
