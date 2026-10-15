/**
 * What fraction of the real threat and ad data can actually be enforced?
 *
 * The Chrome safe dynamic-rule quota is 30,000. This measures the real supply
 * behind it, so coverage claims are numbers rather than adjectives.
 */
import { compileRule, readRuntimeLimits, planQuota, resetRuleIdAllocator } from '../src/blocking/compiler.ts';
import { parseAdblock } from '../src/feeds/parsers.ts';
import { selectEvenlyIterative } from '../src/security/reputation.ts';

globalThis.chrome ??= {
  declarativeNetRequest: {
    MAX_NUMBER_OF_DYNAMIC_AND_SESSION_RULES: 30_000,
    MAX_NUMBER_OF_ENABLED_STATIC_RULESETS: 50,
  },
};

import fs from 'node:fs';

const FEEDS = 'C:/Users/VOLTRIS/AppData/Local/Temp/opencode/feeds';
const read = (name) => {
  const p = `${FEEDS}/${name}`;
  return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null;
};

const quota = planQuota(readRuntimeLimits(), 0);
console.log(`Chrome safe dynamic-rule quota : ${quota.budget}\n`);

function measure(label, hosts, budget) {
  const sorted = [...hosts].sort();
  const selected = selectEvenlyIterative(sorted, budget);
  const pct = (selected.size / sorted.length) * 100;
  console.log(`${label}`);
  console.log(`  hosts available        ${sorted.length.toLocaleString()}`);
  console.log(`  rules installable       ${budget.toLocaleString()}`);
  console.log(`  coverage                ${pct.toFixed(1)}%`);
  console.log(`  not enforced            ${(sorted.length - selected.size).toLocaleString()}\n`);
  return selected;
}

// --- phishing: the real supply
const phish = fs.existsSync(`${FEEDS}/phish-doms.txt`)
  ? fs.readFileSync(`${FEEDS}/phish-doms.txt`, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(l))
  : [];
const phishHosts = new Set(phish);
measure('PHISHING (Phishing.Database, active domains)', phishHosts, 13_000);

// --- ads: the real supply
const easy = read('easylist.txt');
if (easy) {
  const parsed = parseAdblock(easy);
  const adHosts = new Set(parsed.rules.map((r) => r.host));
  measure('ADS (EasyList network rules)', adHosts, 2_500);

  // Are the ad networks seen on real pages inside the sample at all?
  const sorted = [...adHosts].sort();
  const selected = selectEvenlyIterative(sorted, 2_500);
  const watched = [
    'static.doubleclick.net',
    'pagead2.googlesyndication.com',
    'googlesyndication.com',
    'taboola.com',
    'adnxs.com',
  ];
  console.log('  well-known ad networks, present in a uniform sample?');
  for (const host of watched) {
    const inList = adHosts.has(host);
    const kept = selected.has(host);
    console.log(`    ${host.padEnd(32)} listed=${inList ? 'yes' : 'no '}  installed=${kept ? 'YES' : 'no'}`);
  }

  // What fraction of the feed is cosmetic (unenforceable by DNR)?
  const cosmetic = parsed.counters.cosmetic_filter ?? 0;
  const network = parsed.rules.length;
  console.log(`\n  EasyList rules: ${network.toLocaleString()} network, ${cosmetic.toLocaleString()} cosmetic`);
  console.log(`  cosmetic share: ${((cosmetic / (network + cosmetic)) * 100).toFixed(1)}%  <- DNR cannot enforce these`);
}
