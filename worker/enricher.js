// ── SCHEDULED ENRICHMENT WORKER ──
// Runs every 6 hours via Cloudflare Cron
// Fetches all sources, enriches from the CVE List (CVSS, published date, CISA SSVC values, fix data), stores in KV
// Page requests just read from KV — instant response

// ── Vulnerability type, from CWE with a name-based fallback ──
// Types are the app's own taxonomy: the industry profiles boost/suppress them and the
// remediation templates key on them. Measured on the real KEV catalog, the previous
// 22-entry map left 864 of 1,728 entries (50%) on the default, which silently
// labelled them "injection" — and a wrong type moves a score by up to 3.4x
// (boost 1.28 vs suppress 0.38). Unmapped entries are now 'unknown' (neutral).
const CWE_GROUPS = {
  injection:         ['CWE-74','CWE-77','CWE-78','CWE-79','CWE-88','CWE-89','CWE-90','CWE-91','CWE-93','CWE-94','CWE-95','CWE-96','CWE-97','CWE-98','CWE-917','CWE-1336','CWE-22','CWE-23','CWE-24','CWE-35','CWE-36','CWE-73','CWE-434'],
  memory_corruption: ['CWE-118','CWE-119','CWE-120','CWE-121','CWE-122','CWE-123','CWE-125','CWE-126','CWE-129','CWE-131','CWE-190','CWE-191','CWE-193','CWE-415','CWE-476','CWE-787','CWE-788','CWE-805','CWE-823','CWE-824','CWE-825','CWE-843','CWE-908','CWE-909'],
  privesc:           ['CWE-250','CWE-264','CWE-266','CWE-267','CWE-268','CWE-269','CWE-270','CWE-271','CWE-272','CWE-273','CWE-274','CWE-281','CWE-282','CWE-416','CWE-59','CWE-61','CWE-362','CWE-367'],
  auth:              ['CWE-255','CWE-259','CWE-284','CWE-285','CWE-287','CWE-288','CWE-290','CWE-291','CWE-294','CWE-295','CWE-296','CWE-297','CWE-300','CWE-302','CWE-303','CWE-304','CWE-305','CWE-306','CWE-307','CWE-308','CWE-321','CWE-322','CWE-330','CWE-345','CWE-346','CWE-347','CWE-384','CWE-521','CWE-522','CWE-547','CWE-565','CWE-598','CWE-603','CWE-613','CWE-639','CWE-640','CWE-648','CWE-798','CWE-862','CWE-863','CWE-1390'],
  deserialization:   ['CWE-502'],
  xxe:               ['CWE-611','CWE-776'],
  api_abuse:         ['CWE-918','CWE-352','CWE-441','CWE-1021'],
  config:            ['CWE-16','CWE-276','CWE-732','CWE-1188'],
  supply_chain:      ['CWE-426','CWE-427','CWE-494','CWE-506','CWE-829','CWE-1357'],
  phishing:          ['CWE-601'],
};
const CWE_MAP = {};
Object.entries(CWE_GROUPS).forEach(([t, list]) => list.forEach(c => { CWE_MAP[c] = t; }));

// CISA's vulnerability names are standardised ("<Vendor> <Product> <Weakness> Vulnerability"),
// so the name is a reliable second signal when the CWE is missing or too generic (e.g. CWE-20).
const NAME_RULES = [
  [/deserializ/i,                                                                        'deserialization'],
  [/xml external|xxe/i,                                                                  'xxe'],
  [/server-side request forgery|cross-site request forgery|ssrf/i,                       'api_abuse'],
  [/sql injection|command injection|code injection|os command|script injection|template engine|cross-site scripting|path traversal|directory traversal|file upload|arbitrary file|injection/i, 'injection'],
  [/race condition|link following|symlink|incorrect default permissions|incorrect permission|privilege (escalation|management)|elevation of privilege/i, 'privesc'],
  [/buffer overflow|out-of-bounds|out of bounds|use-after-free|use after free|type confusion|memory corruption|double free|integer overflow|heap-based|stack-based|null pointer|uninitialized/i, 'memory_corruption'],
  [/authentication|authorization|access control|credential|hard-coded|hardcoded|missing authentication|improper access|authentication bypass/i, 'auth'],
  [/embedded malicious code|supply chain|backdoor|untrusted search path|dll hijack/i,    'supply_chain'],
];
function classifyType(k) {
  for (const c of (k.cwes || [])) if (CWE_MAP[c]) return CWE_MAP[c];
  const name = k.vulnerabilityName || '';
  for (const [re, t] of NAME_RULES) if (re.test(name)) return t;
  return 'unknown';
}

// ══════════════════════════════════════════════════════════════════
// CVE RECORDS — the source for real CVSS, real published dates, CISA's SSVC
// decision points and vendor fix data.
// Measured over the whole KEV catalog (1,728 entries): 100% have a CVE record,
// a published date, CVSS, and CISA's SSVC values; 35.5% carry fixed-version ranges.
// Records are static files in the CVE List (github.com/CVEProject/cvelistV5).
// ══════════════════════════════════════════════════════════════════
function cvelistUrl(id) {
  const m = /^CVE-(\d{4})-(\d+)$/.exec(id);
  return m ? `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${m[1]}/${Math.floor(+m[2] / 1000)}xxx/${id}.json` : null;
}

const CVSS3 = { AV:{N:.85,A:.62,L:.55,P:.2}, AC:{L:.77,H:.44}, UI:{N:.85,R:.62}, CIA:{H:.56,L:.22,N:0} };
function roundUp1(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}
// CVSS v3.x base score from a vector string (FIRST specification, v3.1 rounding).
function cvss3Base(vec) {
  if (!vec || !/^CVSS:3\.[01]\//.test(vec)) return null;
  const m = {}; vec.split('/').slice(1).forEach(p => { const [k, v] = p.split(':'); m[k] = v; });
  if (!(m.AV in CVSS3.AV) || !(m.AC in CVSS3.AC) || !(m.UI in CVSS3.UI) || !(m.C in CVSS3.CIA) || !(m.I in CVSS3.CIA) || !(m.A in CVSS3.CIA)) return null;
  const changed = m.S === 'C';
  const pr = m.PR === 'N' ? .85 : m.PR === 'L' ? (changed ? .68 : .62) : m.PR === 'H' ? (changed ? .5 : .27) : null;
  if (pr === null || (m.S !== 'U' && m.S !== 'C')) return null;
  const iss = 1 - (1 - CVSS3.CIA[m.C]) * (1 - CVSS3.CIA[m.I]) * (1 - CVSS3.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - .029) - 3.25 * Math.pow(iss - .02, 15) : 6.42 * iss;
  const expl = 8.22 * CVSS3.AV[m.AV] * CVSS3.AC[m.AC] * pr * CVSS3.UI[m.UI];
  if (impact <= 0) return 0;
  return roundUp1(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

// SSVC decision points derived from a CVSS v3 vector — used ONLY when CISA has published no
// values for a CVE (mainly non-KEV entries). Rules were measured against CISA's own values on
// the KEV catalog; the agreement rate is reported by the test suite and shown as "derived".
function deriveSsvc(vec) {
  if (!vec || !/^CVSS:3\.[01]\//.test(vec)) return null;
  const m = {}; vec.split('/').slice(1).forEach(p => { const [k, v] = p.split(':'); m[k] = v; });
  return {
    a: (m.AV === 'N' && m.AC === 'L' && m.PR === 'N' && m.UI === 'N') ? 'yes' : 'no',
    t: (m.C === 'H' && m.I === 'H') ? 'total' : 'partial',
  };
}

const CVSS_RANK = { cvssV3_1: 3, cvssV3_0: 2, cvssV4_0: 1 };
function cleanText(t, n) { return String(t || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n); }

// One CVE-record JSON -> the compact record we store and ship.
function extractCveRecord(rec, today) {
  if (!rec || !rec.containers) return null;
  const cna = rec.containers.cna || {};
  const adps = rec.containers.adp || [];
  const cands = [];
  const collect = (metrics, srcRank, src) => (metrics || []).forEach(mt => {
    for (const k of Object.keys(CVSS_RANK)) {
      const x = mt[k];
      if (x && (x.vectorString || x.baseScore != null)) {
        const vec = x.vectorString || null;
        // Base score is computed from the vector when there is one: 18 of the published "baseScore" values on KEV
        // records are really temporal scores (their vectors carry E/RL/RC), and 3 disagree with their own vector.
        const calc = cvss3Base(vec);
        const score = calc != null ? calc : (x.baseScore != null ? +x.baseScore : null);
        if (score != null && !isNaN(score)) cands.push({ score, vec, ver: k.replace('cvssV','').replace('_','.'), rank: CVSS_RANK[k] * 10 + srcRank, src });
      }
    }
  });
  collect(cna.metrics, 2, 'CNA');
  let ssvc = null;
  adps.forEach(a => {
    const sn = a.providerMetadata?.shortName;
    collect(a.metrics, sn === 'CISA-ADP' ? 1 : 0, sn === 'CISA-ADP' ? 'CISA-ADP' : (sn || 'ADP'));
    if (sn === 'CISA-ADP') (a.metrics || []).forEach(mt => {
      if (mt.other?.type === 'ssvc') {
        const o = {}; (mt.other.content?.options || []).forEach(x => { const k = Object.keys(x)[0]; o[k] = String(x[k]).toLowerCase(); });
        if (o.Exploitation || o.Automatable || o['Technical Impact']) ssvc = { e: o.Exploitation || null, a: o.Automatable || null, t: o['Technical Impact'] || null };
      }
    });
  });
  cands.sort((x, y) => y.rank - x.rank);
  const best = cands[0];
  const fixed = new Set();
  (cna.affected || []).forEach(af => (af.versions || []).forEach(v => {
    // Only EXPLICIT fix boundaries: an affected range's upper bound, or a "changes" entry that flips to unaffected.
    // A bare 'unaffected' version is ambiguous (a branch that was never affected vs. the first fixed build), so it is
    // not used — including it once told readers to "update to 9.0.0" for a branch PAN-OS lists as never vulnerable.
    if (v.versionType === 'git') return;
    const ok = s => s && s !== '*' && s !== 'unspecified' && s !== '0' && /\d/.test(s) && String(s).length <= 40 && !/^[0-9a-f]{7,40}$/i.test(s);
    if (v.status === 'affected' && ok(v.lessThan)) fixed.add(String(v.lessThan));
    (v.changes || []).forEach(ch => { if (ch.status === 'unaffected' && ok(String(ch.at || ''))) fixed.add(String(ch.at)); });
  }));
  const en = arr => (arr || []).find(x => !x.lang || /^en/i.test(x.lang))?.value;
  const advTags = ['vendor-advisory', 'patch', 'mitigation'];
  const adv = [...new Set((cna.references || []).filter(r => (r.tags || []).some(t => advTags.includes(t))).map(r => r.url))].slice(0, 3);
  const out = { p: (rec.cveMetadata?.datePublished || '').slice(0, 10) || null };
  if (best) out.c = { s: best.score, v: best.vec, ver: best.ver, src: best.src };
  if (ssvc) out.s = ssvc;
  if (fixed.size) out.fx = [...fixed].slice(0, 8);
  const sol = cleanText(en(cna.solutions), 240), wk = cleanText(en(cna.workarounds), 240);
  if (sol) out.sol = sol;
  if (wk) out.wk = wk;
  if (adv.length) out.adv = adv;
  if (today != null) out.t = today;
  return out;
}

// ── Platform, from vendor/product ──
// The profile's platform choices are cloud, saas, onprem, ot_ics, ai_llm, remote, iot, payment.
// Every KEV entry used to be hard-coded ['onprem'], and the app multiplies by 1.18 on a match
// and 0.55 otherwise — so an org that didn't tick "onprem" had ALL confirmed-exploited entries cut
// by 45%. Rules cover only the clear cases; anything else keeps 'onprem' but is flagged
// platKnown:false so the app can treat "unknown" as neutral rather than as a mismatch.
const PLATFORM_RULES = [
  [['ot_ics'],           /siemens|rockwell|schneider|mitsubishi|omron|honeywell|yokogawa|advantech|moxa|wago|phoenix contact|emerson|aveva|inductive automation|unitronics|codesys|fuji electric|delta electronics|hitachi energy|abb\b|simatic|scada|\bplc\b|\bics\b/i],
  [['iot','onprem'],     /d-link|tp-link|zyxel|netgear|linksys|tenda|hikvision|dahua|draytek|\bzte\b|reolink|geovision|nuuo|foscam|vivotek|mikrotik|ubiquiti|totolink|trendnet|comtrend|ruijie|avtech|\brouter|\bcamera|\bnvr\b|\bdvr\b|webcam/i],
  [['ai_llm','cloud'],   /litellm|langflow|mlflow|ray-project|ollama|langchain|vllm|comfyui|llama|openai|hugging ?face/i],
  [['payment'],          /verifone|ingenico|point[- ]of[- ]sale|\bpos\b|aloha/i],
  [['remote','onprem'],  /globalprotect|ssl[- ]?vpn|connect secure|policy secure|pulse|netscaler|(vpn|access|remote|secure access) gateway|anyconnect|secure firewall|adaptive security|\basa\b|fortios|fortigate|forticlient|fortiproxy|\bsma\d*|sonicos|sonicwall|big-ip|check point|watchguard|barracuda|juniper|junos|zscaler|pan-os|\bvpn|remote access/i],
  [['remote'],           /^apple\b.*\b(ios|ipados|macos|safari|iphone|ipad)|chromium|google chrome|mozilla firefox|\bandroid|\bpixel/i],
  [['cloud'],            /azure|\baws\b|amazon web|google cloud|kubernetes|docker|openshift|terraform/i],
  [['saas'],             /salesforce|servicenow|okta|zendesk|workday|slack|zoom\b|dropbox|microsoft 365|office 365|sharepoint online/i],
];
function classifyPlatform(k) {
  const hay = `${k.vendorProject || ''} ${k.product || ''}`;
  const tags = new Set();
  PLATFORM_RULES.forEach(([t, re]) => { if (re.test(hay)) t.forEach(x => tags.add(x)); });
  return tags.size ? { affects: [...tags], known: true } : { affects: ['onprem'], known: false };
}

async function safeFetch(url, opts={}, timeoutMs=15000) {
  const res = await fetch(url, {
    headers: { 'User-Agent': 'RiskSync/1.0' },
    signal: AbortSignal.timeout(timeoutMs),
    ...opts,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} — ${url}`);
  const text = await res.text();
  if (!text.trim()) throw new Error('Empty response');
  return JSON.parse(text);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ══════════════════════════════════════════════════════════════════
// CISA KEV feed — fetched ONCE per invocation and threaded through every stage that
// needs it (it used to be re-fetched up to 3 times per run, so one bad CISA response
// had three chances to fail the whole sync). The last good response is cached in KV;
// if CISA 403s, rate-limits, or times out, the Worker falls back to it rather than
// losing the run. Genuinely stale KEV data is still far better than none.
// ══════════════════════════════════════════════════════════════════
const KEV_LAST_GOOD_KEY = 'kev_last_good';   // { fetchedAt, data: <raw KEV JSON> }
async function fetchKev(env) {
  try {
    const data = await safeFetch(KEV_URL, {}, 12000);
    if (data && Array.isArray(data.vulnerabilities) && data.vulnerabilities.length > 0) {
      env.RISKSYNC_KV?.put(KEV_LAST_GOOD_KEY, JSON.stringify({ fetchedAt: Date.now(), data })).catch(() => {});
      return data;
    }
    throw new Error('CISA KEV response had no vulnerabilities');
  } catch (e) {
    console.error('CISA KEV fetch failed, trying last-good cache:', e.message);
    const raw = await env.RISKSYNC_KV?.get(KEV_LAST_GOOD_KEY);
    if (raw) {
      const cached = JSON.parse(raw);
      const ageHrs = Math.round((Date.now() - cached.fetchedAt) / 3600000);
      console.log(`Using cached CISA KEV from ${ageHrs}h ago (${cached.data.vulnerabilities.length} entries)`);
      return cached.data;
    }
    throw new Error(`CISA KEV unavailable and no cached copy exists: ${e.message}`);
  }
}

// ══════════════════════════════════════════════════════════════════
// CVE-record store: seeded once from a static file, then maintained incrementally.
// The seed (kev_enrichment.json, built from the CVE List) gives 100% of the KEV base on day one.
// After that the Worker only fetches NEW KEV additions, plus a few records per run that
// still have no fix data (vendors publish fixes later). Well inside the 50-request limit.
// ══════════════════════════════════════════════════════════════════
const CVEREC_CACHE_KEY = 'cverec_cache';   // { seededAt, records: { [CVE]: compact record } }
const CVEREC_SEED_URLS = ['https://syncrisk.co.uk/kev_enrichment.json', 'https://risksync.pages.dev/kev_enrichment.json'];
const CVEREC_MAX_WALL_MS = 5000;
const CVEREC_NEW_PER_RUN = 12;
const CVEREC_REFRESH_PER_RUN = 4;
const CVEREC_REFRESH_DAYS = 7;
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

async function loadCveRecords(env) {
  const raw = await env.RISKSYNC_KV?.get(CVEREC_CACHE_KEY);
  try { const c = raw ? JSON.parse(raw) : null; if (c && c.records) return c; } catch (e) { /* fall through to empty */ }
  return { seededAt: null, records: {} };
}

async function runCveRecordSync(env, kevData) {
  const startedAt = Date.now();
  const today = Math.floor(Date.now() / 86400000);
  const cache = await loadCveRecords(env);
  let changed = false, seeded = 0;

  if (!cache.seededAt) {
    for (const url of CVEREC_SEED_URLS) {
      try {
        const seed = await safeFetch(url, {}, 8000);
        if (seed && seed.records) {
          Object.entries(seed.records).forEach(([id, r]) => { if (!cache.records[id]) { cache.records[id] = r; seeded++; } });
          cache.seededAt = Date.now(); changed = true; break;
        }
      } catch (e) { console.error(`CVE record seed failed (${url}):`, e.message); }
    }
  }

  const ids = (kevData.vulnerabilities || []).sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded)).map(v => v.cveID);
  const isMissing = id => { const r = cache.records[id]; return !r || (r.nf && today - (r.t || 0) >= 2); };
  const missing = ids.filter(isMissing);
  const stale = ids.filter(id => { const r = cache.records[id]; return r && !r.nf && !r.fx && today - (r.t || 0) >= CVEREC_REFRESH_DAYS; });
  const todo = [...missing.slice(0, CVEREC_NEW_PER_RUN), ...stale.slice(0, CVEREC_REFRESH_PER_RUN)];

  let fetched = 0;
  for (let i = 0; i < todo.length && Date.now() - startedAt < CVEREC_MAX_WALL_MS; i += 5) {
    const results = await Promise.all(todo.slice(i, i + 5).map(async id => {
      try { return [id, extractCveRecord(await safeFetch(cvelistUrl(id), {}, 4000), today)]; }
      catch (e) { return [id, /HTTP 404/.test(e.message) ? { nf: 1, t: today } : null]; }
    }));
    results.forEach(([id, r]) => { if (r) { cache.records[id] = r; fetched++; changed = true; } });
  }
  if (changed) await env.RISKSYNC_KV?.put(CVEREC_CACHE_KEY, JSON.stringify(cache));
  const total = Object.keys(cache.records).length;
  console.log(`CVE records: ${seeded ? 'seeded ' + seeded + ', ' : ''}fetched ${fetched}, ${total} cached, ${Math.max(0, missing.length - fetched)} KEV entries still missing`);
}

// ══════════════════════════════════════════════════════════════════
// OSV.dev — fixed too. The old code queried with an empty package
// name (`{package: {ecosystem: eco, name: ''}}`), hoping for an
// "everything in this ecosystem" result. OSV's real API has no such
// query — POST /v1/query always requires a specific package name +
// ecosystem (version is optional; omitting it returns vulnerabilities
// across all versions of that package). There is no live "browse an
// ecosystem" endpoint; the only bulk mechanism is a per-ecosystem ZIP
// export (confirmed >30MB each), far too large for this Worker.
//
// So: single-package lookups —
// a curated list of well-known packages, walked with a persisted
// cursor, saved after every single package, bounded by a small hard
// wall-clock budget so it can't blow the overall invocation's time.
// ══════════════════════════════════════════════════════════════════

const OSV_CACHE_KEY   = 'osv_vulns_cache';    // { [pkgKey]: [vuln,...] } — accumulates forever
const OSV_CURSOR_KEY  = 'osv_enrich_cursor';  // { idx: N }
const OSV_MAX_WALL_MS = 3000;                 // keeps the whole run comfortably inside the ~30s ceiling

const OSV_PACKAGES = [
  {name:'lodash', ecosystem:'npm'}, {name:'express', ecosystem:'npm'}, {name:'axios', ecosystem:'npm'}, {name:'minimist', ecosystem:'npm'},
  {name:'jinja2', ecosystem:'PyPI'}, {name:'django', ecosystem:'PyPI'}, {name:'flask', ecosystem:'PyPI'}, {name:'requests', ecosystem:'PyPI'},
  {name:'github.com/gin-gonic/gin', ecosystem:'Go'}, {name:'github.com/gorilla/websocket', ecosystem:'Go'},
  {name:'org.apache.logging.log4j:log4j-core', ecosystem:'Maven'}, {name:'org.springframework:spring-core', ecosystem:'Maven'},
  {name:'rails', ecosystem:'RubyGems'}, {name:'nokogiri', ecosystem:'RubyGems'},
  {name:'tokio', ecosystem:'crates.io'}, {name:'openssl', ecosystem:'crates.io'},
];

// Extracts "fixed at version X" from OSV's affected/ranges/events schema —
// this field was already in every response, just unread.
function extractOsvFixedVersions(v) {
  const fixed = new Set();
  (v.affected || []).forEach(a => {
    (a.ranges || []).forEach(r => {
      (r.events || []).forEach(e => {
        if (e.fixed) fixed.add(e.fixed);
      });
    });
  });
  return [...fixed];
}

async function fetchOsvPackage(pkg) {
  const data = await safeFetch(
    'https://api.osv.dev/v1/query',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'RiskSync/1.0' },
      body: JSON.stringify({ package: { name: pkg.name, ecosystem: pkg.ecosystem } }),
    },
    3000
  );
  return (data.vulns || []).map(v => ({ ...v, _eco: pkg.ecosystem, fixedVersions: extractOsvFixedVersions(v) }));
}

async function runOsvSync(env) {
  const startedAt = Date.now();

  const cursorRaw = await env.RISKSYNC_KV?.get(OSV_CURSOR_KEY);
  let idx = cursorRaw ? (JSON.parse(cursorRaw).idx || 0) : 0;

  const cacheRaw = await env.RISKSYNC_KV?.get(OSV_CACHE_KEY);
  const cache = cacheRaw ? JSON.parse(cacheRaw) : {};

  let attempted = 0, found = 0;

  while (Date.now() - startedAt < OSV_MAX_WALL_MS) {
    if (idx >= OSV_PACKAGES.length) {
      idx = 0;
      console.log('OSV sync: completed a full pass over the curated package list — wrapping around');
    }
    const pkg = OSV_PACKAGES[idx];
    const key = `${pkg.ecosystem}:${pkg.name}`;
    idx++;
    attempted++;

    try {
      const vulns = await fetchOsvPackage(pkg);
      cache[key] = vulns;
      found += vulns.length;
      console.log(`OSV ${key}: ${vulns.length} vulns`);
    } catch(e) {
      console.error(`OSV lookup failed for ${key}:`, e.message);
    }

    await env.RISKSYNC_KV?.put(OSV_CACHE_KEY, JSON.stringify(cache));
    await env.RISKSYNC_KV?.put(OSV_CURSOR_KEY, JSON.stringify({ idx }));

    if (Date.now() - startedAt >= OSV_MAX_WALL_MS) break;
    await sleep(150);
  }

  const flat = Object.values(cache).flat();
  console.log(`OSV sync complete: attempted ${attempted} packages this run, ${flat.length} total vulns cached across ${Object.keys(cache).length} packages`);
  return flat;
}

// ══════════════════════════════════════════════════════════════════
// Stage timing — logs elapsed seconds since the invocation started, so the
// ~30s budget can be tuned from real numbers instead of guesses.
// ══════════════════════════════════════════════════════════════════
function makeLap() {
  const t0 = Date.now();
  return (label) => console.log(`t+${((Date.now() - t0) / 1000).toFixed(1)}s ${label}`);
}

// ══════════════════════════════════════════════════════════════════
// EPSS — per-CVE lookup for the whole KEV base.
// The old approach downloaded only the top 3,000 EPSS scores, so any KEV entry
// outside that list silently got a made-up 0.85. FIRST's API takes a
// comma-separated list in `cve` (max 2,000 chars total, ~15 chars per ID), and
// returns 100 rows unless `limit` is raised — so batches of 100 with limit=100.
// Results are cached; not-found is cached as null so it isn't retried every run;
// everything is re-checked after 7 days because EPSS scores drift.
// ══════════════════════════════════════════════════════════════════
const EPSS_CACHE_KEY = 'epss_cache';   // { [CVE]: [score|null, epochDay] }
const EPSS_MAX_WALL_MS = 3500;
const EPSS_BATCH = 100;
const EPSS_REFRESH_DAYS = 7;

async function runEpssSync(env, kevData) {
  const startedAt = Date.now();
  const today = Math.floor(Date.now() / 86400000);
  const ids = (kevData.vulnerabilities || [])
    .sort((a,b) => new Date(b.dateAdded) - new Date(a.dateAdded))
    .map(v => v.cveID);

  const raw = await env.RISKSYNC_KV?.get(EPSS_CACHE_KEY);
  const cache = raw ? JSON.parse(raw) : {};
  // never-looked-up first, then stale; both newest-first
  const todo = [
    ...ids.filter(id => !cache[id]),
    ...ids.filter(id => cache[id] && (today - cache[id][1]) >= EPSS_REFRESH_DAYS),
  ];

  let looked = 0, found = 0;
  for (let i = 0; i < todo.length && Date.now() - startedAt < EPSS_MAX_WALL_MS; i += EPSS_BATCH) {
    const batch = todo.slice(i, i + EPSS_BATCH);
    try {
      const res = await safeFetch(
        `https://api.first.org/data/v1/epss?cve=${batch.join(',')}&limit=${EPSS_BATCH}`, {}, 3000);
      const got = new Map((res.data || []).map(d => [d.cve, parseFloat(d.epss)]));
      batch.forEach(id => {
        const sc = got.get(id);
        cache[id] = [Number.isFinite(sc) ? sc : null, today];
      });
      looked += batch.length;
      found  += got.size;
    } catch (e) {
      console.error('EPSS batch failed:', e.message);
      break;
    }
  }
  if (looked) await env.RISKSYNC_KV?.put(EPSS_CACHE_KEY, JSON.stringify(cache));
  console.log(`EPSS sync: looked up ${looked}, found ${found}, ${Object.keys(cache).length} cached, ${Math.max(0, todo.length - looked)} still pending`);
}

// ══════════════════════════════════════════════════════════════════
// GitHub Advisories — incremental, same pattern as OSV/EPSS.
// The old fetch restarted at page 1 every run, so a 4s budget only ever reached
// ~200 advisories and the count swung around whenever a fetch was cut short.
// Now a cursor (severity, page) survives between runs and advisories accumulate
// by ID, so coverage only ever grows. Enrichment just reads the cache.
// ══════════════════════════════════════════════════════════════════
const GH_CACHE_KEY   = 'gh_advisories_cache';   // { items: { [id]: slim }, sevIdx, page }
const GH_MAX_WALL_MS = 3500;
const GH_SEVERITIES  = ['critical', 'high'];
const GH_MAX_PAGES   = 5;                        // 5 x 100 per severity

function ghSlim(a) {
  return {
    cve_id:       a.cve_id || (a.identifiers || []).find(i => i.type === 'CVE')?.value || null,
    ghsa_id:      a.ghsa_id,
    summary:      (a.summary || '').slice(0, 200),
    cvss:         { score: a.cvss?.score ?? null, vector: a.cvss?.vector_string ?? null },
    published_at: a.published_at,
  };
}

async function loadGhCache(env) {
  const raw = await env.RISKSYNC_KV?.get(GH_CACHE_KEY);
  let c = null;
  try { c = raw ? JSON.parse(raw) : null; } catch (e) { c = null; }
  if (!c) return { items: {}, sevIdx: 0, page: 1 };
  if (Array.isArray(c.items)) {   // earlier format: a flat array — convert, keep what was fetched
    const obj = {};
    c.items.forEach(a => { const k = a.ghsa_id || a.cve_id; if (k) obj[k] = a; });
    return { items: obj, sevIdx: 0, page: 1 };
  }
  return { items: c.items || {}, sevIdx: c.sevIdx || 0, page: c.page || 1 };
}

async function runGithubSync(env) {
  const token = env?.GITHUB_TOKEN || '';
  const headers = {
    'User-Agent': 'RiskSync/1.0',
    'Accept': 'application/vnd.github+json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
  };
  const startedAt = Date.now();
  const cache = await loadGhCache(env);
  const before = Object.keys(cache.items).length;
  let pages = 0;

  while (Date.now() - startedAt < GH_MAX_WALL_MS) {
    const sev = GH_SEVERITIES[cache.sevIdx];
    let data;
    try {
      data = await safeFetch(
        `https://api.github.com/advisories?type=reviewed&severity=${sev}&per_page=100&page=${cache.page}`,
        { headers }, 3000);
    } catch (e) {
      console.error(`GitHub Advisory ${sev} page ${cache.page} failed:`, e.message);
      break;                       // keep the cursor here and retry next run
    }
    pages++;
    if (Array.isArray(data)) data.forEach(a => { const k = a.ghsa_id || a.cve_id; if (k) cache.items[k] = ghSlim(a); });
    const lastPage = !Array.isArray(data) || data.length < 100 || cache.page >= GH_MAX_PAGES;
    if (lastPage) {
      cache.sevIdx = (cache.sevIdx + 1) % GH_SEVERITIES.length;   // wraps to critical/page 1 = a fresh refresh pass
      cache.page = 1;
      if (cache.sevIdx === 0) break;   // finished a full pass this run — the next refresh waits for the next run
    } else {
      cache.page++;
    }
  }
  const after = Object.keys(cache.items).length;
  if (pages) await env.RISKSYNC_KV?.put(GH_CACHE_KEY, JSON.stringify(cache));
  console.log(`GitHub sync: ${pages} pages, +${after - before} new, ${after} cached, cursor ${GH_SEVERITIES[cache.sevIdx]} p${cache.page}`);
}

async function getGithubAdvisories(env) {
  const cache = await loadGhCache(env);
  return Object.values(cache.items);
}

// ── MAIN ENRICHMENT FUNCTION ──
// Builds the payload from whatever is CURRENTLY in the caches.
// Does NOT grow the cache itself — that's runNvdBulkSync's job, called
// separately (and only) from the cron handler, below.
async function runEnrichment(env, kevData) {
  console.log('Starting enrichment run at', new Date().toISOString());

  console.log('Using CISA KEV...');
  const kevVulns = kevData.vulnerabilities || [];
  console.log(`CISA KEV: ${kevVulns.length} entries`);

  console.log('Fetching EPSS scores...');
  let epssTop = [];
  try {
    for (let offset = 0; offset < 3000; offset += 1000) {
      const epss = await safeFetch(`https://api.first.org/data/v1/epss?order=!epss&limit=1000&offset=${offset}`);
      const data = epss.data || [];
      epssTop.push(...data);
      if (data.length < 1000) break;
      await sleep(500);
    }
  } catch(e) { console.error('EPSS failed:', e.message); }
  console.log(`EPSS: ${epssTop.length} scores`);

  console.log('Reading GitHub Advisories cache...');
  const ghAdvisories = await getGithubAdvisories(env);
  console.log(`GitHub: ${ghAdvisories.length} advisories`);

  console.log('Reading OSV.dev cache...');
  const osvCacheRaw = await env.RISKSYNC_KV?.get(OSV_CACHE_KEY);
  const osvCacheObj = osvCacheRaw ? JSON.parse(osvCacheRaw) : {};
  const osvRaw = Object.values(osvCacheObj).flat();
  const osvPkgCovered = Object.keys(osvCacheObj).length;
  console.log(`OSV: ${osvRaw.length} vulns cached`);

  const epssMap = {};
  const epssCacheRaw = await env.RISKSYNC_KV?.get(EPSS_CACHE_KEY);
  if (epssCacheRaw) {
    Object.entries(JSON.parse(epssCacheRaw)).forEach(([id, e]) => { if (e && e[0] !== null) epssMap[id] = e[0]; });
  }
  epssTop.forEach(e => { epssMap[e.cve] = parseFloat(e.epss); });

  const cveRecs = await loadCveRecords(env);
  console.log(`CVE records: ${Object.keys(cveRecs.records).length} available`);

  const allKev = [...kevVulns].sort((a,b) => new Date(b.dateAdded) - new Date(a.dateAdded));
  const kevMapped = allKev.map(v => {
    const epssReal = epssMap[v.cveID] !== undefined;
    const epss = epssReal ? epssMap[v.cveID] : 0.85;
    const cwes = v.cwes || [];
    const cwe  = cwes[0] || 'CWE-0';
    const plat = classifyPlatform(v);
    const rec  = cveRecs.records[v.cveID];
    const c    = rec && rec.c;
    const cis  = rec && rec.s;
    const der  = !cis && c ? deriveSsvc(c.v) : null;
    const action = v.requiredAction || '';
    return {
      id:            v.cveID,
      cvss:          c ? c.s : (epss > 0.8 ? 9.0 : epss > 0.5 ? 7.5 : 6.5),   // an estimate ONLY when no record exists
      cvssV:         c ? c.ver : null,
      vector:        c ? c.v : null,
      cvssSrc:       c ? c.src : undefined,
      desc:          (v.shortDescription || v.vulnerabilityName || '').slice(0, 200),
      type:          classifyType(v),
      src:           rec ? 'CISA KEV + CVE record' : 'CISA KEV',
      kev:           true,
      // SSVC decision points: CISA's own values (published in the CVE record) where present. KEV membership IS
      // active exploitation, so exploitation is 'active' regardless of an older record value.
      ssvc:          { e: 'active', a: (cis && cis.a) || (der && der.a) || 'no', t: (cis && cis.t) || (der && der.t) || 'partial', src: cis ? 'CISA' : der ? 'derived' : 'assumed' },
      epss,
      epssEst:       epssReal ? undefined : true,
      affects:       plat.affects,
      platKnown:     plat.known ? undefined : false,
      ransomware:    v.knownRansomwareCampaignUse === 'Known' ? true : undefined,
      industries:    ['all'],
      cwe,
      publishedDate: (rec && rec.p) || v.dateAdded,          // the real CVE publish date, not the KEV-added date
      publishedEst:  rec && rec.p ? undefined : true,
      dateAdded:     v.dateAdded,
      vendor:        v.vendorProject,
      product:       (v.vendorProject + ' ' + v.product).trim(),
      action,
      directive:     /BOD 26-04/.test(action + ' ' + (v.notes || '')) ? 'BOD 26-04' : /BOD 22-01/.test(action + ' ' + (v.notes || '')) ? 'BOD 22-01' : undefined,
      dueDate:       v.dueDate,
      fixedVersions: rec && rec.fx ? rec.fx : undefined,
      solution:      rec && rec.sol ? rec.sol : undefined,
      workaround:    rec && rec.wk ? rec.wk : undefined,
      advisoryUrls:  rec && rec.adv ? rec.adv : undefined,
    };
  });
  const recHits = kevMapped.filter(v => v.cvssV != null).length;
  console.log(`Applied CVE records to ${recHits}/${kevMapped.length} KEV entries`);

  const ghMapped = ghAdvisories.map(a => {
    const ghCvssReal = a.cvss?.score != null && !isNaN(parseFloat(a.cvss.score));
    const cvss = ghCvssReal ? parseFloat(a.cvss.score) : 7.0;
    const cve  = a.cve_id || (a.identifiers||[]).find(i=>i.type==='CVE')?.value || a.ghsa_id;
    return {
      id:            cve || a.ghsa_id,
      cvss,
      cvssV:         ghCvssReal ? '3.1' : null,
      vector:        a.cvss?.vector || null,
      ssvc:          (() => { const d = deriveSsvc(a.cvss?.vector); return { e: 'none', a: d ? d.a : 'no', t: d ? d.t : 'partial', src: d ? 'derived' : 'assumed' }; })(),
      desc:          (a.summary || '').slice(0, 200),
      type:          'supply_chain',
      src:           'GitHub Advisory',
      kev:           false,
      epss:          epssMap[cve] !== undefined ? epssMap[cve] : 0.3,
      epssEst:       epssMap[cve] !== undefined ? undefined : true,
      affects:       ['cicd','cloud'],
      industries:    ['all'],
      cwe:           'CWE-0',
      publishedDate: a.published_at,
    };
  }).filter(v => v.cvss >= 6.0);

  const osvMapped = osvRaw.filter(v => v.id && v.summary).map(v => {
    const sev = (v.severity||[]).find(s=>s.type==='CVSS_V3') ||
                (v.severity||[]).find(s=>s.type==='CVSS_V2');
    let cvss  = 7.0;
    let osvCvssReal = false;
    const osvVec = /^CVSS:3\.[01]\//.test(sev?.score || '') ? sev.score : null;   // OSV stores the vector string; V4 vectors are not scored here
    const calc = cvss3Base(osvVec);
    if (calc != null) { cvss = calc; osvCvssReal = true; }
    const cve  = (v.aliases||[]).find(a=>a.startsWith('CVE-')) || v.id;
    const osvEpssReal = epssMap[cve] !== undefined;
    const epss = osvEpssReal ? epssMap[cve] : 0.2;
    const affectsMap = {
      npm:'web', PyPI:'api', Go:'cloud',
      Maven:'cloud', RubyGems:'web', 'crates.io':'cloud', Packagist:'web',
    };
    return {
      id:            cve,
      cvss,
      cvssV:         osvCvssReal ? (osvVec.startsWith('CVSS:3.0') ? '3.0' : '3.1') : null,
      vector:        osvVec || null,
      ssvc:          (() => { const d = deriveSsvc(osvVec); return { e: 'none', a: d ? d.a : 'no', t: d ? d.t : 'partial', src: d ? 'derived' : 'assumed' }; })(),
      desc:          (v.summary||'').slice(0,200),
      type:          'supply_chain',
      src:           `OSV (${v._eco||'open source'})`,
      kev:           false,
      epss,
      epssEst:       osvEpssReal ? undefined : true,
      affects:       ['cicd', affectsMap[v._eco]||'cloud'].filter(Boolean),
      industries:    ['all'],
      cwe:           'CWE-94',
      publishedDate: v.published || v.modified,
      ecosystem:     v._eco,
      fixedVersions: v.fixedVersions && v.fixedVersions.length ? v.fixedVersions : undefined,
    };
  }).filter(v => v.cvss >= 5.0);

  const seen = new Set();
  const all  = [...kevMapped, ...ghMapped, ...osvMapped].filter(v => {
    if (!v.id || seen.has(v.id)) return false;
    seen.add(v.id);
    return v.kev || (v.cvss||0) >= 5.0; // confirmed-exploited entries are never filtered out on score
  });

  all.sort((a,b) => b.epss - a.epss || b.cvss - a.cvss);

  // ── COVERAGE — always measured over the full base, never a test subset ──
  const pct = (n, d) => d ? Math.round((n / d) * 1000) / 10 : 0;
  const base = all.length;
  const kevIn = all.filter(v => v.kev);
  const coverage = {
    base,
    kevTotal: kevIn.length,
    realCvss:      { count: all.filter(v => v.cvssV != null).length, ofBase: base, pct: pct(all.filter(v => v.cvssV != null).length, base) },
    publishedReal: { count: kevIn.filter(v => !v.publishedEst).length, ofKev: kevIn.length, pct: pct(kevIn.filter(v => !v.publishedEst).length, kevIn.length) },
    ssvcCisa:      { count: kevIn.filter(v => v.ssvc && v.ssvc.src === 'CISA').length, ofKev: kevIn.length, pct: pct(kevIn.filter(v => v.ssvc && v.ssvc.src === 'CISA').length, kevIn.length) },
    cveRecords:    Object.keys(cveRecs.records).length,
    realCvssKev:   { count: kevIn.filter(v => v.cvssV != null).length, ofKev: kevIn.length, pct: pct(kevIn.filter(v => v.cvssV != null).length, kevIn.length) },
    realEpss:      { count: all.filter(v => !v.epssEst).length, ofBase: base, pct: pct(all.filter(v => !v.epssEst).length, base) },
    realEpssKev:   { count: kevIn.filter(v => !v.epssEst).length, ofKev: kevIn.length, pct: pct(kevIn.filter(v => !v.epssEst).length, kevIn.length) },
    fixedVersions: { count: all.filter(v => v.fixedVersions && v.fixedVersions.length).length, ofBase: base, pct: pct(all.filter(v => v.fixedVersions && v.fixedVersions.length).length, base) },
    osv:           { packagesCovered: osvPkgCovered, packagesTotal: OSV_PACKAGES.length, note: 'curated package list, not driven by our CVE base' },
    github:        { count: ghMapped.length, note: 'critical+high feed, capped, not an enrichment of KEV' },
  };
  console.log(`COVERAGE (base ${base}): real CVSS ${coverage.realCvss.count} (${coverage.realCvss.pct}%), KEV real CVSS ${coverage.realCvssKev.count}/${kevIn.length} (${coverage.realCvssKev.pct}%), KEV real EPSS ${coverage.realEpssKev.count}/${kevIn.length} (${coverage.realEpssKev.pct}%), fixed versions ${coverage.fixedVersions.count} (${coverage.fixedVersions.pct}%), OSV packages ${osvPkgCovered}/${OSV_PACKAGES.length}`);

  const payload = {
    ok:        true,
    coverage,
    count:     all.length,
    kevCount:  kevVulns.length,
    osvCount:  osvMapped.length,
    ghCount:   ghMapped.length,
    sources:   ['CISA KEV', 'CVE List (CNA + CISA-ADP)', 'FIRST EPSS', 'GitHub Advisory', 'OSV.dev'],
    updatedAt: new Date().toISOString(),
    vulns:     all,
  };

  console.log(`Enrichment complete: ${all.length} total vulns, ${coverage.realCvssKev.count} KEV with real CVSS`);
  return payload;
}

// ── DEFAULT EXPORT ──
export default {

  async fetch(request, env, ctx) {
    const CORS = {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json',
      'Cache-Control': 'public, s-maxage=21600, stale-while-revalidate=86400',
    };

    // ── Manual test trigger — fires the exact same logic the cron runs, on demand.
    // Requires a secret (set via `wrangler secret put SYNC_SECRET` or the dashboard's
    // Settings → Variables, as a Secret, not a plain text var). Runs in the background
    // via ctx.waitUntil so this request returns immediately — check /threats again in
    // 30–60 seconds, or the Logs tab for live progress.
    const url = new URL(request.url);
    if (url.searchParams.has('sync')) {
      if (!env.SYNC_SECRET || url.searchParams.get('sync') !== env.SYNC_SECRET) {
        return new Response(JSON.stringify({ ok:false, error:'unauthorized — set SYNC_SECRET and pass ?sync=<that value>' }),
          { status:401, headers:CORS });
      }
      ctx.waitUntil((async () => {
        try {
          console.log('Manual sync triggered');
          const lap = makeLap();
          const kevData = await fetchKev(env); lap('KEV fetched');
          // Each stage fails independently — a broken source no longer costs the whole run's progress.
          const stage = async (name, fn) => { try { await fn(); } catch (e) { console.error(`${name} stage failed:`, e.message); } lap(`${name} stage done`); };
          await stage('CVE record', () => runCveRecordSync(env, kevData));
          await stage('OSV',        () => runOsvSync(env));
          await stage('EPSS',       () => runEpssSync(env, kevData));
          await stage('GitHub',     () => runGithubSync(env));
          const payload = await runEnrichment(env, kevData); lap('payload built');
          const json    = JSON.stringify(payload);
          await env.RISKSYNC_KV.put(env.CACHE_KEY || 'threats_v1', json, { expirationTtl: 86400 });
          lap('saved to KV');
          console.log(`Manual sync complete: ${payload.count} vulns, ${payload.coverage.realCvssKev.count} KEV with real CVSS, ${payload.osvCount} from OSV`);
        } catch(e) {
          console.error('Manual sync failed:', e.message);
        }
      })());
      return new Response(JSON.stringify({ ok:true, message:'Sync started in background. Check /threats or the Logs tab in 30-60 seconds.' }),
        { status:202, headers:CORS });
    }

    try {
      const cached = await env.RISKSYNC_KV?.get(env.CACHE_KEY || 'threats_v1');
      if (cached) {
        return new Response(cached, { status:200, headers:CORS });
      }
      // KV empty — build once from whatever the caches hold (no sync here, keep it fast)
      const kevData = await fetchKev(env);
      const payload = await runEnrichment(env, kevData);
      const json    = JSON.stringify(payload);
      await env.RISKSYNC_KV?.put(env.CACHE_KEY || 'threats_v1', json, { expirationTtl: 3600 });
      return new Response(json, { status:200, headers:CORS });
    } catch(err) {
      return new Response(JSON.stringify({ ok:false, error:err.message }),
        { status:500, headers:CORS });
    }
  },

  // Cron trigger — runs every 6 hours.
  // Grows the NVD cache first (the actual fix), then rebuilds the payload from it.
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        const lap = makeLap();
        const kevData = await fetchKev(env); lap('KEV fetched');
        const stage = async (name, fn) => { try { await fn(); } catch (e) { console.error(`${name} stage failed:`, e.message); } lap(`${name} stage done`); };
        await stage('CVE record', () => runCveRecordSync(env, kevData));
        await stage('OSV',        () => runOsvSync(env));
        await stage('EPSS',       () => runEpssSync(env, kevData));
        await stage('GitHub',     () => runGithubSync(env));
        const payload = await runEnrichment(env, kevData); lap('payload built');
        const json    = JSON.stringify(payload);
        await env.RISKSYNC_KV.put(env.CACHE_KEY || 'threats_v1', json, { expirationTtl: 86400 });
        lap('saved to KV');
        console.log(`KV updated: ${json.length} bytes, ${payload.count} vulns, ${payload.coverage.realCvssKev.count} KEV with real CVSS, ${payload.osvCount} from OSV`);
      } catch(e) {
        console.error('Scheduled enrichment failed:', e.message);
      }
    })());
  },
};
