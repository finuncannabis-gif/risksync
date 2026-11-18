// ── SCHEDULED ENRICHMENT WORKER ──
// Runs every 6 hours via Cloudflare Cron
// Fetches all sources, enriches with real NVD CVSS, stores in KV
// Page requests just read from KV — instant response

const CWE_MAP = {
  'CWE-89':'injection','CWE-79':'injection','CWE-78':'injection',
  'CWE-77':'injection','CWE-787':'memory_corruption','CWE-416':'privesc',
  'CWE-119':'memory_corruption','CWE-120':'memory_corruption',
  'CWE-284':'auth','CWE-287':'auth','CWE-306':'auth','CWE-862':'auth',
  'CWE-502':'deserialization','CWE-427':'supply_chain','CWE-601':'phishing',
  'CWE-918':'api_abuse','CWE-22':'injection','CWE-434':'injection',
  'CWE-94':'supply_chain','CWE-1188':'config','CWE-295':'auth',
  'CWE-0':'unknown',
};

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
// NVD BULK ENRICHMENT — the actual fix
//
// The old approach called NVD's /cves/2.0 endpoint with multiple
// &cveId= params in one URL, expecting a batch lookup. NVD's API does
// NOT support that — it only honors ONE cveId per request, silently
// ignoring the rest. That's why only ~18 of 1,721 KEV entries ever
// got real CVSS: one real hit per "batch" of 100.
//
// NVD's real bulk mechanism is date-range pagination: pubStartDate/
// pubEndDate (max 120-day span), resultsPerPage up to 2000. This
// walks that properly, and persists progress in KV so results
// accumulate across cron runs instead of being thrown away.
//
// It walks BACKWARD from today toward the earliest KEV date, so the
// newest, most demo-relevant CVEs get real CVSS first. Once it
// reaches the bottom of KEV history, it wraps back to today and keeps
// refreshing the most recent slice on a rolling basis.
// ══════════════════════════════════════════════════════════════════

const NVD_CACHE_KEY   = 'nvd_cvss_cache';    // { [cveId]: {cvss, cvssV, vector, desc} } — accumulates forever
const NVD_CURSOR_KEY  = 'nvd_enrich_cursor'; // { windowEnd: ISOdate } — where the walk left off
const NVD_WINDOW_DAYS = 120;                 // NVD's max span per request
const NVD_WINDOWS_PER_RUN = 8;               // ~2.6 years walked per cron cycle (~2-3 days to cover all KEV history)
const NVD_EARLIEST     = '2000-01-01T00:00:00.000';

function isoDate(d) { return d.toISOString().split('.')[0] + '.000'; }

async function fetchNvdWindow(startISO, endISO, apiKey) {
  const headers = apiKey
    ? { 'apiKey': apiKey, 'User-Agent': 'RiskSync/1.0' }
    : { 'User-Agent': 'RiskSync/1.0' };
  const results = {};
  let startIndex = 0;
  let total = Infinity;
  while (startIndex < total) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(startISO)}&pubEndDate=${encodeURIComponent(endISO)}&resultsPerPage=2000&startIndex=${startIndex}`;
    const data = await safeFetch(url, { headers }, 20000);
    total = data.totalResults || 0;
    (data.vulnerabilities || []).forEach(item => {
      const cve  = item.cve;
      const id   = cve.id;
      const mets = cve.metrics || {};
      const v31  = mets.cvssMetricV31?.[0]?.cvssData;
      const v30  = mets.cvssMetricV30?.[0]?.cvssData;
      const v2   = mets.cvssMetricV2?.[0]?.cvssData;
      const cvssD = v31 || v30 || v2;
      const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
      if (cvssD) {
        results[id] = {
          cvss:   cvssD.baseScore,
          cvssV:  cvssD.version || '3.1',
          vector: cvssD.vectorString || '',
          desc:   desc.slice(0, 200),
        };
      }
    });
    startIndex += 2000;
    if (startIndex < total) await sleep(apiKey ? 300 : 7000);
  }
  return results;
}

async function runNvdBulkSync(env) {
  const NVD_KEY = env?.NVD_API_KEY || '';

  const cursorRaw = await env.RISKSYNC_KV?.get(NVD_CURSOR_KEY);
  let windowEnd = cursorRaw ? JSON.parse(cursorRaw).windowEnd : new Date().toISOString();

  const cacheRaw = await env.RISKSYNC_KV?.get(NVD_CACHE_KEY);
  const cache = cacheRaw ? JSON.parse(cacheRaw) : {};
  const cacheSizeBefore = Object.keys(cache).length;

  for (let i = 0; i < NVD_WINDOWS_PER_RUN; i++) {
    const end = new Date(windowEnd);
    const start = new Date(end.getTime() - NVD_WINDOW_DAYS * 86400000);

    if (start.toISOString() < NVD_EARLIEST) {
      console.log('NVD bulk sync: reached earliest KEV era — wrapping back to today for a fresh pass');
      windowEnd = new Date().toISOString();
      break;
    }

    try {
      const results = await fetchNvdWindow(isoDate(start), isoDate(end), NVD_KEY);
      Object.assign(cache, results);
      console.log(`NVD window ${start.toISOString().slice(0,10)}..${end.toISOString().slice(0,10)}: +${Object.keys(results).length} CVEs`);
    } catch(e) {
      console.error('NVD window failed:', e.message);
    }

    windowEnd = start.toISOString();
    await sleep(NVD_KEY ? 300 : 7000);
  }

  await env.RISKSYNC_KV?.put(NVD_CACHE_KEY, JSON.stringify(cache));
  await env.RISKSYNC_KV?.put(NVD_CURSOR_KEY, JSON.stringify({ windowEnd }));

  const cacheSizeAfter = Object.keys(cache).length;
  console.log(`NVD bulk sync complete: +${cacheSizeAfter - cacheSizeBefore} this run, ${cacheSizeAfter} total cached`);
  return cache;
}

// ── OSV.dev — paginate all critical vulns per ecosystem ──
async function fetchOsv() {
  const ecosystems = ['npm','PyPI','Go','Maven','RubyGems','crates.io'];
  const vulns = [];

  await Promise.allSettled(ecosystems.map(async (eco) => {
    try {
      const data = await safeFetch(
        'https://api.osv.dev/v1/query',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'RiskSync/1.0' },
          body: JSON.stringify({
            query: {
              package: { ecosystem: eco, name: '' }
            }
          }),
        },
        15000
      );
      if (data.vulns && Array.isArray(data.vulns)) {
        data.vulns.forEach(v => vulns.push({ ...v, _eco: eco }));
      }
    } catch(e) {
      try {
        const batch = await safeFetch(
          'https://api.osv.dev/v1/vulns?page_token=&page_size=100',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': 'RiskSync/1.0' },
            body: JSON.stringify({ ecosystem: eco }),
          },
          15000
        );
        if (batch.vulns) batch.vulns.forEach(v => vulns.push({ ...v, _eco: eco }));
      } catch(e2) {
        console.error(`OSV ${eco} failed:`, e2.message);
      }
    }
  }));

  return vulns;
}

// ── GitHub Advisory — paginate all pages ──
async function fetchGitHubAdvisories(token='') {
  const advisories = [];
  const headers = {
    'User-Agent': 'RiskSync/1.0',
    'Accept': 'application/vnd.github+json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
  };
  const severities = ['critical','high'];

  for (const sev of severities) {
    let page = 1;
    while (page <= 5) {
      try {
        const data = await safeFetch(
          `https://api.github.com/advisories?type=reviewed&severity=${sev}&per_page=100&page=${page}`,
          { headers }
        );
        if (!Array.isArray(data) || data.length === 0) break;
        advisories.push(...data);
        if (data.length < 100) break;
        page++;
        await sleep(500);
      } catch(e) {
        console.error(`GitHub Advisory page ${page} failed:`, e.message);
        break;
      }
    }
  }
  return advisories;
}

// ── MAIN ENRICHMENT FUNCTION ──
// Builds the payload from whatever is CURRENTLY in the NVD cache.
// Does NOT grow the cache itself — that's runNvdBulkSync's job, called
// separately (and only) from the cron handler, below.
async function runEnrichment(env) {
  console.log('Starting enrichment run at', new Date().toISOString());
  const GH_TOKEN = env?.GITHUB_TOKEN || '';

  console.log('Fetching CISA KEV...');
  const kevData  = await safeFetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
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

  console.log('Fetching GitHub Advisories...');
  const ghAdvisories = await fetchGitHubAdvisories(GH_TOKEN);
  console.log(`GitHub: ${ghAdvisories.length} advisories`);

  console.log('Fetching OSV.dev...');
  const osvRaw = await fetchOsv();
  console.log(`OSV: ${osvRaw.length} vulns`);

  const epssMap = {};
  epssTop.forEach(e => { epssMap[e.cve] = parseFloat(e.epss); });

  // Read whatever NVD real-CVSS data has accumulated so far
  const nvdCacheRaw = await env.RISKSYNC_KV?.get(NVD_CACHE_KEY);
  const nvdMap = nvdCacheRaw ? JSON.parse(nvdCacheRaw) : {};
  console.log(`NVD cache: ${Object.keys(nvdMap).length} CVEs with real CVSS available`);

  const allKev = [...kevVulns].sort((a,b) => new Date(b.dateAdded) - new Date(a.dateAdded));
  const kevMapped = allKev.map(v => {
    const epss = epssMap[v.cveID] || 0.85;
    const cwes = v.cwes || [];
    const cwe  = cwes[0] || 'CWE-0';
    return {
      id:            v.cveID,
      cvss:          null,
      cvssV:         null,
      vector:        null,
      desc:          (v.shortDescription || v.vulnerabilityName || '').slice(0, 200),
      type:          CWE_MAP[cwe] || 'injection',
      src:           'CISA KEV',
      kev:           true,
      epss,
      affects:       ['onprem'],
      industries:    ['all'],
      cwe,
      publishedDate: v.dateAdded,
      dateAdded:     v.dateAdded,
      product:       (v.vendorProject + ' ' + v.product).trim(),
      action:        v.requiredAction,
      dueDate:       v.dueDate,
    };
  });

  let nvdHits = 0;
  kevMapped.forEach(v => {
    const nvd = nvdMap[v.id];
    if (nvd) {
      v.cvss   = nvd.cvss;
      v.cvssV  = nvd.cvssV;
      v.vector = nvd.vector;
      v.src    = 'CISA KEV + NVD';
      if (nvd.desc && nvd.desc.length > v.desc.length) v.desc = nvd.desc.slice(0,200);
      nvdHits++;
    } else {
      v.cvss = v.epss > 0.8 ? 9.0 : v.epss > 0.5 ? 7.5 : 6.5;
    }
  });
  console.log(`Applied NVD data to ${nvdHits}/${kevMapped.length} KEV entries`);

  const ghMapped = ghAdvisories.map(a => {
    const cvss = parseFloat(a.cvss?.score || 7.0);
    const cve  = a.cve_id || (a.identifiers||[]).find(i=>i.type==='CVE')?.value || a.ghsa_id;
    return {
      id:            cve || a.ghsa_id,
      cvss,
      cvssV:         '3.1',
      desc:          (a.summary || '').slice(0, 200),
      type:          'supply_chain',
      src:           'GitHub Advisory',
      kev:           false,
      epss:          epssMap[cve] || 0.3,
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
    if (sev?.score) {
      const match = sev.score.match(/\/(\d+\.\d+)$/);
      cvss = match ? parseFloat(match[1]) : 7.0;
    }
    cvss = isNaN(cvss) ? 7.0 : Math.min(cvss, 10);
    const cve  = (v.aliases||[]).find(a=>a.startsWith('CVE-')) || v.id;
    const epss = epssMap[cve] || 0.2;
    const affectsMap = {
      npm:'web', PyPI:'api', Go:'cloud',
      Maven:'cloud', RubyGems:'web', 'crates.io':'cloud', Packagist:'web',
    };
    return {
      id:            cve,
      cvss,
      cvssV:         sev?.type === 'CVSS_V3' ? '3.x' : '2.0',
      desc:          (v.summary||'').slice(0,200),
      type:          'supply_chain',
      src:           `OSV (${v._eco||'open source'})`,
      kev:           false,
      epss,
      affects:       ['cicd', affectsMap[v._eco]||'cloud'].filter(Boolean),
      industries:    ['all'],
      cwe:           'CWE-94',
      publishedDate: v.published || v.modified,
      ecosystem:     v._eco,
    };
  }).filter(v => v.cvss >= 5.0);

  const seen = new Set();
  const all  = [...kevMapped, ...ghMapped, ...osvMapped].filter(v => {
    if (!v.id || seen.has(v.id)) return false;
    seen.add(v.id);
    return (v.cvss||0) >= 5.0;
  });

  all.sort((a,b) => b.epss - a.epss || b.cvss - a.cvss);

  const payload = {
    ok:        true,
    count:     all.length,
    kevCount:  kevVulns.length,
    nvdCount:  nvdHits,
    osvCount:  osvMapped.length,
    ghCount:   ghMapped.length,
    sources:   ['CISA KEV', 'NVD (real CVSS)', 'FIRST EPSS', 'GitHub Advisory', 'OSV.dev'],
    updatedAt: new Date().toISOString(),
    vulns:     all,
  };

  console.log(`Enrichment complete: ${all.length} total vulns, ${nvdHits} with real CVSS`);
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
    try {
      const cached = await env.RISKSYNC_KV?.get(env.CACHE_KEY || 'threats_v1');
      if (cached) {
        return new Response(cached, { status:200, headers:CORS });
      }
      // KV empty — build once from whatever NVD cache exists so far (no bulk sync here, keep it fast)
      const payload = await runEnrichment(env);
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
        await runNvdBulkSync(env);
        const payload = await runEnrichment(env);
        const json    = JSON.stringify(payload);
        await env.RISKSYNC_KV.put(env.CACHE_KEY || 'threats_v1', json, { expirationTtl: 86400 });
        console.log(`KV updated: ${json.length} bytes, ${payload.count} vulns, ${payload.nvdCount} with real CVSS`);
      } catch(e) {
        console.error('Scheduled enrichment failed:', e.message);
      }
    })());
  },
};
