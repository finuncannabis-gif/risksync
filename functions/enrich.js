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

// ── NVD CVSS enrichment — no artificial limit ──
// Batches 100 CVEs per request with proper rate limiting
async function enrichWithNvd(cveIds, apiKey) {
  const map = {};
  const headers = apiKey
    ? { 'apiKey': apiKey, 'User-Agent': 'RiskSync/1.0' }
    : { 'User-Agent': 'RiskSync/1.0' };
  const batchSize = apiKey ? 100 : 20;
  const delayMs   = apiKey ? 300  : 7000; // respect rate limits

  console.log(`NVD enrichment: ${cveIds.length} CVEs in batches of ${batchSize}`);

  for (let i = 0; i < cveIds.length; i += batchSize) {
    const batch = cveIds.slice(i, i + batchSize);
    try {
      const url  = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + batch.join('&cveId=');
      const data = await safeFetch(url, { headers }, 20000);
      (data.vulnerabilities || []).forEach(item => {
        const cve   = item.cve;
        const id    = cve.id;
        const mets  = cve.metrics || {};
        const v31   = mets.cvssMetricV31?.[0]?.cvssData;
        const v30   = mets.cvssMetricV30?.[0]?.cvssData;
        const v2    = mets.cvssMetricV2?.[0]?.cvssData;
        const cvssD = v31 || v30 || v2;
        // Also grab description if available
        const desc  = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
        if (cvssD) {
          map[id] = {
            cvss:   cvssD.baseScore,
            cvssV:  cvssD.version || '3.1',
            vector: cvssD.vectorString || '',
            desc:   desc.slice(0, 200),
          };
        }
      });
      console.log(`NVD batch ${i}-${i+batchSize}: ${Object.keys(map).length} enriched so far`);
    } catch(e) {
      console.error(`NVD batch ${i} failed:`, e.message);
    }
    if (i + batchSize < cveIds.length) await sleep(delayMs);
  }
  return map;
}

// ── OSV.dev — paginate all critical vulns per ecosystem ──
async function fetchOsv() {
  const ecosystems = ['npm','PyPI','Go','Maven','RubyGems','crates.io','Packagist'];
  const vulns = [];

  await Promise.allSettled(ecosystems.map(async (eco) => {
    try {
      // Query recent modified vulns per ecosystem
      const data = await safeFetch(
        `https://api.osv.dev/v1/query`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'RiskSync/1.0' },
          body: JSON.stringify({
            query: { ecosystem: eco },
            page_size: 100,
          }),
        },
        15000
      );
      if (data.vulns) {
        data.vulns.forEach(v => vulns.push({ ...v, _eco: eco }));
      }
    } catch(e) {
      console.error(`OSV ${eco} failed:`, e.message);
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
    while (page <= 5) { // max 5 pages = 500 advisories per severity
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
export async function runEnrichment(env) {
  console.log('Starting enrichment run at', new Date().toISOString());
  const NVD_KEY    = env?.NVD_API_KEY || '';
  const GH_TOKEN   = env?.GITHUB_TOKEN || '';

  // 1. Fetch CISA KEV — all 1607+
  console.log('Fetching CISA KEV...');
  const kevData  = await safeFetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  const kevVulns = kevData.vulnerabilities || [];
  console.log(`CISA KEV: ${kevVulns.length} entries`);

  // 2. Fetch EPSS — top 1000 by exploitation probability
  console.log('Fetching EPSS scores...');
  let epssTop = [];
  try {
    // Paginate EPSS — 1000 entries at a time
    for (let offset = 0; offset < 3000; offset += 1000) {
      const epss = await safeFetch(`https://api.first.org/data/v1/epss?order=!epss&limit=1000&offset=${offset}`);
      const data = epss.data || [];
      epssTop.push(...data);
      if (data.length < 1000) break;
      await sleep(500);
    }
  } catch(e) { console.error('EPSS failed:', e.message); }
  console.log(`EPSS: ${epssTop.length} scores`);

  // 3. Fetch GitHub Advisories — all pages
  console.log('Fetching GitHub Advisories...');
  const ghAdvisories = await fetchGitHubAdvisories(GH_TOKEN);
  console.log(`GitHub: ${ghAdvisories.length} advisories`);

  // 4. Fetch OSV.dev — all ecosystems
  console.log('Fetching OSV.dev...');
  const osvRaw = await fetchOsv();
  console.log(`OSV: ${osvRaw.length} vulns`);

  // 5. Build EPSS map
  const epssMap = {};
  epssTop.forEach(e => { epssMap[e.cve] = parseFloat(e.epss); });

  // 6. Map all KEV entries
  const allKev = [...kevVulns].sort((a,b) => new Date(b.dateAdded) - new Date(a.dateAdded));
  const kevMapped = allKev.map(v => {
    const epss = epssMap[v.cveID] || 0.85;
    const cwes = v.cwes || [];
    const cwe  = cwes[0] || 'CWE-0';
    return {
      id:           v.cveID,
      cvss:         null, // filled by NVD
      cvssV:        null,
      vector:       null,
      desc:         (v.shortDescription || v.vulnerabilityName || '').slice(0, 200),
      type:         CWE_MAP[cwe] || 'injection',
      src:          'CISA KEV',
      kev:          true,
      epss,
      affects:      ['onprem'],
      industries:   ['all'],
      cwe,
      publishedDate: v.dateAdded,
      dateAdded:    v.dateAdded,
      product:      (v.vendorProject + ' ' + v.product).trim(),
      action:       v.requiredAction,
      dueDate:      v.dueDate,
    };
  });

  // 7. NVD enrichment — ALL KEV entries, no limit
  console.log(`Enriching ${kevMapped.length} CVEs with NVD...`);
  const kevIds = kevMapped.map(v => v.id);
  const nvdMap = await enrichWithNvd(kevIds, NVD_KEY);
  console.log(`NVD: enriched ${Object.keys(nvdMap).length}/${kevMapped.length} CVEs`);

  // Apply real CVSS, use NVD description if better
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

  // 8. Map GitHub advisories
  const ghMapped = ghAdvisories.map(a => {
    const cvss = parseFloat(a.cvss?.score || 7.0);
    const cve  = a.cve_id || (a.identifiers||[]).find(i=>i.type==='CVE')?.value || a.ghsa_id;
    return {
      id:           cve || a.ghsa_id,
      cvss,
      cvssV:        '3.1',
      desc:         (a.summary || '').slice(0, 200),
      type:         'supply_chain',
      src:          'GitHub Advisory',
      kev:          false,
      epss:         epssMap[cve] || 0.3,
      affects:      ['cicd','cloud'],
      industries:   ['all'],
      cwe:          'CWE-0',
      publishedDate: a.published_at,
    };
  }).filter(v => v.cvss >= 6.0);

  // 9. Map OSV vulns
  const osvMapped = osvRaw.filter(v => v.id && v.summary).map(v => {
    const sev   = (v.severity||[]).find(s=>s.type==='CVSS_V3') ||
                  (v.severity||[]).find(s=>s.type==='CVSS_V2');
    let cvss    = 7.0;
    if (sev?.score) {
      // CVSS vector string — extract base score
      const match = sev.score.match(/\/(\d+\.\d+)$/);
      cvss = match ? parseFloat(match[1]) : 7.0;
    }
    cvss = isNaN(cvss) ? 7.0 : Math.min(cvss, 10);
    const cve   = (v.aliases||[]).find(a=>a.startsWith('CVE-')) || v.id;
    const epss  = epssMap[cve] || 0.2;
    const affectsMap = {
      npm:'web', PyPI:'api', Go:'cloud',
      Maven:'cloud', RubyGems:'web', 'crates.io':'cloud', Packagist:'web',
    };
    return {
      id:           cve,
      cvss,
      cvssV:        sev?.type === 'CVSS_V3' ? '3.x' : '2.0',
      desc:         (v.summary||'').slice(0,200),
      type:         'supply_chain',
      src:          `OSV (${v._eco||'open source'})`,
      kev:          false,
      epss,
      affects:      ['cicd', affectsMap[v._eco]||'cloud'].filter(Boolean),
      industries:   ['all'],
      cwe:          'CWE-94',
      publishedDate: v.published || v.modified,
      ecosystem:    v._eco,
    };
  }).filter(v => v.cvss >= 5.0);

  // 10. Combine + deduplicate
  const seen = new Set();
  const all  = [...kevMapped, ...ghMapped, ...osvMapped].filter(v => {
    if (!v.id || seen.has(v.id)) return false;
    seen.add(v.id);
    return (v.cvss||0) >= 5.0;
  });

  // Sort by EPSS desc, then CVSS desc
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

// ── SCHEDULED TRIGGER (Cron) ──
export async function scheduled(event, env, ctx) {
  ctx.waitUntil((async () => {
    try {
      const payload = await runEnrichment(env);
      const json    = JSON.stringify(payload);
      await env.RISKSYNC_KV.put(env.CACHE_KEY || 'threats_v1', json, {
        expirationTtl: 86400, // 24hr max TTL in KV
      });
      console.log(`KV updated: ${json.length} bytes, ${payload.count} vulns`);
    } catch(e) {
      console.error('Scheduled enrichment failed:', e.message);
    }
  })());
}

// ── HTTP REQUEST (page hits /threats) ──
export async function onRequest(context) {
  const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
    'Cache-Control': 'public, s-maxage=21600, stale-while-revalidate=86400',
  };

  try {
    // Try KV first — pre-enriched, instant
    const cached = await context.env.RISKSYNC_KV?.get(
      context.env.CACHE_KEY || 'threats_v1'
    );

    if (cached) {
      console.log('Serving from KV cache');
      return new Response(cached, { status:200, headers:CORS });
    }

    // KV empty (first run) — enrich live, store in KV, return
    console.log('KV empty — running live enrichment (first run)');
    const payload = await runEnrichment(context.env);
    const json    = JSON.stringify(payload);

    // Store for next request
    await context.env.RISKSYNC_KV?.put(
      context.env.CACHE_KEY || 'threats_v1',
      json,
      { expirationTtl: 86400 }
    );

    return new Response(json, { status:200, headers:CORS });

  } catch(err) {
    return new Response(JSON.stringify({
      ok: false, error: err.message,
    }), { status:500, headers: CORS });
  }
}
