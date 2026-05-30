// Cloudflare Pages Function — runs at the edge in 200+ cities
// Free: 100,000 requests/day
// Cache: 6 hours at edge = ~4 function executions/day regardless of traffic

export async function onRequest(context) {
  const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
    // Cache 6 hours at Cloudflare edge — serves millions of visitors for free
    'Cache-Control': 'public, s-maxage=21600, stale-while-revalidate=86400',
  };

  // Return cached response if available
  const cache = caches.default;
  const cacheKey = new Request('https://risksync-cache/threats', context.request);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  try {
    // Fetch all 3 sources in parallel
    const [kevRes, nvdCritRes, nvdHighRes] = await Promise.all([
      fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
      fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate=' + new Date(Date.now()-30*86400000).toISOString().split('.')[0] + '.000&resultsPerPage=100'),
      fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH&pubStartDate=' + new Date(Date.now()-30*86400000).toISOString().split('.')[0] + '.000&resultsPerPage=60'),
    ]);

    const [kevData, nvdCrit, nvdHigh] = await Promise.all([
      kevRes.json(), nvdCritRes.json(), nvdHighRes.json()
    ]);

    const kevSet = new Set(kevData.vulnerabilities.map(v => v.cveID));
    const allNvd = [...(nvdCrit.vulnerabilities||[]), ...(nvdHigh.vulnerabilities||[])];

    const CWE_MAP = {
      'CWE-89':'injection','CWE-79':'injection','CWE-78':'injection',
      'CWE-787':'memory_corruption','CWE-416':'privesc','CWE-284':'auth',
      'CWE-287':'auth','CWE-306':'auth','CWE-502':'deserialization',
      'CWE-427':'supply_chain','CWE-601':'phishing','CWE-918':'api_abuse',
    };

    const mapped = allNvd.map(entry => {
      const cve     = entry.cve;
      const id      = cve.id;
      const desc    = (cve.descriptions?.find(d=>d.lang==='en')?.value||'').slice(0,120);
      const cwe     = cve.weaknesses?.[0]?.description?.[0]?.value || 'CWE-0';
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
      const cvss    = parseFloat(metrics?.cvssData?.baseScore || 5.0);
      const isKev   = kevSet.has(id);
      return {
        id, cvss, desc,
        type:          CWE_MAP[cwe] || 'injection',
        src:           isKev ? 'NVD+KEV' : 'NVD',
        kev:           isKev,
        epss:          isKev ? 0.85 : 0.3,
        affects:       ['onprem'],
        industries:    ['all'],
        cwe,
        publishedDate: cve.published,
      };
    }).filter(v => v.cvss >= 5.0);

    // EPSS enrichment
    if (mapped.length > 0) {
      try {
        const epssRes  = await fetch(`https://api.first.org/data/v1/epss?cve=${mapped.map(v=>v.id).join(',')}`);
        const epssData = await epssRes.json();
        const epssMap  = {};
        (epssData.data||[]).forEach(e => { epssMap[e.cve] = parseFloat(e.epss); });
        mapped.forEach(v => { if (epssMap[v.id] !== undefined) v.epss = epssMap[v.id]; });
      } catch(e) { /* EPSS optional */ }
    }

    const body = JSON.stringify({
      ok: true,
      count: mapped.length,
      kevCount: kevSet.size,
      updatedAt: new Date().toISOString(),
      vulns: mapped,
    });

    const response = new Response(body, { status: 200, headers: CORS });

    // Store in Cloudflare cache
    context.waitUntil(cache.put(cacheKey, response.clone()));

    return response;

  } catch(err) {
    return new Response(
      JSON.stringify({ ok: false, error: err.message }),
      { status: 500, headers: CORS }
    );
  }
}
