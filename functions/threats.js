export async function onRequest(context) {
  const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
    'Cache-Control': 'public, s-maxage=21600, stale-while-revalidate=86400',
  };

  const CWE_MAP = {
    'CWE-89':'injection','CWE-79':'injection','CWE-78':'injection',
    'CWE-787':'memory_corruption','CWE-416':'privesc','CWE-284':'auth',
    'CWE-287':'auth','CWE-306':'auth','CWE-502':'deserialization',
    'CWE-427':'supply_chain','CWE-601':'phishing','CWE-918':'api_abuse',
  };

  async function safeFetchJson(url) {
    const res  = await fetch(url, { headers: { 'User-Agent': 'RiskSync/1.0 (security research)' } });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
    const text = await res.text();
    if (!text || text.trim() === '') throw new Error(`Empty response from ${url}`);
    return JSON.parse(text);
  }

  try {
    const since = new Date(Date.now() - 30*86400000).toISOString().split('.')[0] + '.000';

    // Fetch CISA KEV first
    let kevSet = new Set();
    try {
      const kevData = await safeFetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      kevSet = new Set((kevData.vulnerabilities || []).map(v => v.cveID));
    } catch(e) {
      // KEV unavailable — continue without it
    }

    // Fetch NVD CRITICAL
    let critVulns = [];
    try {
      const nvdCrit = await safeFetchJson(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate=${since}&resultsPerPage=100`
      );
      critVulns = nvdCrit.vulnerabilities || [];
    } catch(e) { /* continue */ }

    // Fetch NVD HIGH
    let highVulns = [];
    try {
      const nvdHigh = await safeFetchJson(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH&pubStartDate=${since}&resultsPerPage=60`
      );
      highVulns = nvdHigh.vulnerabilities || [];
    } catch(e) { /* continue */ }

    const allNvd = [...critVulns, ...highVulns];

    // If NVD returned nothing, return curated fallback signal
    if (allNvd.length === 0) {
      return new Response(JSON.stringify({
        ok: false,
        error: 'NVD returned no data — may be rate limited. Try again in 30 seconds.',
        kevCount: kevSet.size,
      }), { status: 503, headers: CORS });
    }

    const mapped = allNvd.map(entry => {
      const cve     = entry.cve;
      const id      = cve.id;
      const desc    = (cve.descriptions?.find(d => d.lang === 'en')?.value || '').slice(0, 120);
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

    // EPSS enrichment — optional
    try {
      const ids     = mapped.slice(0, 80).map(v => v.id).join(',');
      const epssData = await safeFetchJson(`https://api.first.org/data/v1/epss?cve=${ids}`);
      const epssMap = {};
      (epssData.data || []).forEach(e => { epssMap[e.cve] = parseFloat(e.epss); });
      mapped.forEach(v => { if (epssMap[v.id] !== undefined) v.epss = epssMap[v.id]; });
    } catch(e) { /* EPSS optional */ }

    return new Response(JSON.stringify({
      ok: true,
      count: mapped.length,
      kevCount: kevSet.size,
      updatedAt: new Date().toISOString(),
      vulns: mapped,
    }), { status: 200, headers: CORS });

  } catch(err) {
    return new Response(JSON.stringify({
      ok: false,
      error: err.message,
    }), { status: 500, headers: CORS });
  }
}
