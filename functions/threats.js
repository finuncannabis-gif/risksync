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

  const NVD_KEY = context.env.NVD_API_KEY || '';
  const nvdHeaders = { 'User-Agent':'RiskSync/1.0', ...(NVD_KEY ? {'apiKey':NVD_KEY} : {}) };

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  async function safeFetch(url, headers={}, retries=3) {
    for (let i = 0; i < retries; i++) {
      try {
        if (i > 0) await sleep(6000 * i); // 6s, 12s between retries
        const res = await fetch(url, { headers: {'User-Agent':'RiskSync/1.0', ...headers} });
        if (res.status === 429) { await sleep(8000); continue; } // rate limit — wait 8s
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        if (!text || !text.trim()) throw new Error('Empty response');
        return JSON.parse(text);
      } catch(e) {
        if (i === retries - 1) throw e;
      }
    }
  }

  try {
    const since = new Date(Date.now()-30*86400000).toISOString().split('.')[0]+'.000';

    // CISA KEV
    let kevSet = new Set();
    try {
      const kev = await safeFetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      kevSet = new Set((kev.vulnerabilities||[]).map(v=>v.cveID));
    } catch(e) {}

    // NVD — fetch one at a time to avoid rate limit
    let critVulns = [], highVulns = [];
    try {
      const c = await safeFetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate=${since}&resultsPerPage=100`,
        nvdHeaders
      );
      critVulns = c.vulnerabilities || [];
    } catch(e) {}

    // Wait 2s between NVD calls even with API key
    await sleep(2000);

    try {
      const h = await safeFetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH&pubStartDate=${since}&resultsPerPage=60`,
        nvdHeaders
      );
      highVulns = h.vulnerabilities || [];
    } catch(e) {}

    const allNvd = [...critVulns, ...highVulns];

    if (allNvd.length === 0) {
      return new Response(JSON.stringify({
        ok: false,
        error: 'NVD unavailable after retries — try again shortly',
        kevCount: kevSet.size,
        hasApiKey: !!NVD_KEY,
      }), { status: 503, headers: CORS });
    }

    const mapped = allNvd.map(entry => {
      const cve  = entry.cve, id = cve.id;
      const desc = (cve.descriptions?.find(d=>d.lang==='en')?.value||'').slice(0,120);
      const cwe  = cve.weaknesses?.[0]?.description?.[0]?.value||'CWE-0';
      const m    = cve.metrics?.cvssMetricV31?.[0]||cve.metrics?.cvssMetricV30?.[0];
      const cvss = parseFloat(m?.cvssData?.baseScore||5.0);
      const isKev = kevSet.has(id);
      return { id, cvss, desc, type:CWE_MAP[cwe]||'injection',
        src:isKev?'NVD+KEV':'NVD', kev:isKev, epss:isKev?0.85:0.3,
        affects:['onprem'], industries:['all'], cwe, publishedDate:cve.published };
    }).filter(v=>v.cvss>=5.0);

    // EPSS
    try {
      const ids = mapped.slice(0,80).map(v=>v.id).join(',');
      const ep  = await safeFetch(`https://api.first.org/data/v1/epss?cve=${ids}`);
      const em  = {};
      (ep.data||[]).forEach(e=>{em[e.cve]=parseFloat(e.epss);});
      mapped.forEach(v=>{if(em[v.id]!==undefined)v.epss=em[v.id];});
    } catch(e) {}

    return new Response(JSON.stringify({
      ok: true, count: mapped.length, kevCount: kevSet.size,
      hasApiKey: !!NVD_KEY, updatedAt: new Date().toISOString(), vulns: mapped,
    }), { status:200, headers:CORS });

  } catch(err) {
    return new Response(JSON.stringify({ ok:false, error:err.message }),
      { status:500, headers:CORS });
  }
}
