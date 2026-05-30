export async function onRequest(context) {
  const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
    'Cache-Control': 'public, s-maxage=21600, stale-while-revalidate=86400',
  };

  try {
    // ── CISA KEV ──
    const kevRes  = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      headers: { 'User-Agent': 'RiskSync/1.0' },
      cf: { cacheTtl: 21600 }
    });
    const kevText = await kevRes.text();
    const kevData = JSON.parse(kevText);
    const kevSet  = new Set(kevData.vulnerabilities.map(v => v.cveID));

    // ── NVD — fetch with timeout ──
    const since = new Date(Date.now() - 30*86400000).toISOString().split('.')[0] + '.000';
    const nvdHeaders = { 'User-Agent': 'RiskSync/1.0' };

    const nvdCritRes = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate=${since}&resultsPerPage=100`,
      { headers: nvdHeaders, cf: { cacheTtl: 21600 } }
    );
    const nvdCritText = await nvdCritRes.text();
    const nvdCrit = JSON.parse(nvdCritText);

    const nvdHighRes = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH&pubStartDate=${since}&resultsPerPage=60`,
      { headers: nvdHeaders, cf: { cacheTtl: 21600 } }
    );
    const nvdHighText = await nvdHighRes.text();
    const nvdHigh = JSON.parse(nvdHighText);

    const allNvd = [
      ...(nvdCrit.vulnerabilities || []),
      ...(nvdHigh.vulnerabilities  || []),
    ];

    const CWE_MAP = {
      'CWE-89':'injection','CWE-79':'injection','CWE-78':'injection',
      'CWE-787':'memory_corruption','CWE-416':'privesc','CWE-284':'auth',
      'CWE-287':'auth','CWE-306':'auth','CWE-502':'deserialization',
      'CWE-427':'supply_chain','CWE-601':'phishing','CWE-918':'api_abuse',
    };

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

    // ── EPSS — optional enrichment ──
    if (mapped.length > 0) {
      try {
        const ids     = mapped.slice(0, 100).map(v => v.id).join(',');
        const epssRes = await fetch(`https://api.first.org/data/v1/epss?cve=${ids}`, {
          headers: nvdHeaders
        });
        const epssText = await epssRes.text();
        const epssData = JSON.parse(epssText);
        const epssMap  = {};
        (epssData.data || []).forEach(e => { epssMap[e.cve] = parseFloat(e.epss); });
        mapped.forEach(v => { if (epssMap[v.id] !== undefined) v.epss = epssMap[v.id]; });
      } catch(e) { /* EPSS optional — skip if unavailable */ }
    }

    return new Response(JSON.stringify({
      ok: true,
      count: mapped.length,
      kevCount: kevSet.size,
      updatedAt: new Date().toISOString(),
      vulns: mapped,
    }), { status: 200, headers: CORS });

  } catch(err) {
    // Return error with details for debugging
    return new Response(JSON.stringify({
      ok: false,
      error: err.message,
      stack: err.stack?.slice(0, 500),
    }), { status: 500, headers: CORS });
  }
}
