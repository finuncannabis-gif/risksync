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

  async function safeFetch(url, opts={}) {
    const res  = await fetch(url, { headers:{'User-Agent':'RiskSync/1.0'}, ...opts });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (!text.trim()) throw new Error('Empty');
    return JSON.parse(text);
  }

  try {
    // ── SOURCE 1: CISA KEV — always works, 1600+ real exploited CVEs ──
    const kevData  = await safeFetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    const kevVulns = kevData.vulnerabilities || [];

    // ── SOURCE 2: EPSS top exploitable CVEs from FIRST.org ──
    // Returns top CVEs by exploitation probability — no IP blocking
    let epssTop = [];
    try {
      const epss = await safeFetch('https://api.first.org/data/v1/epss?order=!epss&limit=100');
      epssTop = epss.data || [];
    } catch(e) {}

    // ── SOURCE 3: GitHub Advisory Database — open, no rate limits ──
    let ghAdvisories = [];
    try {
      const gh = await safeFetch(
        'https://api.github.com/advisories?type=reviewed&severity=critical&per_page=50',
        { headers:{'User-Agent':'RiskSync/1.0','Accept':'application/vnd.github+json'} }
      );
      ghAdvisories = Array.isArray(gh) ? gh : [];
    } catch(e) {}

    // ── Map KEV entries to internal schema ──
    // KEV has: cveID, vendorProject, product, vulnerabilityName, dateAdded, 
    //          shortDescription, requiredAction, dueDate, cwes
    const epssMap = {};
    epssTop.forEach(e => { epssMap[e.cve] = parseFloat(e.epss); });

    // Take most recent 60 KEV entries (sorted by dateAdded desc)
    const recentKev = [...kevVulns]
      .sort((a,b) => new Date(b.dateAdded) - new Date(a.dateAdded))
      .slice(0, 60);

    const kevMapped = recentKev.map(v => {
      const epss  = epssMap[v.cveID] || 0.85; // KEV = known exploited, high EPSS
      const cwes  = (v.cwes || []);
      const cwe   = cwes[0] || 'CWE-0';
      // Estimate CVSS from EPSS and KEV status
      const cvss  = epss > 0.8 ? 9.0 : epss > 0.5 ? 7.5 : 6.5;
      return {
        id:            v.cveID,
        cvss,
        desc:          (v.shortDescription || v.vulnerabilityName || '').slice(0, 120),
        type:          CWE_MAP[cwe] || 'injection',
        src:           'CISA KEV',
        kev:           true,
        epss,
        affects:       ['onprem'],
        industries:    ['all'],
        cwe,
        publishedDate: v.dateAdded,
        product:       v.vendorProject + ' ' + v.product,
        action:        v.requiredAction,
        dueDate:       v.dueDate,
      };
    });

    // ── Map GitHub advisories ──
    const ghMapped = ghAdvisories.map(a => {
      const cvss = a.cvss?.score || 7.0;
      const cve  = a.cve_id || (a.identifiers||[]).find(i=>i.type==='CVE')?.value || a.ghsa_id;
      return {
        id:            cve || a.ghsa_id,
        cvss:          parseFloat(cvss),
        desc:          (a.summary || '').slice(0, 120),
        type:          'supply_chain',
        src:           'GitHub Advisory',
        kev:           false,
        epss:          epssMap[cve] || 0.3,
        affects:       ['cicd'],
        industries:    ['all'],
        cwe:           'CWE-0',
        publishedDate: a.published_at,
      };
    }).filter(v => v.cvss >= 7.0);

    // ── Combine + deduplicate ──
    const seen = new Set();
    const all  = [...kevMapped, ...ghMapped].filter(v => {
      if (seen.has(v.id)) return false;
      seen.add(v.id);
      return v.cvss >= 5.0;
    });

    // Sort by EPSS desc (most likely to be exploited today)
    all.sort((a,b) => b.epss - a.epss || b.cvss - a.cvss);

    return new Response(JSON.stringify({
      ok:        true,
      count:     all.length,
      kevCount:  kevVulns.length,
      sources:   ['CISA KEV', 'FIRST EPSS', 'GitHub Advisory'],
      updatedAt: new Date().toISOString(),
      vulns:     all,
    }), { status:200, headers:CORS });

  } catch(err) {
    return new Response(JSON.stringify({
      ok: false, error: err.message,
    }), { status:500, headers:CORS });
  }
}
