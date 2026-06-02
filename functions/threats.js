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
    'CWE-94':'supply_chain','CWE-22':'injection','CWE-0':'unknown',
  };

  async function safeFetch(url, opts={}) {
    const res = await fetch(url, {
      headers:{'User-Agent':'RiskSync/1.0'},
      signal: AbortSignal.timeout(8000),
      ...opts,
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }

  try {
    // ── Try KV first — populated by risksync-enricher cron worker ──
    const kv = context.env.RISKSYNC_KV;
    const cacheKey = context.env.CACHE_KEY || 'threats_v1';

    if (kv) {
      const cached = await kv.get(cacheKey);
      if (cached) {
        return new Response(cached, { status:200, headers:CORS });
      }
    }

    // ── KV empty — fast live fetch (no NVD to avoid timeout) ──
    const [kevData, epssData, ghData] = await Promise.allSettled([
      safeFetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
      safeFetch('https://api.first.org/data/v1/epss?order=!epss&limit=200'),
      safeFetch('https://api.github.com/advisories?type=reviewed&severity=critical&per_page=50',
        { headers:{'User-Agent':'RiskSync/1.0','Accept':'application/vnd.github+json'} }),
    ]);

    const kevVulns = kevData.status === 'fulfilled' ? (kevData.value.vulnerabilities || []) : [];
    const epssTop  = epssData.status === 'fulfilled' ? (epssData.value.data || []) : [];
    const ghAdvs   = ghData.status === 'fulfilled' && Array.isArray(ghData.value) ? ghData.value : [];

    const epssMap = {};
    epssTop.forEach(e => { epssMap[e.cve] = parseFloat(e.epss); });

    // Map all KEV entries
    const kevMapped = kevVulns
      .sort((a,b) => new Date(b.dateAdded) - new Date(a.dateAdded))
      .map(v => {
        const epss = epssMap[v.cveID] || 0.85;
        const cwe  = (v.cwes||[])[0] || 'CWE-0';
        const cvss = epss > 0.8 ? 9.0 : epss > 0.5 ? 7.5 : 6.5;
        return {
          id: v.cveID, cvss, desc: (v.shortDescription||v.vulnerabilityName||'').slice(0,150),
          type: CWE_MAP[cwe]||'injection', src:'CISA KEV', kev:true, epss,
          affects:['onprem'], industries:['all'], cwe,
          publishedDate:v.dateAdded, dateAdded:v.dateAdded,
          product:(v.vendorProject+' '+v.product).trim(),
          action:v.requiredAction, dueDate:v.dueDate,
        };
      });

    // Map GitHub advisories
    const ghMapped = ghAdvs.map(a => {
      const cvss = parseFloat(a.cvss?.score||7.0);
      const cve  = a.cve_id||(a.identifiers||[]).find(i=>i.type==='CVE')?.value||a.ghsa_id;
      return {
        id:cve||a.ghsa_id, cvss, desc:(a.summary||'').slice(0,150),
        type:'supply_chain', src:'GitHub Advisory', kev:false,
        epss:epssMap[cve]||0.3, affects:['cicd','cloud'], industries:['all'],
        cwe:'CWE-0', publishedDate:a.published_at,
      };
    }).filter(v=>v.cvss>=6.0);

    // Combine + deduplicate
    const seen = new Set();
    const all  = [...kevMapped, ...ghMapped].filter(v => {
      if (!v.id||seen.has(v.id)) return false;
      seen.add(v.id); return v.cvss>=5.0;
    });
    all.sort((a,b) => b.epss-a.epss || b.cvss-a.cvss);

    const payload = {
      ok:true, count:all.length, kevCount:kevVulns.length,
      nvdCount:0, osvCount:0, ghCount:ghMapped.length,
      sources:['CISA KEV','FIRST EPSS','GitHub Advisory'],
      note:'KV not yet populated — run risksync-enricher for full NVD enrichment',
      updatedAt:new Date().toISOString(), vulns:all,
    };

    // Store in KV for next request (1hr TTL so enricher cron can overwrite)
    if (kv) {
      await kv.put(cacheKey, JSON.stringify(payload), { expirationTtl: 3600 });
    }

    return new Response(JSON.stringify(payload), { status:200, headers:CORS });

  } catch(err) {
    return new Response(JSON.stringify({ ok:false, error:err.message }),
      { status:500, headers:CORS });
  }
}
