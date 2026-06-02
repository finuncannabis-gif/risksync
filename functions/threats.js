export async function onRequest(context) {
  const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
    'Cache-Control': 'public, s-maxage=21600, stale-while-revalidate=86400',
  };

  try {
    // Read pre-enriched data from KV — instant, no API calls
    const cached = await context.env.RISKSYNC_KV?.get(
      context.env.CACHE_KEY || 'threats_v1'
    );

    if (cached) {
      return new Response(cached, { status:200, headers:CORS });
    }

    // KV not yet populated — fall back to live fetch (first cold start only)
    // Import and run enrichment inline
    const { runEnrichment } = await import('./enrich.js');
    const payload = await runEnrichment(context.env);
    const json    = JSON.stringify(payload);

    // Cache it
    await context.env.RISKSYNC_KV?.put(
      context.env.CACHE_KEY || 'threats_v1',
      json,
      { expirationTtl: 86400 }
    );

    return new Response(json, { status:200, headers:CORS });

  } catch(err) {
    // Final fallback — return error with helpful message
    return new Response(JSON.stringify({
      ok:      false,
      error:   err.message,
      hint:    'KV namespace may not be configured. Check wrangler.toml and Cloudflare dashboard.',
    }), { status:500, headers:CORS });
  }
}
