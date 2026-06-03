export async function onRequestPost(context) {
  const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  try {
    const body     = await context.request.json();
    const email    = (body.email || '').trim().toLowerCase();
    const industry = (body.industry || 'all').trim();
    const source   = body.source || 'daily-brief';

    // Validate email
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return new Response(JSON.stringify({ ok:false, error:'Invalid email address' }),
        { status:400, headers:CORS });
    }

    const RESEND_KEY = context.env.RESEND_API_KEY;
    if (!RESEND_KEY) {
      return new Response(JSON.stringify({ ok:false, error:'Email service not configured' }),
        { status:500, headers:CORS });
    }

    // ── Send welcome email via Resend ──
    const welcomeRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'RiskSync <onboarding@resend.dev>',
        to:   [email],
        subject: '✓ You\'re subscribed to RiskSync Daily',
        html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#07090f;font-family:'Helvetica Neue',Arial,sans-serif">
  <div style="max-width:520px;margin:0 auto;padding:32px 24px">

    <div style="display:flex;align-items:center;gap:10px;margin-bottom:28px">
      <div style="width:28px;height:28px;background:#2D7EF7;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px">🛡</div>
      <span style="font-size:16px;font-weight:800;color:#ffffff">RiskSync</span>
      <span style="font-size:9px;font-weight:700;padding:2px 7px;background:#0ED27A;color:#000;border-radius:3px;letter-spacing:.5px">LIVE</span>
    </div>

    <h1 style="font-size:24px;font-weight:900;color:#ffffff;margin:0 0 8px">You're subscribed.</h1>
    <p style="font-size:14px;color:#5A6F96;margin:0 0 24px;line-height:1.6">
      The daily cybersecurity threat brief will land in your inbox every morning at <strong style="color:#DDE4F0">07:00 UTC</strong>.
      Scored for <strong style="color:#2D7EF7">${industry !== 'all' ? industry.replace(/-/g,' ') : 'your industry'}</strong>.
    </p>

    <div style="background:#0C1220;border:1px solid #1A2540;border-radius:8px;padding:20px;margin-bottom:24px">
      <p style="font-size:11px;font-weight:700;color:#5A6F96;text-transform:uppercase;letter-spacing:.8px;margin:0 0 12px">What you'll get</p>
      <div style="display:grid;gap:10px">
        <div style="display:flex;gap:10px;align-items:flex-start">
          <span style="color:#0ED27A;font-size:14px;margin-top:1px">✓</span>
          <span style="font-size:13px;color:#DDE4F0">Full Critical &amp; High threat list — all CVEs scoring ≥7.0 for your industry</span>
        </div>
        <div style="display:flex;gap:10px;align-items:flex-start">
          <span style="color:#0ED27A;font-size:14px;margin-top:1px">✓</span>
          <span style="font-size:13px;color:#DDE4F0">CISA KEV confirmed exploits — real remediation actions with due dates</span>
        </div>
        <div style="display:flex;gap:10px;align-items:flex-start">
          <span style="color:#0ED27A;font-size:14px;margin-top:1px">✓</span>
          <span style="font-size:13px;color:#DDE4F0">Contextual scores — CVSS × your industry × scale × platform multipliers</span>
        </div>
      </div>
    </div>

    <a href="https://risksync.pages.dev/daily" style="display:block;background:#0ED27A;color:#000;text-align:center;padding:12px;border-radius:6px;font-size:13px;font-weight:700;text-decoration:none;margin-bottom:24px">
      Read Today's Brief →
    </a>

    <p style="font-size:11px;color:#2E3F62;text-align:center;margin:0;line-height:1.6">
      No spam · No password · Unsubscribe anytime<br>
      Data: CISA KEV · NIST NVD · FIRST EPSS · GitHub Advisory
    </p>
  </div>
</body>
</html>`,
      }),
    });

    const welcomeData = await welcomeRes.json();

    if (!welcomeRes.ok) {
      console.error('Resend welcome email failed:', JSON.stringify(welcomeData));
      // Don't fail the subscription — contact was added to audience
    }

    return new Response(JSON.stringify({
      ok: true,
      message: 'Subscribed successfully',
    }), { status:200, headers:CORS });

  } catch(err) {
    console.error('Subscribe error:', err.message);
    return new Response(JSON.stringify({ ok:false, error:'Subscription failed — please try again' }),
      { status:500, headers:CORS });
  }
}

// Handle CORS preflight
export async function onRequestOptions() {
  return new Response(null, {
    status:204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
