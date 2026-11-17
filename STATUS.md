# STATUS (update at the end of every milestone)  — last updated 2026-11-17

## Live and verified
- KEV base 1,728; real CVSS 100% of KEV, EPSS 99.9%; fix versions ~40%. SSVC scoring; vendor checklist; source-tiered Advisory.
- KEV freshness confirmed: Nov 9 (GPUStack) and Nov 10 (Cisco BroadWorks) additions present.
- Fixed today: top-bar counter no longer invented (was 14%/86% split); EPSS shows "<1%" / "Not scored yet".

## Known issues / findings
1. `daily.html` (served at /daily, and / redirects there) has NO SSVC engine; `daily-demo.html` does. Live /daily is likely an old version. Fix = replace daily.html with daily-demo.html's content (needs owner go).
2. www.syncrisk.co.uk takes ~26% of requests: add a www→apex 301 (Cloudflare rule).
3. ~1,106 KEV entries have no parsed fix (generic Advisory only).
4. Repo `functions/enrich.js` differs from the earlier Worker copy — confirm which is live.
5. Real human traffic ≈ 10 visits/30 days (Web Analytics, bots excluded); ~43%+ of requests are scanners (curl/no-UA/Palo Alto). No outside users yet.

## Plan (one milestone per session)
1 Trust cleanup (daily.html, www redirect, label audit) · 2 Inventory CSV match (client-side) · 3 Per-CVE public pages (SEO) · 4 Match alerts (email/RSS/Slack) · 5 Board/audit report + fix tracker · 6 LLM "Researched" fixes (pilot ~20 CVEs first) · 7 Accounts + billing (after demand signals).

## Decisions pending (owner)
- Go on daily.html fix · LLM pilot as script vs in-Worker · pricing model (per-CVE credits vs subscription) · email provider choice.
