# STATUS (update at the end of every milestone)  — last updated 2026-11-17

## Live and verified
- KEV 1,781 (feed 2,886 incl. GitHub advisories) as of 2026-11-17; at last full audit (1,728 KEV): real CVSS 100%, EPSS 99.9%, fix versions ~40%. SSVC scoring; vendor checklist; source-tiered Advisory.
- KEV freshness confirmed: Nov 9 (GPUStack) and Nov 10 (Cisco BroadWorks) additions present.
- Fixed today: top-bar counter no longer invented (was 14%/86% split); EPSS shows "<1%" / "Not scored yet".

## Shipped 2026-11-17
- "My Inventory" page: paste/upload a software list -> matching KEV CVEs, tiers via the SSVC engine, version check where fixed versions exist. Matching is client-side; nothing uploaded or stored. Limits: KEV has no affected versions (fixed versions known for ~1 in 3); name matching is fuzzy.
- Daily page: "Limited data mode" banner + n/a when the feed is the unscored fallback; identical-industry panel collapses to an honest note.
- Tests (kept in /mnt/user-data/outputs/tests, not in the repo): matcher 20, inventory flow 12, render 32, engine 39, daily 12.


## Known issues / findings
1. DONE 2026-11-17: daily.html replaced with SSVC brief; canonical/JSON-LD now syncrisk.co.uk. Contact email now hello@syncrisk.co.uk (Cloudflare Email Routing → finun.cannabis@gmail.com).
2. DONE 2026-11-17: www→apex 301 redirect rule deployed (Cloudflare). Confirm by opening https://www.syncrisk.co.uk/app.
3. ~1,106 KEV entries have no parsed fix (generic Advisory only).
4. Repo `functions/enrich.js` differs from the earlier Worker copy — confirm which is live.
5. Real human traffic ≈ 10 visits/30 days (Web Analytics, bots excluded); ~43%+ of requests are scanners (curl/no-UA/Palo Alto). No outside users yet.

## Plan (one milestone per session)
1 Trust cleanup DONE (daily.html, www redirect, counters, EPSS, contact email) · 2 Inventory CSV match (client-side) · 3 Per-CVE public pages (SEO) · 4 Match alerts (email/RSS/Slack) · 5 Board/audit report + fix tracker · 6 LLM "Researched" fixes (pilot ~20 CVEs first) · 7 Accounts + billing (after demand signals).

## Decisions pending (owner)
- Go on daily.html fix · LLM pilot as script vs in-Worker · pricing model (per-CVE credits vs subscription) · email provider choice.
6. /app is behind a client-side access-code gate ("Private demo"). The code is readable in the public repo (base64), so it is not security, and it blocks outside visitors. Decide: remove/loosen (public sample-data demo) vs keep.
7. Cloudflare Pages previews have no KV binding, so preview /daily and /app run on the unscored fallback feed (expected).
