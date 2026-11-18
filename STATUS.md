# STATUS (update at the end of every milestone)  — last updated 2026-11-17

## Live and verified
- KEV 1,781 (feed 2,886 incl. GitHub advisories) as of 2026-11-17; at last full audit (1,728 KEV): real CVSS 100%, EPSS 99.9%, fix versions ~40%. SSVC scoring; vendor checklist; source-tiered Advisory.
- KEV freshness confirmed: Nov 9 (GPUStack) and Nov 10 (Cisco BroadWorks) additions present.
- Fixed today: top-bar counter no longer invented (was 14%/86% split); EPSS shows "<1%" / "Not scored yet".

## Shipped 2026-11-17
- "My Inventory" page: paste/upload a software list -> matching KEV CVEs, tiers via the SSVC engine, version check where fixed versions exist. Matching is client-side; nothing uploaded or stored. Limits: KEV has no affected versions (fixed versions known for ~1 in 3); name matching is fuzzy.
- Daily page: "Limited data mode" banner + n/a when the feed is the unscored fallback; identical-industry panel collapses to an honest note.
- Tests (kept in /mnt/user-data/outputs/tests, not in the repo): matcher 20, inventory flow 12, render 32, engine 39, daily 12.


## Milestone 3 DONE 2026-11-17 (merged: 3be78db, desc fix aa12ce4; verified live)
- Static pages: `cve/<ID>.html` (served at /cve/<ID>), hub `cve/index.html`, `sitemap.xml` (all KEV + /daily + / + /cve/). Built by `node scripts/build-cve-pages.mjs [payload.json|https://syncrisk.co.uk/threats] .`; engine is read from the SSVC block in daily.html (no drift).
- Why static, not a Function: parsing the 1.5-2.4MB KV payload costs ~5ms+ CPU per request vs the 10ms free limit.
- Tests: 1,728 pages, 5,184 tier decisions match the independent Table 9; no undefined/NaN; estimates shown as "Not scored yet"; fix items tagged by trust tier.
- NEXT: submit sitemap in Google Search Console; rebuild from live feed (+53 entries) and decide Action for daily refresh.
- Rebuilt 2026-11-17 from live feed (kv-cache, 1,781 KEV, all with SSVC). Pages are a snapshot: rebuild with the script + a saved /threats JSON (sandbox cannot reach the site). Daily auto-refresh still needs a GitHub Action (workflow permission) or manual run.
- Decision 2026-11-17: keep /app access-code gate during development; move to "option 2" (public sample-data demo, extras behind email sign-up) once built.

## Milestone 5 (branch `board-tracker`, NOT merged until owner says "merge")
- Board Summary reworked: no "top N"; Act items grouped by vendor (200 groups vs 405 by product), every vendor reachable ("Show all"), tie-breakers visible per row (ransomware, EPSS, fix info, newest). Printable report opens in its own tab (old window.print only printed the first screen because of the app's fixed-height layout).
- Fix tracker: statuses Not started / In progress / Fixed / Risk accepted (+reason), stored only in the browser (localStorage), CSV export/import as backup; status column also on My Inventory. No scoring change.
- Tests: render 32, inventory 12, engine 39, board_flow 17 (jsdom, real feed), board_logic 21. Screenshots from the real 1,781-KEV feed.
- Limits: per-browser only (accounts = milestone 7); CSV import trusts the file (rows not a CVE id or known status are skipped and counted).

## Milestone 7 (branch `auto-refresh`, NOT merged until owner says "merge")
- `.github/workflows/refresh-cve-pages.yml`: daily 05:17 UTC + manual button; fetch /threats, build, validate, commit to main only if changed (Cloudflare then deploys). Aborts (nothing published) on: fallback feed, <1,700 KEV, <90% SSVC coverage, >5% drop, failed validation.
- Generator writes only changed pages ("Last updated" date changes only with content); sitemap lastmod no longer changes daily. First run after merge rewrites all pages once (footer wording).
- `scripts/validate-cve-pages.mjs` + `scripts/ssvc_table9.json` (independent CISA table). Tested: idempotent, new-entry, removal, refuse-on-bad-feed (shrink/no-SSVC/fallback).
- OWNER STEPS: add the workflow file via the GitHub web UI if the app cannot push it; Settings > Actions > General > Workflow permissions = Read and write; run once manually. If Cloudflare WAF blocks the runner (curl 403), add a skip rule for User-Agent "SyncRiskPagesBot".

## Parked 2026-11-17 (owner: revisit later)
- Milestone 4 match alerts / subscriber system. Reason: needs subscriber storage, double opt-in + unsubscribe, and a Worker-vs-new-Worker decision (A: add to risksync-enricher, B: separate Worker).
- FINDING: `/subscribe` only sends a Resend welcome email; it stores no subscriber list and has no unsubscribe link. Sign-ups (incl. CVE-page "Notify me") exist only in Resend's sent-mail log. Check there for any real sign-ups.

- Milestone 6 (AI-researched fixes) ON HOLD per owner 2026-11-18. Cost estimate (Sonnet 5.5 $2/$10 per M tokens, web search $10/1,000; assumes 4 searches, 30K in, 2K out per CVE): ~$0.12/CVE Sonnet, ~$0.05 Haiku 5.5; pilot of 20 ~ $1-2.50; all ~1,106 fix-less CVEs ~ $50-130; ~ $1/week ongoing. Needs a separate API account (not covered by Pro) with prepaid credit and spend cap. AI fixes must be labelled lowest tier, cite a URL, and be machine-checked against that page. Free pilot option: run 20 CVEs in-session via web search.

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
