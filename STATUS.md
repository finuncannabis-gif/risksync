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

## Milestone 8 Layer 1 DONE 2026-11-18 (merged 5c9996b)
- Owner decisions 2026-11-18: /daily gate stays unchanged; Layer 2 (Cloudflare Access on /app) on hold.
- CORRECTION: until now `/app` had NO gate. The gate markup/script in app.html sat inside the bulletin-export template string (so "Copy/Download HTML" briefs also carried an access-code overlay). `/daily` has its own separate gate (key rs_daily_demo), which blocks first-time visitors arriving via `/` -> `/daily`; decision on that pending.
- Now: real gate on `/app` (key rs_app_demo, same code). The app is not compiled, started or fed until unlocked. Gate removed from the export template. Client-side only: code visible in page source/public repo, so it deters casual visitors only.
- Tested in headless Chrome (tests/gate_test.py, 11 checks) + existing suites (render 32, inventory 12, board 17, engine 39).
- Layer 2 (optional, owner side): Cloudflare Access (free <=50 users, email one-time PIN) on syncrisk.co.uk/app; risksync.pages.dev/app would remain reachable.

## Milestone 7 DONE 2026-11-18 (merged 688e6fc; first manual run succeeded, bot commit 26e28a8; daily 05:17 UTC)
- `.github/workflows/refresh-cve-pages.yml`: daily 05:17 UTC + manual button; fetch /threats, build, validate, commit to main only if changed (Cloudflare then deploys). Aborts (nothing published) on: fallback feed, <1,700 KEV, <90% SSVC coverage, >5% drop, failed validation.
- Generator writes only changed pages ("Last updated" date changes only with content); sitemap lastmod no longer changes daily. First run after merge rewrites all pages once (footer wording).
- `scripts/validate-cve-pages.mjs` + `scripts/ssvc_table9.json` (independent CISA table). Tested: idempotent, new-entry, removal, refuse-on-bad-feed (shrink/no-SSVC/fallback).
- OWNER STEPS: add the workflow file via the GitHub web UI if the app cannot push it; Settings > Actions > General > Workflow permissions = Read and write; run once manually. If Cloudflare WAF blocks the runner (curl 403), add a skip rule for User-Agent "SyncRiskPagesBot".

## Parked 2026-11-17 (owner: revisit later)
- Milestone 4 match alerts / subscriber system. Reason: needs subscriber storage, double opt-in + unsubscribe, and a Worker-vs-new-Worker decision (A: add to risksync-enricher, B: separate Worker).
- FINDING: `/subscribe` only sends a Resend welcome email; it stores no subscriber list and has no unsubscribe link. Sign-ups (incl. CVE-page "Notify me") exist only in Resend's sent-mail log. Check there for any real sign-ups.

- Milestone 6 (AI-researched fixes) ON HOLD per owner 2026-11-18. Cost estimate (Sonnet 5.5 $2/$10 per M tokens, web search $10/1,000; assumes 4 searches, 30K in, 2K out per CVE): ~$0.12/CVE Sonnet, ~$0.05 Haiku 5.5; pilot of 20 ~ $1-2.50; all ~1,106 fix-less CVEs ~ $50-130; ~ $1/week ongoing. Needs a separate API account (not covered by Pro) with prepaid credit and spend cap. AI fixes must be labelled lowest tier, cite a URL, and be machine-checked against that page. Free pilot option: run 20 CVEs in-session via web search.

## Milestone 9 Scanner Import BUILT 2026-11-18 (branch scanner-import, not merged)
New "Scanner Import" page: paste CVE IDs or upload CSV/TSV/TXT/JSON (<=10 MB), read in-browser only. CSV with a CVE column reads only that column (+ distinct host counts if a Host column exists); otherwise every CVE ID in the text, with a warning. Found items are treated as in-environment (never skippable). Non-KEV IDs counted, not scored. Order: SSVC tier, ransomware, hosts, real EPSS, fix, newest (shown per row). CSV export + shared status tracker. Tests: import_flow 12, scanner logic 26 (real KEV feed), regressions pass. Sandbox cannot load Babel CDN, so no browser screenshot; check on the Pages preview.

## Milestone 10 Feeds + vendor pages BUILT 2026-11-18 (branch vendor-feeds, not merged)
build-cve-pages.mjs now also writes vendor/<slug>.html (295 vendors, all KEV CVEs, tiers, ransomware, due), feed.xml (Atom) and feed.json (JSON Feed 1.1) with the newest 50 additions; sitemap +295 urls; hub and CVE-page breadcrumbs link to vendor pages. Validator checks vendor row counts vs feed, unscored rows say "Not scored yet", feeds parse and match newest 50, sitemap count. Guards: slug collision refuses publish. Workflow commit list extended. Tested on the real 2026-11-17 feed: 7,422 checks, 0 failures, no churn on rerun, tamper tests caught. Generated files are NOT in the branch: after merge, run the Action once (Actions > Refresh CVE pages > Run workflow).

## Milestone 11 Methodology + top-N wording BUILT 2026-11-18 (branch methodology, not merged)
/methodology static page (sources, SSVC tree, order inside a tier, fix trust tiers, missing data, limits; percentages computed from the feed), built by the Action, in sitemap (+1), linked from CVE/vendor/hub footers, site nav and app Data Sources. Removed top-N wording: nav "Why These 25" -> "How We Rank"; "TOP 25 CONTEXTUAL THREATS" and bulletin "Top 25 Threats" -> "Highest-urgency threats"; "Your top threats" -> "Highest urgency for you"; "of your top 10 threats" -> "of your N highest-urgency threats"; /daily and daily-demo card title text only (gate untouched); landing line. Validator +4 checks (7,426 total, 0 failures); render smoke strings updated. Run the Action once after merge.

## Milestone 12 Affected-version ranges BUILT 2026-11-18 (branch version-ranges, not merged)
scripts/build-kev-versions.mjs reads CVE records (cvelistV5, via raw.githubusercontent) for every KEV CVE and writes kev_versions.json (394 KB; real feed 2026-11-17: 747 CVEs with usable versions, 604 with numeric ranges). Conservative: git/patch/prerelease/unspecified/wildcard/open-ended/inverted ranges are dropped or mark the block partial (f:1); the app never says "outside" for a partial block, and never says "safe". Workflow step is continue-on-error and the file is committed with the pages. Inventory page lazily loads /kev_versions.json; new status "outside" (blue); "vulnerable" from a range or exact version; a named fix comparison still wins when both exist; tiers unchanged. Methodology bullet updated. Tests: ranges_test 12 (incl. a property test over 4k real ranges that found inverted Exchange ranges, now dropped), ranges_ui 3, fixtures in tests/kv_fixtures. After merge: run the Action once to create kev_versions.json.

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
