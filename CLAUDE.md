# SyncRisk (RiskSync) — working rules for Claude

Live: https://syncrisk.co.uk/app (dashboard) · /daily (public brief). Stack: vanilla HTML/JS (React via CDN+Babel in app.html), Cloudflare Pages + Functions, Worker `risksync-enricher` (cron 6h), KV `RISKSYNC_KV`. Free tier limits apply.

## Product goal
Explainable, context-aware prioritization of CISA-KEV (known-exploited) vulnerabilities for small/mid security teams, MSPs, vCISOs. Not breach detection. Every number must be traceable to a real source.

## Non-negotiable data rules
- Measure and build against the FULL KEV base (~1,728), never a filtered sample.
- Scoring = CISA SSVC decision tree (Act/Attend/Track). No invented multipliers; context may never suppress a confirmed-exploited item.
- No fabricated UI numbers/claims. Missing data is shown as missing ("Not scored yet"), never as 0 or a guess.
- Fix/remediation trust tiers: vendor advisory > CISA pointer > CERT bulletin > NVD/OSV > news. Always label the tier.
- Verify changes with tests/mocks against real KEV data before shipping.

## How to work with the owner
- Be terse. No preamble or recap. Changed snippets, not whole files, unless a file upload is the deploy path.
- BEFORE each milestone: state the change, files touched, what happens on "go" (deploy path + how to undo), effort, risk. Push only after an explicit go.
- Small pushes (one-line display fixes) may go straight to main; bigger work goes to a branch first.
- Respect Pro-plan limits: one milestone per session; never read all of app.html (~190KB) — grep/read slices; end each milestone with a commit and an update to STATUS.md.
- On "SAVE STATE": reply with a <300-word blueprint (Context / Verified progress / Next step).

## Deploy facts
- Pages deploys on push to `main`. Worker code is pasted in the Cloudflare dashboard (not git-connected) — check before assuming repo `functions/enrich.js` equals the live Worker.
- `_redirects`: `/ /daily 302`. `_routes.json` routes only /threats and /subscribe to Functions.
- Seed file `kev_enrichment.json` must sit at repo root with exactly that name.
