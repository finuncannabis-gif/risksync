// Builds kev_versions.json: affected-version ranges for every KEV CVE, read from CVE records (CVEProject/cvelistV5).
// Usage: node scripts/build-kev-versions.mjs <payload.json | url> [outDir=.] [recordsDir]   (recordsDir = local cvelistV5 'cves' folder, for tests)
// Conservative on purpose: only clear numeric ranges and exact numeric versions are kept. Anything the record states in a way
// we cannot compare safely (git hashes, patch builds, prerelease starts, "unspecified", wildcards) marks the block partial (f:1),
// and the app never says "not affected" for a partial block.
import fs from 'fs'; import path from 'path';
const SRC = process.argv[2] || 'https://syncrisk.co.uk/threats', OUT = process.argv[3] || '.', LOCAL = process.argv[4] || '';
const payload = /^https?:/.test(SRC) ? await (await fetch(SRC)).json() : JSON.parse(fs.readFileSync(SRC, 'utf8'));
const ids = [...new Set((payload.vulns || []).filter(v => v.kev && /^CVE-\d{4}-\d{4,}$/.test(v.id)).map(v => v.id))].sort();
export const STRICT = /^v?\d+(?:\.\d+)*(?:[-.]?h\d+)?$/i;
const ok = s => typeof s === 'string' && STRICT.test(s.trim());
const clean = s => s.trim().replace(/^v/i, '');
const nums = s => (String(s).match(/\d+/g) || []).map(Number);
const cmpV = (a, b) => { const x = nums(a), y = nums(b); for (let i = 0; i < Math.max(x.length, y.length); i++) { const p = x[i] || 0, q = y[i] || 0; if (p !== q) return p < q ? -1 : 1; } return 0; };
// a range whose start is not below its end is a data error in the record: drop it and mark the block partial
const addRange = (b, from, to, incl) => { if (cmpV(from, to) > (incl ? 0 : -1)) { b.f = 1; return; } b.r.push([from, to, incl]); };
const pkey = s => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '');

export function extract(rec) {
  const conts = [rec.containers && rec.containers.cna].concat((rec.containers && rec.containers.adp) || []).filter(Boolean);
  const blocks = new Map();
  for (const c of conts) for (const a of (c.affected || [])) {
    const key = pkey(a.product); if (!key) continue;
    const b = blocks.get(key) || {p: a.product, r: [], x: [], f: 0}; blocks.set(key, b);
    for (const v of (a.versions || [])) {
      if (v.status !== 'affected') continue;
      const vt = String(v.versionType || '').toLowerCase();
      if (vt === 'git' || vt === 'commit' || vt === 'patch') { b.f = 1; continue; }
      const from = v.version == null ? '' : String(v.version), lt = v.lessThan, lte = v.lessThanOrEqual;
      if (Array.isArray(v.changes) && v.changes.length) {
        let cur = ok(from) ? clean(from) : null;
        if (cur == null) b.f = 1;
        for (const ch of v.changes) {
          if (ch.status === 'unaffected') { if (cur != null && ok(ch.at)) addRange(b, cur, clean(ch.at), 0); else b.f = 1; cur = null; }
          else if (ch.status === 'affected') { cur = ok(ch.at) ? clean(ch.at) : (b.f = 1, null); }
        }
        if (cur != null) b.f = 1; // open-ended: end unknown
      } else if (lt || lte) {
        const start = (!from || from === '0' || from === 'unspecified') ? '0' : (ok(from) ? clean(from) : null);
        const end = String(lt || lte);
        if (start != null && ok(end)) addRange(b, start, clean(end), lte ? 1 : 0); else b.f = 1;
      } else if (ok(from)) b.x.push(clean(from));
      else b.f = 1;
    }
  }
  const uniq = a => [...new Map(a.map(x => [JSON.stringify(x), x])).values()];
  return [...blocks.values()].map(b => ({p: b.p, r: uniq(b.r), x: [...new Set(b.x)], f: b.f})).filter(b => b.r.length || b.x.length);
}

async function getRec(id) {
  const [, y, n] = id.split('-'); const rel = `${y}/${Math.floor(+n / 1000)}xxx/${id}.json`;
  if (LOCAL) { const f = path.join(LOCAL, rel); return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : null; }
  for (let t = 0; t < 4; t++) {
    try { const r = await fetch(`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${rel}`);
      if (r.status === 404) return null; if (r.ok) return await r.json(); } catch (e) {}
    await new Promise(r => setTimeout(r, 800 * (t + 1)));
  }
  throw new Error('fetch failed ' + id);
}

if (import.meta.url === 'file://' + process.argv[1] || process.argv[1].endsWith('build-kev-versions.mjs')) {
  const out = {}; let fetched = 0, missing = 0, failed = 0, i = 0;
  await Promise.all(Array.from({length: 12}, async () => { while (i < ids.length) { const id = ids[i++];
    try { const rec = await getRec(id); if (!rec) { missing++; continue; } fetched++; const b = extract(rec); if (b.length) out[id] = b; }
    catch (e) { failed++; } } }));
  const problems = [];
  const T = !!process.env.KV_TEST; // tests use small fixtures; real runs always enforce the size guards
  if (!T && ids.length < 1700) problems.push(`only ${ids.length} KEV ids in feed`);
  if (!T && failed > 0.02 * ids.length) problems.push(`${failed} record fetches failed (more than 2%)`);
  if (!T && fetched < 0.9 * ids.length) problems.push(`only ${fetched} of ${ids.length} records readable`);
  const file = path.join(OUT, 'kev_versions.json');
  if (fs.existsSync(file)) { const prev = Object.keys(JSON.parse(fs.readFileSync(file, 'utf8')).v || {}).length; if (Object.keys(out).length < 0.8 * prev) problems.push(`entries fell from ${prev} to ${Object.keys(out).length}`); }
  if (problems.length) { console.error('REFUSING TO PUBLISH kev_versions.json:\n - ' + problems.join('\n - ')); process.exit(1); }
  const sorted = {}; Object.keys(out).sort().forEach(k => sorted[k] = out[k]);
  const body = JSON.stringify({src: 'CVE records (cvelistV5)', v: sorted}) + '\n';
  const same = fs.existsSync(file) && fs.readFileSync(file, 'utf8') === body; if (!same) fs.writeFileSync(file, body);
  const withR = Object.values(sorted).filter(b => b.some(x => x.r.length)).length;
  console.log(`${ids.length} KEV ids: ${fetched} records read, ${missing} not found, ${failed} failed; ${Object.keys(sorted).length} with usable versions (${withR} with numeric ranges); ${same ? 'unchanged' : 'written'}; ${(body.length / 1024).toFixed(0)} KB`);
}
