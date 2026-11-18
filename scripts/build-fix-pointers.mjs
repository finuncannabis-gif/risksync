// Builds kev_fixes.json: labelled advisory pointers for KEV CVEs, from free, checkable sources only.
// Usage: node scripts/build-fix-pointers.mjs <payload.json | url> [outDir=.] [recordsDir] [kevJson | url]
// Tiers (CLAUDE.md order: vendor advisory > CISA pointer > CERT bulletin > NVD/OSV > news). Vendor-advisory links are already
// in the feed (advisoryUrls), so this file carries only the two tiers the feed lacks:
//   "c" = CISA pointer: a URL in CISA's own KEV "notes" field (CISA points at it; it is not necessarily the vendor's page).
//   "b" = CERT bulletin: a CVE-record reference on a CERT/CSIRT host (CERT/CC, CISA ICS advisories, JVN, NCSC, CERT-EU...).
// Nothing here states a fixed version. Generic pages (NVD, the KEV catalog itself) and news/blog links are dropped.
import fs from 'fs'; import path from 'path';
const SRC = process.argv[2] || 'https://syncrisk.co.uk/threats', OUT = process.argv[3] || '.', LOCAL = process.argv[4] || '';
const KEV_SRC = process.argv[5] || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const load = async s => /^https?:/.test(s) ? await (await fetch(s, {headers: {'User-Agent': 'SyncRiskPagesBot/1.0 (+https://syncrisk.co.uk)'}})).json() : JSON.parse(fs.readFileSync(s, 'utf8'));

const CERT_HOSTS = /(^|\.)(kb\.cert\.org|us-cert\.gov|us-cert\.cisa\.gov|cert\.europa\.eu|jvn\.jp|jvndb\.jvn\.jp|ncsc\.gov\.uk|cert\.ssi\.gouv\.fr|cert-bund\.de|bsi\.bund\.de|cyber\.gc\.ca|auscert\.org\.au|cyber\.gov\.au|ncsc\.nl|certcc\.org)$/i;
const DROP_HOST = /(^|\.)(nvd\.nist\.gov|cve\.org|cve\.mitre\.org|first\.org|github\.com\/advisories)$/i;
export function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ''; } }
export function cleanUrl(u) { return String(u || '').trim().replace(/[)\].,;>"']+$/, ''); }
export const isCertUrl = u => { const h = hostOf(u); return CERT_HOSTS.test(h) || (h === 'www.cisa.gov' && /\/(news-events\/(ics-advisories|ics-medical-advisories|cybersecurity-advisories)|uscert|ncas)\//.test(u)); };
export const isGeneric = u => { const h = hostOf(u); return !h || DROP_HOST.test(h) || (h.endsWith('cisa.gov') && /known-exploited|\/kev|binding-operational|bod-/.test(u)); };

// URLs CISA put in the KEV "notes" field -> CISA pointer (or CERT bulletin if the host is a CERT)
export function fromNotes(notes) {
  const out = [];
  for (const m of String(notes || '').matchAll(/https?:\/\/[^\s;,<>"]+/g)) {
    const u = cleanUrl(m[0]); if (isGeneric(u) || !/^https:\/\//.test(u)) continue;
    out.push({t: isCertUrl(u) ? 'b' : 'c', u});
  }
  return out;
}
// CERT-host references in the CVE record
export function fromRecord(rec) {
  const out = [], cna = (rec && rec.containers && rec.containers.cna) || {};
  const refs = [].concat(cna.references || [], ...((rec && rec.containers && rec.containers.adp) || []).map(a => a.references || []));
  for (const r of refs) { const u = cleanUrl(r.url); if (/^https:\/\//.test(u) && !isGeneric(u) && isCertUrl(u)) out.push({t: 'b', u}); }
  return out;
}
export function merge(list, existing) {
  const seen = new Set((existing || []).map(x => x)), out = [];
  for (const x of list) { if (seen.has(x.u)) continue; seen.add(x.u); out.push(x); }
  out.sort((a, b) => (a.t === b.t ? 0 : a.t === 'c' ? -1 : 1)); // CISA pointer outranks CERT bulletin
  return out.slice(0, 3).map(x => [x.t, x.u]);
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

if (import.meta.url === 'file://' + process.argv[1] || process.argv[1].endsWith('build-fix-pointers.mjs')) {
  const payload = await load(SRC), kev = await load(KEV_SRC);
  const kevs = (payload.vulns || []).filter(v => v.kev && /^CVE-\d{4}-\d{4,}$/.test(v.id));
  const ids = [...new Set(kevs.map(v => v.id))].sort();
  const have = new Map(kevs.map(v => [v.id, v.advisoryUrls || []]));
  const notes = new Map((kev.vulnerabilities || []).map(v => [v.cveID, v.notes || '']));
  const out = {}; let fetched = 0, missing = 0, failed = 0, i = 0;
  await Promise.all(Array.from({length: 12}, async () => { while (i < ids.length) { const id = ids[i++];
    try { const rec = await getRec(id); if (rec) fetched++; else missing++;
      const l = merge([...fromNotes(notes.get(id)), ...fromRecord(rec)], have.get(id)); if (l.length) out[id] = l; }
    catch (e) { failed++; } } }));
  const problems = [], T = !!process.env.KV_TEST;
  if (!T && ids.length < 1700) problems.push(`only ${ids.length} KEV ids in feed`);
  if (!T && notes.size < 1700) problems.push(`CISA KEV feed has only ${notes.size} entries`);
  if (!T && failed > 0.02 * ids.length) problems.push(`${failed} record fetches failed (more than 2%)`);
  const file = path.join(OUT, 'kev_fixes.json');
  if (fs.existsSync(file)) { const prev = Object.keys(JSON.parse(fs.readFileSync(file, 'utf8')).f || {}).length; if (Object.keys(out).length < 0.8 * prev) problems.push(`entries fell from ${prev} to ${Object.keys(out).length}`); }
  if (problems.length) { console.error('REFUSING TO PUBLISH kev_fixes.json:\n - ' + problems.join('\n - ')); process.exit(1); }
  const sorted = {}; Object.keys(out).sort().forEach(k => sorted[k] = out[k]);
  const body = JSON.stringify({src: 'CISA KEV notes; CERT hosts in CVE records', f: sorted}) + '\n';
  const same = fs.existsSync(file) && fs.readFileSync(file, 'utf8') === body; if (!same) fs.writeFileSync(file, body);
  // coverage report over the gap: KEV entries with no fix info in the feed
  const gap = kevs.filter(v => !(v.fixedVersions && v.fixedVersions.length) && !v.solution && !(v.advisoryUrls && v.advisoryUrls.length));
  const gapHit = gap.filter(v => sorted[v.id]).length, c = Object.values(sorted).filter(l => l.some(x => x[0] === 'c')).length, b = Object.values(sorted).filter(l => l.some(x => x[0] === 'b')).length;
  console.log(`${ids.length} KEV ids: ${fetched} records read, ${missing} not found, ${failed} failed; pointers for ${Object.keys(sorted).length} (CISA pointer ${c}, CERT bulletin ${b}); gap entries now covered ${gapHit}/${gap.length}; ${same ? 'unchanged' : 'written'}; ${(body.length / 1024).toFixed(0)} KB`);
}
