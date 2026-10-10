// Data collection + normalization from NVD and CISA KEV.
// NOTE: network calls here need outbound internet access and have not been run against the live services in the build environment.
import { db, init, setSource } from './db.js';
import { fileURLToPath } from 'url';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const cap = s => (s ? s[0] + s.slice(1).toLowerCase() : null);

export function upsertKev(json) {
  const find = db.prepare('SELECT 1 FROM vulns WHERE id=?');
  const mark = db.prepare('UPDATE vulns SET kev=1, mitigation=CASE WHEN mitigation=\'\' THEN ? ELSE mitigation END WHERE id=?');
  const ins = db.prepare("INSERT INTO vulns(id,title,description,product,severity,cvss,kev,published,source,fix,mitigation) VALUES(?,?,?,?,'Unrated',NULL,1,?,'CISA KEV','',?)");
  let n = 0;
  db.transaction(() => {
    for (const k of json.vulnerabilities || []) {
      if (find.get(k.cveID)) mark.run(k.requiredAction || '', k.cveID);
      else ins.run(k.cveID, k.vulnerabilityName || k.cveID, k.shortDescription || '', `${k.vendorProject || ''} ${k.product || ''}`.trim(), k.dateAdded, k.requiredAction || '');
      n++;
    }
  })();
  return n;
}

export function upsertNvd(json) {
  const up = db.prepare(`INSERT INTO vulns(id,title,description,product,severity,cvss,kev,published,source,fix,mitigation)
    VALUES(@id,@title,@description,@product,@severity,@cvss,0,@published,'NVD','','')
    ON CONFLICT(id) DO UPDATE SET description=excluded.description,severity=excluded.severity,cvss=excluded.cvss,product=excluded.product,published=excluded.published`);
  let n = 0, skipped = 0;
  db.transaction(() => {
    for (const item of json.vulnerabilities || []) {
      const c = item.cve, m = c.metrics || {};
      const met = (m.cvssMetricV31 || m.cvssMetricV40 || m.cvssMetricV30 || [])[0]?.cvssData;
      if (!met) { skipped++; continue; }
      const desc = (c.descriptions || []).find(d => d.lang === 'en')?.value || '';
      const cpe = c.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria || '';
      const product = cpe ? cpe.split(':').slice(3, 5).join(' ').replace(/_/g, ' ') : 'Not specified';
      up.run({ id: c.id, title: desc.split('. ')[0].slice(0, 120), description: desc, product, severity: cap(met.baseSeverity) || 'Low', cvss: met.baseScore, published: (c.published || '').slice(0, 10) });
      n++;
    }
  })();
  return { n, skipped };
}

// Possible (not confirmed) matches: product keyword appears in the asset's software string.
export function matchAssets() {
  const assets = db.prepare('SELECT id,software,match FROM assets').all();
  const vulns = db.prepare('SELECT id,product FROM vulns').all();
  const ins = db.prepare('INSERT OR IGNORE INTO asset_vulns VALUES(?,?)');
  const setm = db.prepare("UPDATE assets SET match='Possible match – verify' WHERE id=? AND match IN ('Asset not assessed','No match found')");
  let n = 0;
  for (const v of vulns) {
    const words = (v.product || '').toLowerCase().split(/\s+/).filter(w => w.length >= 4 && !['microsoft', 'windows', 'apache', 'linux'].includes(w));
    for (const a of assets) if (words.some(w => (a.software || '').toLowerCase().includes(w))) { n += ins.run(a.id, v.id).changes; setm.run(a.id); }
  }
  return n;
}

async function getJson(url, headers = {}) {
  const r = await fetch(url, { headers: { 'User-Agent': 'VulnCentral/1.0', ...headers } });
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
  return r.json();
}

export async function ingestKev() {
  try { const n = upsertKev(await getJson(KEV_URL)); setSource('CISA KEV', 'Connected', `${n} records processed`); return n; }
  catch (e) { setSource('CISA KEV', 'Failed to update', e.message); throw e; }
}

export async function ingestNvd(days = 7) {
  try {
    const end = new Date(), start = new Date(end - days * 864e5), f = d => d.toISOString().replace('Z', '');
    const url = `${NVD_URL}?pubStartDate=${f(start)}&pubEndDate=${f(end)}&resultsPerPage=200`;
    const r = upsertNvd(await getJson(url, process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}));
    setSource('NVD', 'Connected', `${r.n} stored, ${r.skipped} skipped (no CVSS yet)`); return r;
  } catch (e) { setSource('NVD', 'Failed to update', e.message); throw e; }
}

export async function ingestAll() {
  const out = {};
  for (const [k, fn] of [['kev', ingestKev], ['nvd', ingestNvd]]) {
    try { out[k] = await fn(); } catch (e) { out[k] = { error: e.message }; }
  }
  out.matches = matchAssets();
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) { init(); ingestAll().then(r => { console.log(r); process.exit(0); }); }
