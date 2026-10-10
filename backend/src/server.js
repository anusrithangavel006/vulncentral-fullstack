import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { db, init } from './db.js';
import { ingestAll } from './ingest.js';
import { answer } from './assistant.js';

init();
const here = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json({ limit: '100kb' }));

const mapV = v => ({ id: v.id, t: v.title, d: v.description, p: v.product, sev: v.severity, cv: v.cvss ?? '—', kev: v.kev, dt: v.published, src: v.source, fix: v.fix, mit: v.mitigation,
  as: db.prepare('SELECT asset_id FROM asset_vulns WHERE vuln_id=?').all(v.id).map(r => r.asset_id) });
const vulns = () => db.prepare('SELECT * FROM vulns ORDER BY cvss DESC').all().map(mapV);
const assets = () => db.prepare('SELECT * FROM assets').all().map(a => ({ id: a.id, n: a.name, ty: a.type, sw: a.software, env: a.env, up: a.updated, mt: a.match, rs: a.status, imp: a.importance }));
const tasks = () => db.prepare('SELECT t.*,a.name an FROM tasks t LEFT JOIN assets a ON a.id=t.asset_id').all().map(t => ({ id: t.id, v: t.vuln_id, a: t.an, pri: t.priority, act: t.action, st: t.status, tm: t.team, due: t.due, ver: t.verification }));
const events = () => db.prepare('SELECT * FROM events').all().map(e => ({ id: e.id, dev: e.device, ty: e.type, ts: e.ts, sev: e.severity, d: e.description, st: e.status, steps: e.steps }));
const sources = () => db.prepare('SELECT * FROM sources').all().map(s => [s.name, s.status, s.last_updated ? new Date(s.last_updated).toLocaleString() : (s.message || '—')]);

app.get('/api/health', (_, res) => res.json({ ok: true, time: new Date().toISOString() }));
app.get('/api/bootstrap', (_, res) => res.json({ vulns: vulns(), assets: assets(), tasks: tasks(), events: events(), sources: sources() }));
app.get('/api/vulnerabilities', (req, res) => {
  const { q = '', severity = '', kev = '' } = req.query;
  res.json(vulns().filter(v => (!q || (v.id + v.t + v.p).toLowerCase().includes(String(q).toLowerCase())) && (!severity || v.sev === severity) && (!kev || String(v.kev) === (kev === 'true' ? '1' : '0'))));
});
app.get('/api/vulnerabilities/:id', (req, res) => { const v = db.prepare('SELECT * FROM vulns WHERE id=?').get(req.params.id); v ? res.json(mapV(v)) : res.status(404).json({ error: 'Not found' }); });
app.get('/api/assets', (_, res) => res.json(assets()));
app.get('/api/tasks', (_, res) => res.json(tasks()));
app.patch('/api/tasks/:id', (req, res) => {
  const ok = ['Open', 'In Progress', 'Resolved', 'Needs Verification'];
  if (!ok.includes(req.body?.status)) return res.status(400).json({ error: 'Invalid status' });
  const r = db.prepare('UPDATE tasks SET status=? WHERE id=?').run(req.body.status, req.params.id);
  r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Not found' });
});
app.get('/api/events', (_, res) => res.json(events()));
app.get('/api/sources', (_, res) => res.json(sources()));
app.post('/api/assistant/query', async (req, res) => {
  const q = String(req.body?.question || '').slice(0, 500).trim();
  if (!q) return res.status(400).json({ error: 'Question required' });
  res.json(await answer(q));
});
app.post('/api/admin/ingest', async (req, res) => {
  const t = process.env.ADMIN_TOKEN;
  if (!t) return res.status(503).json({ error: 'Set ADMIN_TOKEN to enable this endpoint' });
  if (req.get('authorization') !== `Bearer ${t}`) return res.status(401).json({ error: 'Unauthorized' });
  res.json(await ingestAll());
});

const pub = path.join(here, '../public');
if (fs.existsSync(pub)) app.use(express.static(pub));
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`VulnCentral API on :${port}`));
if (process.env.AUTO_INGEST === 'true') { ingestAll().catch(console.error); setInterval(() => ingestAll().catch(console.error), 6 * 36e5); }
