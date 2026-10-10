import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const here = path.dirname(fileURLToPath(import.meta.url));
const file = process.env.DB_PATH || path.join(here, '../data/vulncentral.db');
fs.mkdirSync(path.dirname(file), { recursive: true });
export const db = new Database(file);
db.pragma('journal_mode = WAL');

export function init() {
  db.exec(`
  CREATE TABLE IF NOT EXISTS vulns(id TEXT PRIMARY KEY,title TEXT,description TEXT,product TEXT,severity TEXT,cvss REAL,kev INTEGER DEFAULT 0,published TEXT,source TEXT,fix TEXT DEFAULT '',mitigation TEXT DEFAULT '');
  CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY,name TEXT,type TEXT,software TEXT,env TEXT,updated TEXT,match TEXT,status TEXT,importance INTEGER DEFAULT 1);
  CREATE TABLE IF NOT EXISTS asset_vulns(asset_id TEXT,vuln_id TEXT,PRIMARY KEY(asset_id,vuln_id));
  CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,vuln_id TEXT,asset_id TEXT,priority TEXT,action TEXT,status TEXT,team TEXT,due TEXT,verification TEXT);
  CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,device TEXT,type TEXT,ts TEXT,severity TEXT,description TEXT,status TEXT,steps TEXT);
  CREATE TABLE IF NOT EXISTS sources(name TEXT PRIMARY KEY,status TEXT,last_updated TEXT,message TEXT);`);
  if (db.prepare('SELECT COUNT(*) c FROM vulns').get().c === 0) seed();
}

function seed() {
  const s = JSON.parse(fs.readFileSync(path.join(here, '../data/seed.json'), 'utf8'));
  const tx = db.transaction(() => {
    const iv = db.prepare('INSERT INTO vulns VALUES(?,?,?,?,?,?,?,?,?,?,?)');
    for (const v of s.V) iv.run(v.id, v.t, v.d, v.p, v.sev, v.cv, v.kev, v.dt, v.src, v.fix, v.mit);
    const ia = db.prepare('INSERT INTO assets VALUES(?,?,?,?,?,?,?,?,?)');
    const iav = db.prepare('INSERT OR IGNORE INTO asset_vulns VALUES(?,?)');
    for (const a of s.A) ia.run(a.id, a.n, a.ty, a.sw, a.env, a.up, a.mt, a.rs, a.imp);
    for (const v of s.V) for (const a of v.as) iav.run(a, v.id);
    const byName = Object.fromEntries(s.A.map(a => [a.n, a.id]));
    const it = db.prepare('INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,?)');
    for (const t of s.T) it.run(t.id, t.v, byName[t.a], t.pri, t.act, t.st, t.tm, t.due, t.ver);
    const ie = db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?)');
    for (const e of s.EV) ie.run(e.id, e.dev, e.ty, e.ts, e.sev, e.d, e.st, e.steps);
    const isrc = db.prepare('INSERT INTO sources VALUES(?,?,?,?)');
    for (const n of ['NVD', 'CISA KEV', 'Vendor advisories']) isrc.run(n, 'Not connected', null, 'Never ingested');
  });
  tx();
  console.log('Database seeded with sample records.');
}

export const setSource = (name, status, message = '') =>
  db.prepare('INSERT INTO sources(name,status,last_updated,message) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET status=excluded.status,last_updated=CASE WHEN excluded.status=\'Connected\' THEN excluded.last_updated ELSE sources.last_updated END,message=excluded.message')
    .run(name, status, new Date().toISOString(), message);
