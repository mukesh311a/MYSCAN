// server.js
// Public contact page (dial virtual number), password-gated docs, Owner Panel (links/password + Deactivate),
// Admin dashboard (create, list, print, Deactivate/Reactivate, Regenerate QRs).
// Render-ready: persistent disk for data.db and /qrs, PUBLIC_BASE_URL auto-fills from service hostname.
// Inline CSS and click-through overlays. Works locally and on Render.

import express from 'express'
import session from 'express-session'
import helmet from 'helmet'
import path from 'path'
import dotenv from 'dotenv'
import { fileURLToPath } from 'url'
import rateLimit from 'express-rate-limit'
import QRCode from 'qrcode'
import bcrypt from 'bcryptjs'
import Database from 'better-sqlite3'
import { v4 as uuidv4 } from 'uuid'
import fs from 'fs'

dotenv.config()
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.use(helmet())
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

// Log
app.use((req, _res, next) => { console.log(new Date().toISOString(), req.method, req.originalUrl); next() })

// ---------- Persistence paths (Render + local) ----------
const PERSIST_DIR = process.env.PERSIST_DIR || __dirname

// Static assets from /public (CSS/images if you add any)
const PUBLIC_DIR = path.join(__dirname, 'public')
fs.mkdirSync(PUBLIC_DIR, { recursive: true })
app.use('/public', express.static(PUBLIC_DIR))

// Generated QR images live on the persistent disk
const QRS_DIR = path.join(PERSIST_DIR, 'qrs')
fs.mkdirSync(QRS_DIR, { recursive: true })
// Make them reachable at /public/qrs/...
app.use('/public/qrs', express.static(QRS_DIR))

// SQLite DB on persistent disk
const DB_PATH = path.join(PERSIST_DIR, 'data.db')
const db = new Database(DB_PATH)
db.pragma('journal_mode = WAL')

// ---------- Config ----------
const PORT = parseInt(process.env.PORT || '3000', 10)
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret'
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'
// On Render, set PUBLIC_BASE_URL to: https://$(RENDER_SERVICE_FQDN)
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '')

// Sessions
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}))

// Limits
const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 8 })
const docLimiter  = rateLimit({ windowMs: 10 * 60 * 1000, max: 30 })

// ---------- DB schema & migrations ----------
db.prepare(`
  CREATE TABLE IF NOT EXISTS cars (
    id TEXT PRIMARY KEY,
    owner_name TEXT NOT NULL,
    car_no TEXT NOT NULL,
    owner_phone TEXT NOT NULL,
    virtual_number TEXT NOT NULL,
    dl_url TEXT,
    rc_url TEXT,
    doc_password_hash TEXT,
    created_at TEXT NOT NULL
  )
`).run()
function hasCol(name){ return db.prepare(`PRAGMA table_info(cars)`).all().map(c=>c.name).includes(name) }
if (!hasCol('dl_url2'))     db.prepare(`ALTER TABLE cars ADD COLUMN dl_url2 TEXT`).run()
if (!hasCol('puc_url'))     db.prepare(`ALTER TABLE cars ADD COLUMN puc_url TEXT`).run()
if (!hasCol('owner_secret'))db.prepare(`ALTER TABLE cars ADD COLUMN owner_secret TEXT`).run()
if (!hasCol('is_active'))   db.prepare(`ALTER TABLE cars ADD COLUMN is_active INTEGER DEFAULT 1`).run()
db.prepare(`UPDATE cars SET is_active=1 WHERE is_active IS NULL`).run()

// ---------- Private-IP https→http redirect (fixes mobile forcing https on 192.168.*) ----------
function isPrivateHost(hostname){
  return hostname === 'localhost' || hostname === '127.0.0.1' ||
         /^10\./.test(hostname) || /^192\.168\./.test(hostname) ||
         /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname) || /^169\.254\./.test(hostname)
}
app.enable('trust proxy')
app.use((req, res, next) => {
  const xfProto = (req.headers['x-forwarded-proto'] || '').toString().toLowerCase()
  if ((req.secure || xfProto === 'https') && isPrivateHost(req.hostname)) {
    const host = req.headers.host
    return res.redirect(301, 'http://' + host + req.originalUrl)
  }
  next()
})

// ---------- One-time tokens (docs) ----------
const tokenStore = new Map()
function issueToken(carId, type='menu', ttlMs=5*60*1000){ const t=uuidv4(); tokenStore.set(t,{carId,type,exp:Date.now()+ttlMs}); return t }
function useToken(t, carId, type){ const r=tokenStore.get(t); const ok=!!r && r.carId===carId && r.type===type && r.exp>Date.now(); if(ok) tokenStore.delete(t); return ok }

// ---------- Helpers ----------
function requireAdmin(req, res, next){ if (req.session && req.session.isAdmin) return next(); return res.redirect('/admin/login') }
function extractFirstNumber(input){ const m=String(input||'').match(/(\+?\d{7,15})/); return m? m[1].replace(/(?!^)\+/g,'') : '' }
function telHref(num){ const first = extractFirstNumber(num); return first ? `tel:${first}` : 'tel:' }
function computeSafeBase(base){ try{ const u = new URL(base+(base.endsWith('/')?'':'/')); if (isPrivateHost(u.hostname)) u.protocol='http:'; return u.origin }catch{ return base } }

// ---------- CSS (inline) ----------
const CSS = `
:root{
  --bg:#0a0f1a;--bg2:#0e1426;--card:#0f172a;--text:#ecf2f8;--muted:#a5b3c5;
  --primary:#5eead4;--primary-2:#22d3ee;--accent:#c084fc;--accent-2:#a855f7;--border:#1e293b;
}
*{box-sizing:border-box}
body{
  margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--text);
  background:
    radial-gradient(1200px 600px at 10% -10%, #122143 0%, transparent 60%),
    radial-gradient(1000px 600px at 90% 10%, #1b2b49 0%, transparent 55%),
    linear-gradient(180deg,var(--bg),var(--bg2));
}
.container{max-width:960px;margin:0 auto;padding:24px}
.narrow{max-width:620px}
.card{
  position:relative;background:linear-gradient(180deg,rgba(15,23,42,.92),rgba(15,23,42,.86));
  backdrop-filter:blur(10px);border:1px solid var(--border);border-radius:20px;padding:26px;
  box-shadow:0 20px 48px rgba(0,0,0,.45);margin-bottom:18px
}
.hero{overflow:hidden;padding:30px;position:relative}
.hero > *:not(.halo):not(.quote-bubble){position:relative; z-index:2}
.halo{position:absolute; inset:-30%; z-index:0; pointer-events:none;
  background:
   radial-gradient(closest-side,rgba(94,234,212,.10),transparent 65%),
   radial-gradient(closest-side,rgba(192,132,252,.10),transparent 70%);
  filter:blur(30px); animation:float 8s ease-in-out infinite alternate}
.quote-bubble{position:absolute; left:50%; top:50%; transform:translate(-50%,-50%); z-index:1; pointer-events:none;
  max-width:72%; padding:12px 14px; border:1px solid var(--border);
  background:rgba(30,41,59,.55); backdrop-filter:blur(6px);
  border-radius:12px; font-size:14px; color:#dbeafe; box-shadow:0 10px 28px rgba(2,132,199,.25);
  opacity:.95; transition:transform .8s ease, opacity .8s}
.quote-bubble.fade{opacity:0}
@keyframes float{to{transform:translateY(-10px) scale(1.05)}}

h1{margin:0 0 10px;font-size:32px;letter-spacing:.2px}
h2{margin:0 0 12px}
.subtle{margin:0;color:var(--muted)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:16px 0}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.kv{display:grid;grid-template-columns:180px 1fr;gap:10px;margin-top:8px}
.kv div{padding:12px 0;border-bottom:1px solid var(--border)}
.meta{font-size:14px;color:var(--muted)}
.input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--border);background:#0d1420;color:var(--text)}
.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid var(--border);padding:8px;text-align:left;vertical-align:middle}
.small{font-size:12px;color:#9fb0c3}
.note{color:var(--muted);font-size:14px;margin-top:8px}
.error{color:#ff6b6b;font-size:14px}
.badge{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid var(--border);font-size:12px;color:#9fb0c3}
.qr{width:240px;height:240px;image-rendering:pixelated}
hr.sep{border:0;border-top:1px solid var(--border);margin:18px 0}

/* Buttons */
.btn{
  font:600 15px/1.1 inherit;padding:16px 18px;border-radius:14px;border:0;
  background:linear-gradient(180deg,var(--primary),var(--primary-2));
  color:#041217;cursor:pointer;text-decoration:none;text-align:center;display:inline-block;
  box-shadow:0 12px 30px rgba(34,211,238,.28);transition:transform .05s ease, filter .2s ease
}
.btn:hover{filter:brightness(1.06)}
.btn:active{transform:translateY(1px)}
.btn.secondary{
  background:linear-gradient(180deg,var(--accent),var(--accent-2));
  color:#160728;box-shadow:0 12px 30px rgba(168,85,247,.28)
}
.btn.warn{
  background:linear-gradient(180deg,#fca5a5,#f97316);
  color:#2b1105; box-shadow:0 12px 30px rgba(249,115,22,.28)
}
.btn.mini{padding:8px 10px;font-size:12px;border-radius:10px}
.btn.ghost{background:transparent;border:1px solid var(--border);color:var(--muted)}
.btn.block{display:block;width:100%}
.btn.big{padding:18px 20px;font-size:16px;border-radius:16px}

@media (max-width:700px){.grid2{grid-template-columns:1fr}.kv{grid-template-columns:140px 1fr}}
`

// ---------- Views ----------
function page(layout){
  return `<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>${CSS}</style>
<title>QR System</title></head><body>${layout}</body></html>`
}
function loginView(error=''){
  return page(`
  <main class="container narrow">
    <div class="card">
      <h1>Admin login</h1>
      <form method="post" action="/admin/login">
        <input class="input" type="password" name="password" placeholder="Password" required style="margin:12px 0">
        ${error ? `<p class="error">${error}</p>` : ``}
        <button class="btn big" type="submit">Sign in</button>
      </form>
    </div>
  </main>`)
}
function adminView(rows, base){
  const trs = rows.map(r=>`
    <tr>
      <td>${r.owner_name}</td>
      <td>${r.car_no}</td>
      <td>${new Date(r.created_at).toLocaleString()}</td>
      <td>${r.is_active ? '<span class="badge">Active</span>' : '<span class="badge">Inactive</span>'}</td>
      <td>
        <a href="/admin/success/${r.id}">QR</a> ·
        <a href="/admin/print/${r.id}" target="_blank">Print</a> ·
        <a href="/c/${r.id}" target="_blank">Public</a>
        <form style="display:inline;margin-left:8px" method="post" action="/admin/${r.is_active ? 'deactivate' : 'reactivate'}/${r.id}">
          <button class="btn ${r.is_active ? 'warn' : 'secondary'} mini" type="submit">${r.is_active ? 'Deactivate' : 'Reactivate'}</button>
        </form>
        <form style="display:inline;margin-left:8px" method="post" action="/admin/regenerate/${r.id}">
          <button class="btn ghost mini" type="submit">Regenerate QRs</button>
        </form>
      </td>
    </tr>`).join('')
  return page(`
  <main class="container">
    <div class="card row" style="justify-content:space-between">
      <h1 style="margin:0">QR Admin</h1>
      <form method="post" action="/admin/logout"><button class="btn ghost" type="submit">Log out</button></form>
    </div>
    <div class="card"><a class="btn big" href="/admin/create">+ Generate new QR</a></div>
    <div class="card">
      <h2>Vehicles</h2>
      <table class="table">
        <thead><tr><th>Owner</th><th>Car No</th><th>Created</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>${trs || `<tr><td colspan="5" class="small">No entries yet</td></tr>`}</tbody>
      </table>
      <p class="small">Public base URL: <strong>${base}</strong></p>
    </div>
  </main>`)
}
function createView(base, error=''){
  return page(`
  <main class="container">
    <div class="card">
      <h1>Generate QR</h1>
      <form method="post" action="/admin/create">
        <div class="grid2">
          <div><label>Owner name*</label><input class="input" name="owner_name" required></div>
          <div><label>Car no*</label><input class="input" name="car_no" required placeholder="AB12CD3456"></div>
          <div><label>Owner mobile (record)</label><input class="input" name="owner_phone" type="tel" required placeholder="+91..." pattern="^\\+?\\d{7,15}$"></div>
          <div><label>Proxy/Virtual number*</label><input class="input" name="virtual_number" type="tel" required placeholder="+91..." pattern="^\\+?\\d{7,15}$"></div>
          <div><label>RC link (optional)</label><input class="input" name="rc_url" placeholder="https://..."></div>
          <div><label>DL front link (optional)</label><input class="input" name="dl_url" placeholder="https://..."></div>
          <div><label>DL back link (optional)</label><input class="input" name="dl_url2" placeholder="https://..."></div>
          <div><label>Pollution (PUC) link (optional)</label><input class="input" name="puc_url" placeholder="https://..."></div>
          <div><label>Docs password (optional)</label><input class="input" name="doc_password" type="password" placeholder="Protect docs"></div>
        </div>
        ${error ? `<p class="error">${error}</p>` : ``}
        <div class="row" style="margin-top:8px">
          <button class="btn big" type="submit">Create</button>
          <a class="btn ghost big" href="/admin">Cancel</a>
        </div>
      </form>
      <p class="note">QR encodes: <strong>${base}/c/&lt;id&gt;</strong></p>
    </div>
  </main>`)
}
function successView(car, qrPath, publicUrl, ownerUrl, ownerQr){
  return page(`
  <main class="container">
    <div class="card hero" style="text-align:center">
      <div class="halo"></div>
      <h1>QR ready</h1>
      <img class="qr" src="${qrPath}" alt="QR">
      <p>Public page: <a href="${publicUrl}" target="_blank">${publicUrl}</a></p>
      <div class="row" style="justify-content:center;margin-top:8px">
        <a class="btn big" href="${qrPath}" download="qr-${car.id}.png">Download Public QR</a>
        ${ownerQr ? `<a class="btn secondary big" href="${ownerQr}" download="owner-qr-${car.id}.png">Download Owner Panel QR</a>` : ``}
      </div>
    </div>
    <div class="card">
      <h2>Owner Panel link</h2>
      <p class="small">Share only with the vehicle owner. They can update links, password, and deactivate their QR.</p>
      <a class="btn secondary" href="${ownerUrl}" target="_blank">${ownerUrl}</a>
    </div>
    <div class="card"><a class="btn ghost" href="/admin">Back to Admin</a></div>
  </main>`)
}
function printView(car, qrPath, publicUrl){
  return page(`
  <div class="container">
    <div class="card" style="text-align:center">
      <button class="btn" onclick="window.print()">Print</button>
      <a class="btn ghost" href="/admin">Back</a>
    </div>
  </div>
  <section class="container card">
    <div class="row" style="align-items:center">
      <img class="qr" src="${qrPath}" alt="QR">
      <div>
        <h2>Scan to contact owner</h2>
        <div class="meta">Name: <strong>${car.owner_name}</strong></div>
        <div class="meta">Car No: <strong>${car.car_no}</strong></div>
        <div class="small">${publicUrl}</div>
      </div>
    </div>
  </section>`)
}

// ---------- Public Front ----------
function publicView(car){
  const safeBase = computeSafeBase(PUBLIC_BASE_URL)
  if (!car.is_active) {
    return page(`
    <main class="container narrow">
      <div class="card hero">
        <div class="halo"></div>
        <h1>QR inactive</h1>
        <p class="subtle">This QR has been deactivated by the owner or admin.</p>
      </div>
    </main>`)
  }
  return page(`
  <main class="container narrow">
    <div class="card hero" id="heroCard">
      <div class="halo"></div>
      <h1>Vehicle contact</h1>
      <div class="kv" style="margin-top:6px">
        <div>Owner Name</div><div><strong>${car.owner_name}</strong></div>
        <div>Car No</div><div><strong>${car.car_no}</strong></div>
        <div>Contact</div>
        <div class="row">
          <a class="btn big" href="${telHref(car.virtual_number)}">Contact owner</a>
        </div>
      </div>
      <hr class="sep">
      <div>
        <a class="btn big block" href="${safeBase}/doc/${car.id}">View documents (password)</a>
        <p class="note" style="margin-top:6px">RC, DL (front/back), Pollution certificate</p>
      </div>
      <div class="quote-bubble fade" id="quoteBubble">“Keep going.”</div>
    </div>
    <script>
      (function(){
        const quotes = [
          "Believe you can and you’re halfway there.",
          "Small steps every day.",
          "Stay curious, stay kind.",
          "Do the next right thing.",
          "Progress, not perfection.",
          "Keep going. You’re doing great.",
          "Make it simple, make it better.",
          "Focus on what you can control."
        ]
        const bubble = document.getElementById('quoteBubble')
        const card = document.getElementById('heroCard')
        let i = 0
        function moveBubble(){
          if(!bubble || !card) return
          i = (i + 1) % quotes.length
          bubble.textContent = "“" + quotes[i] + "”"
          const rect = card.getBoundingClientRect()
          const padX = 40, padY = 60
          const x = Math.random()*(rect.width - padX*2) + padX
          const y = Math.random()*(rect.height - padY*2) + padY
          bubble.classList.add('fade')
          setTimeout(()=>{
            bubble.style.transform = 'translate(' + (x - rect.width/2) + 'px,' + (y - rect.height/2) + 'px)'
            bubble.classList.remove('fade')
          }, 380)
        }
        moveBubble()
        setInterval(moveBubble, 3200)
      })()
    </script>
  </main>`)
}

// ---------- Password → Menu ----------
function docPasswordView(car, err=''){
  if (!car.is_active) {
    return page(`
    <main class="container narrow">
      <div class="card hero"><div class="halo"></div>
        <h1>QR inactive</h1>
        <p class="subtle">Documents are unavailable because this QR is deactivated.</p>
      </div>
    </main>`)
  }
  return page(`
  <main class="container narrow">
    <div class="card hero"><div class="halo"></div>
      <h1>Enter password to view documents</h1>
      <p class="subtle">Owner: <strong>${car.owner_name}</strong> · Car: <strong>${car.car_no}</strong></p>
      ${err ? `<p class="error" style="margin-top:8px">${err}</p>` : ``}
      <form id="pwForm" method="post" action="/doc/auth/${car.id}" style="margin-top:12px">
        <input class="input" name="password" type="password" placeholder="Password" required>
        <button class="btn big" type="submit" style="margin-top:10px">Unlock</button>
      </form>
      <script>
        (function(){
          const form = document.getElementById('pwForm')
          form.addEventListener('submit', async (e) => {
            try {
              e.preventDefault()
              const fd = new FormData(form)
              const r = await fetch('/api/doc/auth/${car.id}', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: fd.get('password') })
              })
              if (r.ok) { const data = await r.json(); location.href = data.url }
              else if (r.status === 401) alert('Wrong password. Try again.')
              else alert('Could not unlock. Check your network.')
            } catch { alert('Network error.') }
          })
        })()
      </script>
    </div>
  </main>`)
}
function docsMenuView(car, menuUrlMap){
  const btn = (label, key) => menuUrlMap[key] ? `<a class="btn big block" href="${menuUrlMap[key]}" target="_blank" rel="noopener">${label}</a>` : ''
  return page(`
  <main class="container narrow">
    <div class="card hero"><div class="halo"></div>
      <h1>Vehicle documents</h1>
      <p class="subtle">Owner: <strong>${car.owner_name}</strong> · Car: <strong>${car.car_no}</strong></p>
      <div class="grid2" style="margin-top:8px">
        ${btn('Show RC','rc')}
        ${btn('Show DL (front)','dl1')}
        ${btn('Show DL (back)','dl2')}
        ${btn('Show Pollution','puc')}
      </div>
      <p class="note">Buttons open the stored links.</p>
    </div>
  </main>`)
}

// ---------- Owner Panel ----------
function ownerPanelView(car, msg='', err=''){
  const status = car.is_active ? '<span class="badge">Active</span>' : '<span class="badge">Inactive</span>'
  const deactSection = car.is_active
    ? `<form method="post" action="/owner/${car.id}/deactivate" style="margin-top:10px">
         <input type="hidden" name="owner_secret" value="${car.owner_secret}">
         <button class="btn warn big" type="submit">Deactivate this QR</button>
       </form>`
    : `<p class="note" style="margin-top:10px">This QR is inactive. Admin can reactivate it from dashboard.</p>`
  return page(`
  <main class="container narrow">
    <div class="card hero"><div class="halo"></div>
      <h1>Owner Panel ${status}</h1>
      <p class="subtle">Update password and document links. You can deactivate your QR here.</p>
      ${msg ? `<p class="small" style="color:#5eead4">${msg}</p>` : ``}
      ${err ? `<p class="error">${err}</p>` : ``}
      <form method="post" action="/owner/${car.id}">
        <input type="hidden" name="owner_secret" value="${car.owner_secret}">
        <h2 style="margin-top:8px">Password</h2>
        <input class="input" type="password" name="doc_password" placeholder="Set/Change password (leave blank to keep)" style="margin:8px 0">

        <h2>Documents</h2>
        <input class="input" name="rc_url" placeholder="RC link (https://...)" value="${car.rc_url || ''}" style="margin:8px 0">
        <input class="input" name="dl_url" placeholder="DL front link (https://...)" value="${car.dl_url || ''}" style="margin:8px 0">
        <input class="input" name="dl_url2" placeholder="DL back link (https://...)" value="${car.dl_url2 || ''}" style="margin:8px 0">
        <input class="input" name="puc_url" placeholder="Pollution (PUC) link (https://...)" value="${car.puc_url || ''}" style="margin:8px 0">

        <div class="row" style="margin-top:10px">
          <button class="btn big" type="submit">Save changes</button>
          <a class="btn ghost big" href="/c/${car.id}">Public page</a>
        </div>
      </form>
      <hr class="sep">
      ${deactSection}
    </div>
  </main>`)
}

// ---------- Admin routes ----------
app.get('/', (req, res) => res.redirect('/admin/login'))

app.get('/admin/login', (req, res) => res.type('html').send(loginView()))
app.post('/admin/login', authLimiter, (req, res) => {
  const { password } = req.body || {}
  if ((password || '') === ADMIN_PASSWORD) { req.session.isAdmin = true; return res.redirect('/admin') }
  res.status(401).send(loginView('Wrong password'))
})
app.post('/admin/logout', (req, res) => { req.session.destroy(() => res.redirect('/admin/login')) })

app.get('/admin', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, owner_name, car_no, created_at, is_active FROM cars ORDER BY created_at DESC').all()
  res.type('html').send(adminView(rows, PUBLIC_BASE_URL))
})

app.get('/admin/create', requireAdmin, (req, res) => { res.type('html').send(createView(PUBLIC_BASE_URL)) })

app.post('/admin/create', requireAdmin, async (req, res) => {
  const { owner_name, car_no, owner_phone, virtual_number, dl_url, dl_url2, rc_url, puc_url, doc_password } = req.body || {}

  const owner_phone_clean = extractFirstNumber(owner_phone)
  const virtual_number_clean = extractFirstNumber(virtual_number)
  if (!owner_name || !car_no || !owner_phone_clean || !virtual_number_clean) {
    return res.status(400).type('html').send(createView(PUBLIC_BASE_URL, 'Please fill required fields (valid phone numbers).'))
  }

  const id = uuidv4()
  const created_at = new Date().toISOString()
  const owner_secret = uuidv4()
  const pwd = String(doc_password || '')
  const hash = pwd.trim() ? bcrypt.hashSync(pwd.trim(), 10) : null

  db.prepare(`
    INSERT INTO cars (id, owner_name, car_no, owner_phone, virtual_number, dl_url, dl_url2, rc_url, puc_url, doc_password_hash, owner_secret, is_active, created_at)
    VALUES (@id,@owner_name,@car_no,@owner_phone,@virtual_number,@dl_url,@dl_url2,@rc_url,@puc_url,@doc_password_hash,@owner_secret,1,@created_at)
  `).run({
    id, owner_name, car_no,
    owner_phone: owner_phone_clean,
    virtual_number: virtual_number_clean,
    dl_url: dl_url || null,
    dl_url2: dl_url2 || null,
    rc_url: rc_url || null,
    puc_url: puc_url || null,
    doc_password_hash: hash,
    owner_secret,
    created_at
  })

  // Generate QRs to persistent dir
  const publicTarget = `${PUBLIC_BASE_URL}/c/${id}`
  const qrOut = path.join(QRS_DIR, `${id}.png`)
  await QRCode.toFile(qrOut, publicTarget, { margin: 1 })

  const ownerUrl = `${PUBLIC_BASE_URL}/owner/${id}/${owner_secret}`
  const ownerQrPath = path.join(QRS_DIR, `owner-${id}.png`)
  await QRCode.toFile(ownerQrPath, ownerUrl, { margin: 1 })

  res.redirect(`/admin/success/${id}`)
})

// Admin Deactivate / Reactivate
app.post('/admin/deactivate/:id', requireAdmin, (req, res) => {
  db.prepare('UPDATE cars SET is_active=0 WHERE id=?').run(req.params.id)
  res.redirect('/admin')
})
app.post('/admin/reactivate/:id', requireAdmin, (req, res) => {
  db.prepare('UPDATE cars SET is_active=1 WHERE id=?').run(req.params.id)
  res.redirect('/admin')
})

// Admin Regenerate QRs using current PUBLIC_BASE_URL
app.post('/admin/regenerate/:id', requireAdmin, async (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('Not found')

  const publicTarget = `${PUBLIC_BASE_URL}/c/${car.id}`
  const qrOut = path.join(QRS_DIR, `${car.id}.png`)
  await QRCode.toFile(qrOut, publicTarget, { margin: 1 })

  const ownerUrl = `${PUBLIC_BASE_URL}/owner/${car.id}/${car.owner_secret}`
  const ownerQrPath = path.join(QRS_DIR, `owner-${car.id}.png`)
  await QRCode.toFile(ownerQrPath, ownerUrl, { margin: 1 })

  res.redirect('/admin')
})

app.get('/admin/success/:id', requireAdmin, (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('Not found')
  const qrPath = `/public/qrs/${car.id}.png`
  const publicUrl = `${PUBLIC_BASE_URL}/c/${car.id}`
  const ownerUrl = `${PUBLIC_BASE_URL}/owner/${car.id}/${car.owner_secret}`
  const ownerQr = `/public/qrs/owner-${car.id}.png`
  res.type('html').send(successView(car, qrPath, publicUrl, ownerUrl, ownerQr))
})

app.get('/admin/print/:id', requireAdmin, (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('Not found')
  const qrPath = `/public/qrs/${car.id}.png`
  const publicUrl = `${PUBLIC_BASE_URL}/c/${car.id}`
  res.type('html').send(printView(car, qrPath, publicUrl))
})

// ---------- Public routes ----------
app.get('/c/:id', (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('Not found')
  res.type('html').send(publicView(car))
})

app.get('/doc/:id', (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('Not found')
  res.type('html').send(docPasswordView(car))
})

app.post('/doc/auth/:id', docLimiter, (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('Not found')
  if (!car.is_active) return res.status(403).type('html').send(docPasswordView(car, 'QR is inactive.'))
  const pw = String((req.body && req.body.password) || '')
  if (!car.doc_password_hash) return res.status(403).type('html').send(docPasswordView(car, 'No password set by owner yet.'))
  const ok = bcrypt.compareSync(pw, car.doc_password_hash)
  if (!ok) return res.status(401).type('html').send(docPasswordView(car, 'Wrong password.'))
  const t = issueToken(car.id, 'menu', 5 * 60 * 1000)
  res.redirect(`/doc/menu/${car.id}?token=${encodeURIComponent(t)}`)
})
app.post('/api/doc/auth/:id', docLimiter, (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).json({ error: 'not_found' })
  if (!car.is_active) return res.status(403).json({ error: 'inactive' })
  const pw = String((req.body && req.body.password) || '')
  if (!car.doc_password_hash) return res.status(403).json({ error: 'no_password' })
  const ok = bcrypt.compareSync(pw, car.doc_password_hash)
  if (!ok) return res.status(401).json({ error: 'invalid' })
  const t = issueToken(car.id, 'menu', 5 * 60 * 1000)
  res.json({ url: `/doc/menu/${car.id}?token=${encodeURIComponent(t)}` })
})

app.get('/doc/menu/:id', docLimiter, (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('Not found')
  if (!car.is_active) return res.status(403).send('QR inactive.')
  const token = String(req.query.token || '')
  if (!useToken(token, car.id, 'menu')) return res.status(403).send('Link expired. Re-enter password.')
  const make = (type) => { const t = issueToken(car.id, type, 60 * 1000); return `/api/doc/open/${car.id}?type=${type}&token=${encodeURIComponent(t)}` }
  const map = {
    rc:  car.rc_url  ? make('rc')  : null,
    dl1: car.dl_url  ? make('dl1') : null,
    dl2: car.dl_url2 ? make('dl2') : null,
    puc: car.puc_url ? make('puc') : null
  }
  res.type('html').send(docsMenuView(car, map))
})

app.get('/api/doc/open/:id', (req, res) => {
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('not_found')
  if (!car.is_active) return res.status(403).send('QR inactive.')
  const type = String(req.query.type || '')
  const token = String(req.query.token || '')
  if (!['rc','dl1','dl2','puc'].includes(type)) return res.status(400).send('bad_type')
  if (!useToken(token, car.id, type)) return res.status(403).send('Link expired or invalid')
  const url = (type === 'rc') ? car.rc_url : (type === 'dl1') ? car.dl_url : (type === 'dl2') ? car.dl_url2 : car.puc_url
  if (!url) return res.status(404).send('No document set')
  res.redirect(String(url))
})

// ---------- Owner Panel ----------
function requireOwner(req, res, next){
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(req.params.id)
  if (!car) return res.status(404).send('not_found')
  if (String(req.params.secret || '') !== String(car.owner_secret || '')) return res.status(403).send('forbidden')
  req.car = car; next()
}
app.get('/owner/:id/:secret', requireOwner, (req, res) => { res.type('html').send(ownerPanelView(req.car)) })

app.post('/owner/:id', (req, res) => {
  const carId = req.params.id
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(carId)
  if (!car) return res.status(404).send('not_found')
  if (String(req.body.owner_secret || '') !== String(car.owner_secret || '')) return res.status(403).send('forbidden')

  const { doc_password, rc_url, dl_url, dl_url2, puc_url } = req.body || {}
  const fields = {
    rc_url: (rc_url && rc_url.trim()) ? rc_url.trim() : null,
    dl_url: (dl_url && dl_url.trim()) ? dl_url.trim() : null,
    dl_url2: (dl_url2 && dl_url2.trim()) ? dl_url2.trim() : null,
    puc_url: (puc_url && puc_url.trim()) ? puc_url.trim() : null
  }
  let set = 'rc_url=@rc_url, dl_url=@dl_url, dl_url2=@dl_url2, puc_url=@puc_url'

  const pwd = (doc_password ?? '')
  if (String(pwd).trim() !== '') {
    fields.doc_password_hash = bcrypt.hashSync(String(pwd).trim(), 10)
    set += ', doc_password_hash=@doc_password_hash'
  }

  db.prepare(`UPDATE cars SET ${set} WHERE id=@id`).run({ id: carId, ...fields })
  const updated = db.prepare('SELECT * FROM cars WHERE id = ?').get(carId)
  res.type('html').send(ownerPanelView(updated, 'Saved successfully.'))
})

app.post('/owner/:id/deactivate', (req, res) => {
  const carId = req.params.id
  const car = db.prepare('SELECT * FROM cars WHERE id = ?').get(carId)
  if (!car) return res.status(404).send('not_found')
  if (String(req.body.owner_secret || '') !== String(car.owner_secret || '')) return res.status(403).send('forbidden')

  db.prepare('UPDATE cars SET is_active=0 WHERE id=?').run(carId)
  const updated = db.prepare('SELECT * FROM cars WHERE id = ?').get(carId)
  res.type('html').send(ownerPanelView(updated, '', 'QR deactivated. Admin can reactivate it.'))
})

// Health
app.get('/health', (_req, res) => res.json({ ok: true }))

// Start
app.listen(PORT, () => {
  console.log(`Running on ${PUBLIC_BASE_URL} (local http://localhost:${PORT})`)
  console.log(`Admin login: ${PUBLIC_BASE_URL}/admin/login`)
})
