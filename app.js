const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const db = new Database("rubynova.sqlite");
const PORT = process.env.PORT || 3000;

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@rubynova.local";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12 ||
    !SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error(
    "Jalankan dengan ADMIN_PASSWORD (min. 12 karakter) dan SESSION_SECRET (min. 32 karakter)."
  );
}

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 coins INTEGER NOT NULL DEFAULT 0 CHECK(coins >= 0),
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS deposits (
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id),
 amount INTEGER NOT NULL CHECK(amount BETWEEN 20000 AND 20000000),
 coins INTEGER NOT NULL,
 reference TEXT UNIQUE NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending'
 CHECK(status IN ('pending','approved','rejected')),
 reviewed_by INTEGER,
 note TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ledger (
 id INTEGER PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id),
 delta INTEGER NOT NULL,
 type TEXT NOT NULL,
 reference TEXT UNIQUE NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY,
 name TEXT NOT NULL,
 description TEXT DEFAULT '',
 price INTEGER NOT NULL CHECK(price >= 0),
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id),
 product_id INTEGER NOT NULL REFERENCES products(id),
 price INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vip (
 id INTEGER PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id),
 tier TEXT NOT NULL,
 expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY,
 actor INTEGER,
 action TEXT NOT NULL,
 reference TEXT,
 details TEXT DEFAULT '{}',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const tiers = [
 ["VIP Bronze", 10000],
 ["VIP+ Silver", 30000],
 ["VVIP Gold", 75000],
 ["Royal Member Platinum", 150000],
 ["Black Card / Onyx Diamond", 300000],
 ["RUBYNOVA Ultimate Apex", 500000]
];

function audit(actor, action, reference = "", details = {}) {
 db.prepare("INSERT INTO audit(actor,action,reference,details) VALUES(?,?,?,?)")
   .run(actor || null, action, reference, JSON.stringify(details));
}

const admin = db.prepare("SELECT id FROM users WHERE email=?").get(ADMIN_EMAIL);
if (!admin) {
 db.prepare("INSERT INTO users(email,password_hash,role) VALUES(?,?, 'admin')")
   .run(ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(ADMIN_PASSWORD, 12));
}

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({limit:"20kb"}));
app.use(express.urlencoded({extended:false,limit:"20kb"}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: { error: "Terlalu banyak percobaaan. Coba lagi nanti." }
});

app.use(rateLimit({windowMs:15*60*1000,limit:100}));

app.use(session({
 name:"rubynova.sid",
 secret:SESSION_SECRET,
 resave:false,
 saveUninitialized:false,
 cookie:{
  httpOnly:true,
  sameSite:"strict",
  secure:process.env.NODE_ENV==="production",
  maxAge:7200000
 }
}));

function auth(req,res,next) {
 if (!req.session.user) return res.status(401).json({error:"Silakan login."});
 next();
}
function adminOnly(req,res,next) {
 if (!req.session.user || req.session.user.role!=="admin")
  return res.status(403).json({error:"Akses admin ditolak."});
 next();
}

function csrf(req,res,next) {
 if (["GET","HEAD","OPTIONS"].includes(req.method)) return next();
 const token = req.get("x-csrf-token");
 const expected = req.session ? req.session.csrf : null;
 
 if (!token || !expected) {
  return res.status(403).json({error:"Token CSRF tidak valid."});
 }
 
 const tokenBuf = Buffer.from(token);
 const expectedBuf = Buffer.from(expected);
 
 if (tokenBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
  return res.status(403).json({error:"Token CSRF tidak valid."});
 }
 next();
}
app.use("/api",csrf);

app.get("/api/csrf",(req,res)=>{
 if (!req.session.csrf) {
   req.session.csrf = crypto.randomBytes(32).toString("hex");
 }
 res.json({token:req.session.csrf});
});

app.post("/api/register", authLimiter, async(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase();
 const password=String(req.body.password||"");
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    password.length<10 || password.length>128)
  return res.status(400).json({error:"Email atau kata sandi tidak valid."});
 try{
  const info=db.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)")
    .run(email,await bcrypt.hash(password,12));
  audit(info.lastInsertRowid,"register");
  res.status(201).json({message:"Akun berhasil dibuat."});
 }catch{
  res.status(400).json({error:"Email sudah terdaftar atau data tidak valid."});
 }
});

app.post("/api/login", authLimiter, async(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase();
 const password=String(req.body.password||"");
 const user=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if(!user || !(await bcrypt.compare(password,user.password_hash)))
  return res.status(401).json({error:"Email atau kata sandi salah."});
 req.session.regenerate(err=>{
  if(err)return res.status(500).json({error:"Sesi gagal dibuat."});
  req.session.user={id:user.id,email:user.email,role:user.role};
  req.session.csrf=crypto.randomBytes(32).toString("hex");
  audit(user.id,"login");
  res.json({user:req.session.user,csrfToken:req.session.csrf});
 });
});

app.post("/api/logout",auth,(req,res)=>{
 const id=req.session.user.id;
 audit(id,"logout");
 req.session.destroy(()=>res.json({message:"Logout berhasil."}));
});

app.get("/api/me",auth,(req,res)=>{
 const user=db.prepare("SELECT id,email,role,coins FROM users WHERE id=?")
  .get(req.session.user.id);
 const membership=db.prepare(
  "SELECT tier,expires_at FROM vip WHERE user_id=? AND expires_at>CURRENT_TIMESTAMP ORDER BY expires_at DESC LIMIT 1"
 ).get(user.id);
 res.json({user,membership:membership||null});
});

app.get("/api/products",(req,res)=>{
 res.json(db.prepare("SELECT id,name,description,price FROM products WHERE active=1").all());
});

app.get("/api/vip/tiers",(req,res)=>{
 res.json(tiers.map(([name,coins],index)=>({index,name,coins,depositEquivalent:coins*40})));
});

app.post("/api/deposits",auth,(req,res)=>{
 const amount=Number(req.body.amount);
 if(!Number.isSafeInteger(amount) || amount<20000 || amount>20000000 || amount % 20000 !== 0)
  return res.status(400).json({error:"Nominal deposit harus kelipatan Rp20.000 (antara Rp20.000–Rp20.000.000)."});
 const id=crypto.randomUUID();
 const reference="RN-"+crypto.randomBytes(8).toString("hex").toUpperCase();
 const coins=Math.floor((amount/20000)*500);
 db.prepare("INSERT INTO deposits(id,user_id,amount,coins,reference) VALUES(?,?,?,?,?)")
  .run(id,req.session.user.id,amount,coins,reference);
 audit(req.session.user.id,"deposit.created",id,{amount,coins});
 res.status(201).json({
  id,reference,amount,coins,status:"pending",
  message:"Belum dikreditkan. Tunggu admin memverifikasi pembayaran QRIS."
 });
});

app.get("/api/deposits",auth,(req,res)=>{
 res.json(db.prepare(
  "SELECT id,amount,coins,reference,status,created_at FROM deposits WHERE user_id=? ORDER BY created_at DESC"
 ).all(req.session.user.id));
});

app.get("/api/wallet/ledger",auth,(req,res)=>{
 res.json(db.prepare(
  "SELECT delta,type,reference,created_at FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100"
 ).all(req.session.user.id));
});

app.post("/api/admin/deposits/:id/approve",auth,adminOnly,(req,res)=>{
 const note=String(req.body.note||"").trim();
 if(note.length<5)return res.status(400).json({error:"Catatan verifikasi wajib diisi."});
 try{
  db.transaction(()=>{
   const d=db.prepare("SELECT * FROM deposits WHERE id=?").get(req.params.id);
   if(!d||d.status!=="pending")throw Error("Deposit tidak ditemukan atau sudah diproses.");
   
   const updated = db.prepare("UPDATE deposits SET status='approved',reviewed_by=?,note=? WHERE id=? AND status='pending'")
    .run(req.session.user.id,note,d.id);
   if (updated.changes === 0) throw Error("Gagal menyetujui, deposit sudah diproses.");

   db.prepare("UPDATE users SET coins=coins+? WHERE id=?").run(d.coins,d.user_id);
   db.prepare("INSERT INTO ledger(user_id,delta,type,reference) VALUES(?,?,?,?)")
    .run(d.user_id,d.coins,"deposit",d.id);
   audit(req.session.user.id,"deposit.approved",d.id,{coins:d.coins,note});
  }).immediate();
  res.json({message:"Deposit disetujui."});
 }catch(e){res.status(400).json({error:e.message});}
});

app.post("/api/admin/deposits/:id/reject",auth,adminOnly,(req,res)=>{
 const note=String(req.body.note||"").trim();
 if(note.length<5)return res.status(400).json({error:"Alasan penolakan wajib diisi."});
 const r=db.prepare(
  "UPDATE deposits SET status='rejected',reviewed_by=?,note=? WHERE id=? AND status='pending'"
 ).run(req.session.user.id,note,req.params.id);
 if(!r.changes)return res.status(400).json({error:"Deposit sudah diproses atau tidak ditemukan."});
 audit(req.session.user.id,"deposit.rejected",req.params.id,{note});
 res.json({message:"Deposit ditolak."});
});

app.post("/api/orders",auth,(req,res)=>{
 const productId=Number(req.body.productId);
 const id=crypto.randomUUID();
 try{
  const order=db.transaction(()=>{
   const p=db.prepare("SELECT * FROM products WHERE id=? AND active=1").get(productId);
   if(!p)throw Error("Produk tidak tersedia.");
   
   const resUpdate = db.prepare("UPDATE users SET coins=coins-? WHERE id=? AND coins>=?")
    .run(p.price, req.session.user.id, p.price);
   if (resUpdate.changes === 0) throw Error("Saldo tidak cukup.");

   db.prepare("INSERT INTO orders(id,user_id,product_id,price) VALUES(?,?,?,?)")
    .run(id,req.session.user.id,p.id,p.price);
   if(p.price>0)db.prepare(
    "INSERT INTO ledger(user_id,delta,type,reference) VALUES(?,?,?,?)"
   ).run(req.session.user.id,-p.price,"purchase",id);
   audit(req.session.user.id,"order.created",id,{productId});
   return {id,product:p.name,price:p.price};
  }).immediate();
  res.status(201).json(order);
 }catch(e){res.status(400).json({error:e.message});}
});

app.post("/api/vip/upgrade",auth,(req,res)=>{
 const index=Number(req.body.tierIndex);
 if(!Number.isInteger(index)||index<0||index>=tiers.length)
  return res.status(400).json({error:"VIP tidak valid."});
 const [name,cost]=tiers[index];
 const ref=crypto.randomUUID();
 try{
  db.transaction(()=>{
   const resUpdate = db.prepare("UPDATE users SET coins=coins-? WHERE id=? AND coins>=?")
    .run(cost, req.session.user.id, cost);
   if (resUpdate.changes === 0) throw Error("Saldo tidak cukup.");

   db.prepare("INSERT INTO ledger(user_id,delta,type,reference) VALUES(?,?,?,?)")
    .run(req.session.user.id,-cost,"vip_upgrade",ref);
   const expiry=new Date(Date.now()+30*86400000).toISOString();
   db.prepare("INSERT INTO vip(user_id,tier,expires_at) VALUES(?,?,?)")
    .run(req.session.user.id,name,expiry);
   audit(req.session.user.id,"vip.upgrade",ref,{name,cost});
  }).immediate();
  res.json({message:"VIP aktif 30 hari.",tier:name});
 }catch(e){res.status(400).json({error:e.message});}
});

app.get("/api/admin/summary",auth,adminOnly,(req,res)=>{
 res.json({
  users:db.prepare("SELECT COUNT(*) n FROM users").get().n,
  pending:db.prepare("SELECT COUNT(*) n FROM deposits WHERE status='pending'").get().n,
  orders:db.prepare("SELECT COUNT(*) n FROM orders").get().n
 });
});
app.get("/api/admin/deposits",auth,adminOnly,(req,res)=>{
 res.json(db.prepare(
  "SELECT d.*,u.email FROM deposits d JOIN users u ON u.id=d.user_id ORDER BY d.created_at DESC"
 ).all());
});
app.get("/api/admin/audit",auth,adminOnly,(req,res)=>{
 res.json(db.prepare("SELECT * FROM audit ORDER BY id DESC LIMIT 200").all());
});

app.get("/api/review-missions",(req,res)=>{
 res.json({status:"coming_soon",active:false,
  message:"Misi Review belum diluncurkan. Pengajuan dan komisi dinonaktifkan."});
});

app.get("*",(req,res)=>{
 res.type("html").send(`<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RubyNova — Digital Marketplace</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#100c10;color:#f9f0f2;font:16px system-ui,-apple-system,sans-serif}
header{padding:22px;background:#1c1118;border-bottom:1px solid #522131}
h1{color:#ff5477;margin:0;font-size:24px}main{max-width:950px;margin:auto;padding:20px}
nav{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
button{background:#a91f49;color:white;border:0;padding:11px 15px;border-radius:9px;cursor:pointer;font-weight:600}
button:hover{background:#c8295b}
input{padding:12px;border-radius:8px;border:1px solid #66404d;background:#20161d;color:white;width:100%;margin:6px 0}
.card{background:#20161d;border:1px solid #492736;border-radius:14px;padding:16px;margin:12px 0}
small,.muted{color:#c7aab5}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#150d13;padding:12px;border-radius:8px;border:1px solid #361a25}
</style></head><body><header><h1>◆ RubyNova</h1>
<p style="margin:4px 0 0 0;color:#c7aab5">Digital Marketplace · VIP Membership</p></header><main>
<nav>
<button onclick="show('home')">Beranda</button>
<button onclick="show('login')">Login</button>
<button onclick="show('register')">Daftar</button>
<button onclick="show('wallet')">Saldo & Deposit</button>
<button onclick="show('vip')">VIP</button>
<button onclick="show('review')">Misi Review</button>
<button onclick="show('admin')">Admin</button>
</nav><section id="content" class="card">Memuat RubyNova…</section>
<p class="muted">Demo awal. Jangan gunakan untuk transaksi uang nyata sebelum keamanan dan pembayaran diverifikasi.</p>
<script>
let csrf="";
async function api(url,method="GET",body){
 const opt={method,headers:{}};
 if(body!==undefined){opt.headers["Content-Type"]="application/json";opt.headers["x-csrf-token"]=csrf;opt.body=JSON.stringify(body);}
 const r=await fetch("/api"+url,opt);const data=await r.json();
 if(data.csrfToken)csrf=data.csrfToken;
 if(!r.ok)throw Error(data.error||"Permintaan gagal");
 return data;
}
async function call(url,method,body){
 try{const d=await api(url,method,body);document.getElementById("result").textContent=JSON.stringify(d,null,2);}
 catch(e){document.getElementById("result").textContent=e.message;}
}
function form(title,fields,button,action){
 return '<h2>'+title+'</h2>'+fields.map(f=>'<input id="'+f[0]+'" placeholder="'+f[1]+'" '+(f[2]||"")+'/>').join("")+
 '<button onclick="'+action+'">'+button+'</button><pre id="result"></pre>';
}
async function show(page){
 const c=document.getElementById("content");
 if(page==="home")c.innerHTML='<h2>Selamat datang di RubyNova</h2><p>Toko produk digital, saldo koin, dan keanggotaan VIP.</p><p>Deposit: Rp20.000–Rp20.000.000 · Rp20.000 = 500 koin.</p>';
 if(page==="register")c.innerHTML=form("Buat akun",[["email","Email","type=email"],["password","Kata sandi","type=password"]],"Daftar",'call("/register","POST",{email:email.value,password:password.value})');
 if(page==="login")c.innerHTML=form("Login",[["email","Email","type=email"],["password","Kata sandi","type=password"]],"Login",'call("/login","POST",{email:email.value,password:password.value})');
 if(page==="wallet")c.innerHTML=form("Ajukan deposit",[["amount","Nominal rupiah","type=number"]],"Ajukan",'call("/deposits","POST",{amount:Number(amount.value)})')+'<p>Saldo baru diberikan setelah verifikasi admin.</p>';
 if(page==="vip"){
  try{const d=await api("/vip/tiers");c.innerHTML="<h2>Enam Tingkat VIP</h2>"+d.map(t=>'<div class=card><b>'+t.name+'</b><p>'+t.coins.toLocaleString()+' koin</p><button onclick="call(\\'/vip/upgrade\\',\\'POST\\',{tierIndex:'+t.index+'})">Upgrade</button></div>').join("")+'<pre id="result"></pre>';}
  catch(e){c.textContent=e.message}
 }
 if(page==="review")c.innerHTML='<h2>Misi Review</h2><p>Coming Soon — fitur belum aktif.</p><p>Pengajuan misi dan komisi dinonaktifkan.</p>';
 if(page==="admin")c.innerHTML='<h2>Dashboard Admin</h2><button onclick="call(\\'/admin/summary\\')">Ringkasan</button><button onclick="call(\\'/admin/deposits\\')">Daftar deposit</button><button onclick="call(\\'/admin/audit\\')">Audit</button><pre id="result"></pre>';
}
(async()=>{try{const d=await fetch("/api/csrf").then(r=>r.json());csrf=d.token;}catch{}show("home")})();
</script></main></body></html>`);
});

app.listen(PORT,()=>console.log(`RubyNova berjalan di http://localhost:${PORT}`));
