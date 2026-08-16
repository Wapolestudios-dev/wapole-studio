const express=require('express'),path=require('path'),fs=require('fs'),crypto=require('crypto');
const bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),rateLimit=require('express-rate-limit'),multer=require('multer'),Database=require('better-sqlite3');
const app=express(),PORT=process.env.PORT||3000,ROOT=path.join(__dirname,'..'),STORAGE=path.join(ROOT,'storage');
const SECRET=process.env.JWT_SECRET||'CHANGE_THIS_SECRET_IN_PRODUCTION',ADMIN_USER=process.env.ADMIN_USER||'admin',ADMIN_PASS=process.env.ADMIN_PASS||'wapole2026';
fs.mkdirSync(STORAGE,{recursive:true});const db=new Database(path.join(__dirname,'wapole.db'));db.pragma('journal_mode=WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY AUTOINCREMENT,full_name TEXT NOT NULL,phone TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,location TEXT,created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,order_code TEXT UNIQUE NOT NULL,customer_name TEXT NOT NULL,phone TEXT NOT NULL,service TEXT NOT NULL,price INTEGER NOT NULL,details TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING',access_code TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL,original_name TEXT NOT NULL,stored_name TEXT UNIQUE NOT NULL,mime_type TEXT NOT NULL,size INTEGER NOT NULL,kind TEXT NOT NULL,uploaded_at TEXT NOT NULL,FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL,reference TEXT NOT NULL,amount INTEGER NOT NULL,method TEXT NOT NULL,proof_file_id INTEGER,status TEXT NOT NULL DEFAULT 'PENDING',note TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,created_at TEXT NOT NULL,read_at TEXT,FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS order_events(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL,status TEXT NOT NULL,note TEXT,created_at TEXT NOT NULL,FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE);
`);
try{db.exec('ALTER TABLE orders ADD COLUMN customer_id INTEGER');}catch(e){if(!String(e.message).includes('duplicate column'))throw e}
if(!db.prepare('SELECT id FROM admins WHERE username=?').get(ADMIN_USER))db.prepare('INSERT INTO admins(username,password_hash,created_at) VALUES(?,?,?)').run(ADMIN_USER,bcrypt.hashSync(ADMIN_PASS,12),new Date().toISOString());
const prices={'Logo Designing':50000,'Poster Designing':30000,'Music Cover Artwork':20000,'Album Cover Artwork':50000,'Lyrics Video':30000,'Ticket / Promo Kit':15000,'Music Distribution':50000,'Starter Package':100000,'Artist Package':150000,'Premium Package':300000};
const STAT=['PENDING','PAYMENT VERIFICATION','PAYMENT VERIFIED','PROCESSING','REVISION REQUESTED','COMPLETED','DELIVERED','CLOSED'];
app.use(express.json({limit:'1mb'}));app.use(express.urlencoded({extended:true}));
const limiter=rateLimit({windowMs:15*60*1000,max:40,standardHeaders:true,legacyHeaders:false});
const apiLimiter=rateLimit({windowMs:15*60*1000,max:180,standardHeaders:true,legacyHeaders:false});
app.disable('x-powered-by');
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','camera=(),microphone=(),geolocation=()');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control','no-store');
  next();
});
app.use('/api/', apiLimiter);
function cleanText(v,max=2000){return String(v??'').trim().slice(0,max)}
function safeId(v){return /^\\d+$/.test(String(v))}
function auth(req,res,next){let h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'Authentication required'});try{req.admin=jwt.verify(h.slice(7),SECRET);next()}catch(e){res.status(401).json({error:'Invalid or expired token'})}}
function order(code){return db.prepare('SELECT * FROM orders WHERE order_code=?').get(code)}
function customer(req,res,next){let o=order(String(req.headers['x-order-code']||'')),a=String(req.headers['x-access-code']||'');if(!o||!a)return res.status(401).json({error:'Invalid Order ID or Access Code'});
let aa=Buffer.from(a), bb=Buffer.from(String(o.access_code));
if(aa.length!==bb.length || !crypto.timingSafeEqual(aa,bb)) return res.status(401).json({error:'Invalid Order ID or Access Code'});req.order=o;next()}
function notify(id,title,message){db.prepare('INSERT INTO notifications(order_id,title,message,created_at) VALUES(?,?,?,?)').run(id,title,message,new Date().toISOString())}
function event(id,status,note=''){db.prepare('INSERT INTO order_events(order_id,status,note,created_at) VALUES(?,?,?,?)').run(id,status,note,new Date().toISOString())}


app.post('/api/customer/register',limiter,(req,res)=>{
  let {full_name,phone,email,password,location}=req.body||{};
  full_name=cleanText(full_name,120); phone=cleanText(phone,40); email=cleanText(email,160).toLowerCase(); location=cleanText(location,120);
  if(!full_name||!phone||!email||!password||String(password).length<8)return res.status(400).json({error:'Full name, phone, email and a password of at least 8 characters are required'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:'Invalid email address'});
  if(db.prepare('SELECT id FROM customers WHERE email=?').get(email))return res.status(409).json({error:'Email is already registered'});
  let r=db.prepare('INSERT INTO customers(full_name,phone,email,password_hash,location,created_at) VALUES(?,?,?,?,?,?)').run(full_name,phone,email,bcrypt.hashSync(password,12),location,new Date().toISOString());
  let token=jwt.sign({type:'customer',id:r.lastInsertRowid,email},SECRET,{expiresIn:'30d'});
  res.status(201).json({token,customer:{id:r.lastInsertRowid,full_name,phone,email,location}});
});
app.post('/api/customer/login',limiter,(req,res)=>{
  let email=cleanText(req.body?.email,160).toLowerCase(),password=String(req.body?.password||''),c=db.prepare('SELECT * FROM customers WHERE email=?').get(email);
  if(!c||!bcrypt.compareSync(password,c.password_hash))return res.status(401).json({error:'Invalid email or password'});
  let token=jwt.sign({type:'customer',id:c.id,email:c.email},SECRET,{expiresIn:'30d'});
  res.json({token,customer:{id:c.id,full_name:c.full_name,phone:c.phone,email:c.email,location:c.location}});
});
function customerAuth(req,res,next){
  let h=req.headers.authorization||''; if(!h.startsWith('Bearer '))return res.status(401).json({error:'Customer login required'});
  try{let x=jwt.verify(h.slice(7),SECRET);if(x.type!=='customer')throw Error();req.customer=db.prepare('SELECT * FROM customers WHERE id=?').get(x.id);if(!req.customer)throw Error();next()}catch(e){return res.status(401).json({error:'Invalid or expired customer session'})}
}
app.get('/api/customer/me',customerAuth,(req,res)=>{
  let c=req.customer, orders=db.prepare('SELECT id,order_code,service,price,status,created_at,updated_at FROM orders WHERE customer_id=? ORDER BY id DESC').all(c.id);
  res.json({customer:{id:c.id,full_name:c.full_name,phone:c.phone,email:c.email,location:c.location},orders});
});
app.post('/api/customer/orders',customerAuth,(req,res)=>{
  let {services,package:pkg,details,lyrics}=req.body||{};
  if(!Array.isArray(services)) services=services?[services]:[];
  services=services.map(x=>cleanText(x,100)).filter(Boolean);
  pkg=cleanText(pkg||'',100);
  details=cleanText(details,5000);
  lyrics=cleanText(lyrics,20000);
  if(!details)return res.status(400).json({error:'Project requirements are required'});
  if(!services.length && !pkg)return res.status(400).json({error:'Choose at least one service or package'});
  if(services.some(x=>prices[x]===undefined))return res.status(400).json({error:'Invalid service selected'});
  if(pkg && prices[pkg]===undefined)return res.status(400).json({error:'Invalid package selected'});
  if(pkg && services.length)return res.status(400).json({error:'Choose a package OR individual services, not both'});
  if(services.includes('Lyrics Video') && !lyrics)return res.status(400).json({error:'Please provide the lyrics for the Lyrics Video service'});
  let selected=services.length?services:[pkg], total=selected.reduce((sum,x)=>sum+prices[x],0);
  let now=new Date().toISOString(),n=db.prepare('SELECT COALESCE(MAX(id),0)+1 n FROM orders').get().n;
  let code=`WPS-${String(n).padStart(6,'0')}`,access=crypto.randomBytes(6).toString('hex').toUpperCase();
  let finalDetails=details;
  if(lyrics) finalDetails += `\n\n--- LYRICS ---\n${lyrics}`;
  let r=db.prepare('INSERT INTO orders(order_code,customer_name,phone,service,price,details,status,access_code,created_at,updated_at,customer_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .run(code,req.customer.full_name,req.customer.phone,JSON.stringify(selected),total,finalDetails,'PENDING',access,now,now,req.customer.id);
  event(r.lastInsertRowid,'PENDING','Order created from customer account');
  notify(r.lastInsertRowid,'Order created',`Your order ${code} has been received.`);
  res.status(201).json({order_code:code,access_code:access,status:'PENDING',price:total,services:selected});
});
app.get('/api/customer/account',customerAuth,(req,res)=>{
  const c=req.customer;
  const orders=db.prepare('SELECT id,order_code,service,price,status,details,created_at,updated_at FROM orders WHERE customer_id=? ORDER BY id DESC').all(c.id);
  const ids=orders.map(o=>o.id);
  let notifications=[];
  let files=[];
  if(ids.length){
    const q=ids.map(()=>'?').join(',');
    notifications=db.prepare(`SELECT id,order_id,title,message,created_at,read_at FROM notifications WHERE order_id IN (${q}) ORDER BY id DESC`).all(...ids);
    files=db.prepare(`SELECT id,order_id,original_name,mime_type,size,kind,uploaded_at FROM files WHERE order_id IN (${q}) ORDER BY id DESC`).all(...ids);
  }
  res.json({customer:{id:c.id,full_name:c.full_name,phone:c.phone,email:c.email,location:c.location},orders,notifications,files});
});
app.post('/api/admin/login',limiter,(req,res)=>{let {username,password}=req.body||{},a=db.prepare('SELECT * FROM admins WHERE username=?').get(username||'');if(!a||!bcrypt.compareSync(password||'',a.password_hash))return res.status(401).json({error:'Invalid username or password'});res.json({token:jwt.sign({id:a.id,username:a.username},SECRET,{expiresIn:'8h'}),username:a.username})});
app.post('/api/orders',(req,res)=>{
 let {name,phone,services,package:pkg,details,lyrics}=req.body||{};
 if(!name||!phone||!details)return res.status(400).json({error:'Name, phone and description are required'});
 if(!Array.isArray(services)) services=services?[services]:[];
 services=services.map(cleanText).filter(Boolean);
 pkg=cleanText(pkg||'',100);
 if(!services.length && !pkg)return res.status(400).json({error:'Choose at least one service or package'});
 if(services.some(x=>prices[x]===undefined))return res.status(400).json({error:'Invalid service selected'});
 if(pkg && prices[pkg]===undefined)return res.status(400).json({error:'Invalid package selected'});
 if(pkg && services.length)return res.status(400).json({error:'Choose a package OR individual services, not both'});
 if(services.includes('Lyrics Video') && !cleanText(lyrics,20000))return res.status(400).json({error:'Please provide the lyrics for the Lyrics Video service'});
 let selected=services.length?services:[pkg], total=selected.reduce((sum,x)=>sum+prices[x],0);
 let now=new Date().toISOString(),n=db.prepare('SELECT COALESCE(MAX(id),0)+1 n FROM orders').get().n;
 let code=`WPS-${String(n).padStart(6,'0')}`,access=crypto.randomBytes(6).toString('hex').toUpperCase();
 let finalDetails=cleanText(details,5000);
 if(cleanText(lyrics,20000)) finalDetails += `\n\n--- LYRICS ---\n${cleanText(lyrics,20000)}`;
 let serviceLabel=JSON.stringify(selected);
 let r=db.prepare('INSERT INTO orders(order_code,customer_name,phone,service,price,details,status,access_code,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
   .run(code,cleanText(name,120),cleanText(phone,80),serviceLabel,total,finalDetails,'PENDING',access,now,now);
 event(r.lastInsertRowid,'PENDING','Order created');
 res.status(201).json({order_code:code,access_code:access,status:'PENDING',price:total,services:selected});
});

app.get('/api/customer/dashboard',customer,(req,res)=>{let o=req.order,files=db.prepare('SELECT id,original_name,mime_type,size,kind,uploaded_at FROM files WHERE order_id=? ORDER BY id DESC').all(o.id),payments=db.prepare('SELECT id,reference,amount,method,status,note,created_at,updated_at FROM payments WHERE order_id=? ORDER BY id DESC').all(o.id),events=db.prepare('SELECT status,note,created_at FROM order_events WHERE order_id=? ORDER BY id ASC').all(o.id),notes=db.prepare('SELECT id,title,message,created_at,read_at FROM notifications WHERE order_id=? ORDER BY id DESC').all(o.id);res.json({order:{order_code:o.order_code,customer_name:o.customer_name,phone:o.phone,service:o.service,price:o.price,details:o.details,status:o.status,created_at:o.created_at,updated_at:o.updated_at},files,payments,events,notifications:notes})});
app.patch('/api/customer/notifications/:id/read',customer,(req,res)=>{db.prepare('UPDATE notifications SET read_at=? WHERE id=? AND order_id=?').run(new Date().toISOString(),req.params.id,req.order.id);res.json({success:true})});
const upload=multer({storage:multer.diskStorage({destination:(req,f,cb)=>{let d=path.join(STORAGE,req.order.order_code);fs.mkdirSync(d,{recursive:true});cb(null,d)},filename:(req,f,cb)=>cb(null,Date.now()+'-'+crypto.randomBytes(4).toString('hex')+'-'+path.basename(f.originalname).replace(/[^a-zA-Z0-9._-]/g,'_'))}),limits:{fileSize:100*1024*1024,files:5}});
app.post('/api/customer/files',customer,(req,res)=>upload.array('files',5)(req,res,e=>{if(e)return res.status(400).json({error:e.message});let now=new Date().toISOString(),ins=db.prepare('INSERT INTO files(order_id,original_name,stored_name,mime_type,size,kind,uploaded_at) VALUES(?,?,?,?,?,?,?)');let out=(req.files||[]).map(f=>{let r=ins.run(req.order.id,f.originalname,f.filename,f.mimetype,f.size,'CUSTOMER_REFERENCE',now);return{id:r.lastInsertRowid,name:f.originalname}});res.json({files:out})}));
app.get('/api/customer/files/:id/download',customer,(req,res)=>{let f=db.prepare('SELECT * FROM files WHERE id=? AND order_id=?').get(req.params.id,req.order.id);if(!f)return res.status(404).json({error:'File not found'});let base=path.resolve(STORAGE,req.order.order_code),p=path.resolve(base,f.stored_name);
if(!p.startsWith(base+path.sep)||!fs.existsSync(p))return res.status(404).json({error:'File missing'});
res.download(p,f.original_name)});

app.get('/api/customer/account/files/:id/download',customerAuth,(req,res)=>{
  let f=db.prepare('SELECT f.*,o.order_code FROM files f JOIN orders o ON o.id=f.order_id WHERE f.id=? AND o.customer_id=?').get(req.params.id,req.customer.id);
  if(!f)return res.status(404).json({error:'File not found'});
  let base=path.resolve(STORAGE,f.order_code),p=path.resolve(base,f.stored_name);
  if(!p.startsWith(base+path.sep)||!fs.existsSync(p))return res.status(404).json({error:'File missing'});
  res.download(p,f.original_name);
});
app.get('/api/admin/summary',auth,(req,res)=>{let total=db.prepare('SELECT COUNT(*) n FROM orders').get().n,revenue=db.prepare("SELECT COALESCE(SUM(amount),0) n FROM payments WHERE status='VERIFIED'").get().n,pending=db.prepare("SELECT COUNT(*) n FROM orders WHERE status='PENDING'").get().n,verify=db.prepare("SELECT COUNT(*) n FROM orders WHERE status='PAYMENT VERIFICATION'").get().n,processing=db.prepare("SELECT COUNT(*) n FROM orders WHERE status='PROCESSING'").get().n,completed=db.prepare("SELECT COUNT(*) n FROM orders WHERE status IN ('COMPLETED','DELIVERED','CLOSED')").get().n;res.json({total,revenue,pending,verify,processing,completed})});
app.get('/api/admin/orders',auth,(req,res)=>res.json(db.prepare('SELECT id,order_code,customer_name,phone,service,price,details,status,created_at,updated_at FROM orders ORDER BY id DESC').all()));
app.get('/api/admin/orders/:id',auth,(req,res)=>{let o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);if(!o)return res.status(404).json({error:'Order not found'});res.json({order:{...o,access_code:undefined},payments:db.prepare('SELECT * FROM payments WHERE order_id=? ORDER BY id DESC').all(o.id),files:db.prepare('SELECT id,original_name,mime_type,size,kind,uploaded_at FROM files WHERE order_id=? ORDER BY id DESC').all(o.id),events:db.prepare('SELECT * FROM order_events WHERE order_id=? ORDER BY id ASC').all(o.id)})});
app.patch('/api/admin/orders/:id/status',auth,(req,res)=>{let {status,note}=req.body||{};if(!STAT.includes(status))return res.status(400).json({error:'Invalid status'});let o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);if(!o)return res.status(404).json({error:'Order not found'});let now=new Date().toISOString();db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run(status,now,o.id);event(o.id,status,note||'Status updated by Admin');notify(o.id,'Order status updated',`Your order is now ${status}. ${note||''}`);res.json({success:true})});
// Admin delivery upload: send completed work into the customer's website dashboard.
const adminDeliveryUpload=multer({storage:multer.diskStorage({destination:(req,f,cb)=>{let o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);if(!o)return cb(new Error('Order not found'));let d=path.join(STORAGE,o.order_code);fs.mkdirSync(d,{recursive:true});cb(null,d)},filename:(req,f,cb)=>cb(null,'DELIVERY-'+Date.now()+'-'+crypto.randomBytes(5).toString('hex')+'-'+path.basename(f.originalname).replace(/[^a-zA-Z0-9._-]/g,'_'))}),limits:{fileSize:500*1024*1024,files:10}});
app.post('/api/admin/orders/:id/deliver',auth,(req,res)=>adminDeliveryUpload.array('files',10)(req,res,e=>{if(e)return res.status(400).json({error:e.message});let o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);if(!o)return res.status(404).json({error:'Order not found'});if(!req.files?.length)return res.status(400).json({error:'Choose at least one completed file'});let message=cleanText(req.body?.message,1000)||'Your completed work is ready. You can download the files from your order dashboard.';let now=new Date().toISOString(),ins=db.prepare('INSERT INTO files(order_id,original_name,stored_name,mime_type,size,kind,uploaded_at) VALUES(?,?,?,?,?,?,?)'),out=req.files.map(f=>{let r=ins.run(o.id,f.originalname,f.filename,f.mimetype,f.size,'ADMIN_DELIVERY',now);return{id:r.lastInsertRowid,name:f.originalname,size:f.size}});db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run('DELIVERED',now,o.id);event(o.id,'DELIVERED','Completed work uploaded by Admin.');notify(o.id,'Completed work delivered',message+' Download your completed files from the website.');res.json({success:true,status:'DELIVERED',files:out})}));
app.get('/api/admin/payments',auth,(req,res)=>res.json(db.prepare('SELECT p.*,o.order_code,o.customer_name,o.phone,o.price FROM payments p JOIN orders o ON o.id=p.order_id ORDER BY p.id DESC').all()));
app.patch('/api/admin/payments/:id',auth,(req,res)=>{let {status,note}=req.body||{},p=db.prepare('SELECT * FROM payments WHERE id=?').get(req.params.id);if(!p)return res.status(404).json({error:'Payment not found'});if(!['VERIFIED','REJECTED','PENDING'].includes(status))return res.status(400).json({error:'Invalid payment status'});let ns=status==='VERIFIED'?'PAYMENT VERIFIED':status==='REJECTED'?'PENDING':'PAYMENT VERIFICATION',now=new Date().toISOString();db.prepare('UPDATE payments SET status=?,note=?,updated_at=? WHERE id=?').run(status,note||'',now,p.id);db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run(ns,now,p.order_id);event(p.order_id,ns,`Payment ${status.toLowerCase()}`);notify(p.order_id,'Payment '+status.toLowerCase(),note||`Payment has been ${status.toLowerCase()}.`);res.json({success:true})});
app.get('/api/admin/notifications',auth,(req,res)=>res.json(db.prepare('SELECT n.*,o.order_code,o.customer_name FROM notifications n JOIN orders o ON o.id=n.order_id ORDER BY n.id DESC LIMIT 100').all()));

app.use(express.static(path.join(ROOT,'frontend')));app.get('*',(req,res)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'API route not found'});res.sendFile(path.join(ROOT,'frontend','index.html'))});
app.listen(PORT,()=>console.log(`WAPOLE STUDIOS v6: http://localhost:${PORT}`));
