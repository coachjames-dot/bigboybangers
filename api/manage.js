const seed=require('../catalog.json');
const {equal,session,valid,sameOrigin,cleanEdit}=require('../security.cjs');
const crypto=require('node:crypto');
const attempts=new Map();
const cookie='__Host-bbb_admin';
const path='catalog/inventory.json';
async function catalog(){const {get}=await import('@vercel/blob');const r=await get(path,{access:'public',useCache:false});if(!r)return {shoes:structuredClone(seed),revision:'seed'};return {shoes:await new Response(r.stream).json(),revision:r.blob.etag}}
module.exports=async function handler(req,res){
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  const send=(status,data)=>res.status(status).json(data);
  const action=req.query.action;const secret=process.env.ADMIN_PASSWORD;
  try{
    if(req.method==='GET'&&action==='catalog'){try{return send(200,await catalog())}catch(e){console.error('Catalog storage unavailable',e.name);return send(503,{error:'Inventory storage is temporarily unavailable'})}}
    const token=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(cookie+'='))?.slice(cookie.length+1);
    if(req.method==='GET'&&action==='session')return send(200,{authenticated:valid(token,secret),configured:!!secret&&secret.length>=20});
    if(req.method!=='POST')return send(405,{error:'Method not allowed'});
    if(!sameOrigin(req))return send(403,{error:'Please use this website to make changes'});
    if(action==='logout'){res.setHeader('Set-Cookie',`${cookie}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);return send(200,{ok:true})}
    if(!secret||secret.length<20)return send(503,{error:'The administrator password needs to be configured'});
    const body=req.body;if(!body||typeof body!=='object')return send(400,{error:'Invalid request'});
    if(action==='login'){
      const ip=req.headers['x-forwarded-for']?.split(',')[0]||'unknown';const now=Date.now();const old=attempts.get(ip);const entry=old&&old.until>now?old:{count:0,until:now+900000};
      if(entry.count>=8)return send(429,{error:'Too many attempts. Try again in 15 minutes.'});entry.count++;attempts.set(ip,entry);if(attempts.size>1000)for(const [k,v]of attempts)if(v.until<now)attempts.delete(k);
      if(typeof body.password!=='string'||body.password.length>256||!equal(body.password,secret)){await new Promise(r=>setTimeout(r,1000));return send(401,{error:'Incorrect password'})}
      attempts.delete(ip);res.setHeader('Set-Cookie',`${cookie}=${session(secret)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`);return send(200,{ok:true});
    }
    if(!valid(token,secret))return send(401,{error:'Please sign in again'});
    const current=await catalog();const existing=current.shoes.find(s=>s.id===Number(body.id));if(!existing)return send(404,{error:'Listing not found'});
    if(action==='upload'){
      if(typeof body.data!=='string'||body.data.length>4200000||!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(body.data))return send(400,{error:'Choose a JPEG photo under 3 MB'});
      const bytes=Buffer.from(body.data.split(',')[1],'base64');if(bytes.length<4||bytes.length>3*1024*1024||bytes[0]!==255||bytes[1]!==216||bytes[2]!==255)return send(400,{error:'Invalid JPEG photo'});
      const {put}=await import('@vercel/blob');const photo=await put(`photos/${existing.id}/${crypto.randomUUID()}.jpg`,bytes,{access:'public',contentType:'image/jpeg',addRandomSuffix:false});return send(200,{url:photo.url});
    }
    if(action==='save'){
      if(body.revision!==current.revision)return send(409,{error:'Inventory changed in another session. Reload this listing before saving.'});
      let updated;try{updated=cleanEdit(body.listing,existing)}catch(e){return send(400,{error:e.message})}
      const {head,put}=await import('@vercel/blob');
      for(const photo of updated.photos){let u;try{u=new URL(photo)}catch{return send(400,{error:'Invalid photo URL'})}if(u.protocol!=='https:'||!u.hostname.endsWith('.public.blob.vercel-storage.com')||!u.pathname.startsWith(`/photos/${existing.id}/`))return send(400,{error:'Invalid photo URL'});const info=await head(photo);if(info.contentType!=='image/jpeg')return send(400,{error:'Invalid photo'})}
      const shoes=current.shoes.map(s=>s.id===existing.id?updated:s);
      const result=await put(path,JSON.stringify(shoes),{access:'public',contentType:'application/json',addRandomSuffix:false,allowOverwrite:current.revision!=='seed',cacheControlMaxAge:60,...(current.revision!=='seed'?{ifMatch:current.revision}:{})});
      return send(200,{shoe:updated,revision:result.etag});
    }
    return send(404,{error:'Unknown action'});
  }catch(e){console.error('Admin operation failed',e.name);return send(/Precondition|AlreadyExists/.test(e.name)?409:500,{error:/Precondition|AlreadyExists/.test(e.name)?'Inventory changed. Reload before saving.':'Could not complete the request. Please try again.'})}
};
