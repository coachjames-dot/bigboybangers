const crypto=require('node:crypto');
const {equal,sameOrigin}=require('../security.cjs');
const path='stats/visitors.json';
const cookie='__Host-bbb_visitor';
const signature=(value,secret)=>crypto.createHmac('sha256',secret).update('visitor:'+value).digest('base64url');
function recognized(token,secret){if(!token||!secret)return false;const parts=token.split('.');return parts.length===2&&/^[a-f0-9]{32}$/.test(parts[0])&&equal(parts[1],signature(parts[0],secret))}
async function read(){
  const {head,get}=await import('@vercel/blob');
  for(let attempt=0;attempt<3;attempt++){
    let before;try{before=await head(path)}catch(e){const missing=await get(path,{access:'public',useCache:false});if(!missing)return {count:0,startedAt:null,revision:null};throw e}
    const r=await get(path,{access:'public',useCache:false});if(!r)continue;
    const value=await new Response(r.stream).json();const after=await head(path);
    if(before.etag===after.etag){if(!Number.isSafeInteger(value.count)||value.count<0)throw Error('Invalid visitor count');return {...value,revision:after.etag}}
  }
  throw Error('Visitor count is busy');
}
module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  const send=(status,data)=>res.status(status).json(data);
  if(req.method!=='POST')return send(405,{error:'Method not allowed'});
  if(!sameOrigin(req))return send(403,{error:'Please use this website'});
  const secret=process.env.ADMIN_PASSWORD||process.env.coachjames3;
  if(!secret||secret.length<20)return send(503,{error:'Visitor count unavailable'});
  const token=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(cookie+'='))?.slice(cookie.length+1);
  try{
    if(recognized(token,secret)){const data=await read();return send(200,{count:data.count,startedAt:data.startedAt})}
    const {put}=await import('@vercel/blob');
    for(let attempt=0;attempt<6;attempt++){
      const current=await read();const next={count:current.count+1,startedAt:current.startedAt||new Date().toISOString()};
      try{
        await put(path,JSON.stringify(next),{access:'public',contentType:'application/json',addRandomSuffix:false,allowOverwrite:current.revision!==null,cacheControlMaxAge:60,...(current.revision!==null?{ifMatch:current.revision}:{})});
        const nonce=crypto.randomBytes(16).toString('hex');res.setHeader('Set-Cookie',`${cookie}=${nonce}.${signature(nonce,secret)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`);
        return send(200,next);
      }catch(e){if(!/Precondition|AlreadyExists|ETag mismatch|already exists/i.test(e.name+' '+e.message))throw e}
    }
    return send(503,{error:'Visitor count is busy. Please try again.'});
  }catch(e){console.error('Visitor count unavailable',e.name,String(e.message).replace(secret,'[redacted]').replace(/https?:\S+/g,'[URL]').replace(/[A-Za-z0-9_-]{40,}/g,'[redacted]'));return send(503,{error:'Visitor count unavailable'})}
};
