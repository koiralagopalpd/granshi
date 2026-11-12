/** * Granshi CMS Worker v4 — department-centric * Pages/categories/media under departments · articles homepage · reply UX */
const enc = new TextEncoder();
const b64 = (b) =>
  btoa(String.fromCharCode(...new Uint8Array(b)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const unb64 = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0)
  );
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });

async function hmac(secret, value) {
  const k = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return b64(await crypto.subtle.sign("HMAC", k, enc.encode(value)));
}
async function passwordHash( password, salt = b64(crypto.getRandomValues(new Uint8Array(16))) ) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: unb64(salt), iterations: 10000, hash: "SHA-256" },
    key,
    256
  );
  return { salt, hash: b64(bits) };
}
async function verifyPassword(password, salt, hash) {
  const x = await passwordHash(password, salt);
  return x.hash === hash;
}
function cookie(req, name) {
  const c = req.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : "";
}
async function sessionToken(env, email) {
  const payload = b64(
    enc.encode(JSON.stringify({ email, exp: Date.now() + 7 * 86400000 }))
  );
  return payload + "." + (await hmac(env.SESSION_SECRET, payload));
}
async function auth(req, env) {
  try {
    const [p, s] = cookie(req, "granshi_session").split(".");
    if (!p || !s || (await hmac(env.SESSION_SECRET, p)) !== s) return null;
    const v = JSON.parse(new TextDecoder().decode(unb64(p)));
    if (v.exp < Date.now()) return null;
    const a = await env.DB.prepare("SELECT email FROM admins WHERE email=?")
      .bind(v.email)
      .first();
    return a ? a.email : null;
  } catch {
    return null;
  }
}
const sessionCookie = (token) =>
  `granshi_session=${encodeURIComponent( token )}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
const clearCookie =
  "granshi_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
async function body(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}
function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
function slugify(s) {
  return String(s || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

async function getSettings(env) {
  try {
    const r = await env.DB.prepare("SELECT key,value FROM settings").all();
    return Object.fromEntries((r.results || []).map((x) => [x.key, x.value]));
  } catch {
    return {};
  }
}

async function safeAll(env, sql, ...binds) {
  try {
    const stmt = env.DB.prepare(sql);
    const r = binds.length ? await stmt.bind(...binds).all() : await stmt.all();
    return r.results || [];
  } catch {
    return [];
  }
}

function searchablePageText(content) {
  try {
    const blocks = typeof content === "string" ? JSON.parse(content) : content;
    if (!Array.isArray(blocks)) return "";
    return blocks.map((b) => {
      if (!b || typeof b !== "object") return "";
      if (["heading","paragraph","quote"].includes(b.type)) return String(b.text || "") + " " + String(b.cite || "");
      if (b.type === "columns") return (b.columns || []).map(c => c.text || "").join(" ");
      if (b.type === "cards") return (b.cards || []).map(c => [c.title,c.text].join(" ")).join(" ");
      if (b.type === "hero") return [b.title,b.subtitle].join(" ");
      if (b.type === "button") return b.text || "";
      return "";
    }).join(" ").replace(/<[^>]*>/g," ").replace(/\\s+/g," ").trim().slice(0,30000);
  } catch { return ""; }
}
function htmlToSearchText(html) {
  return String(html || "").replace(/<script\b[\s\S]*?<\/script>/gi," ")
    .replace(/<style\b[\s\S]*?<\/style>/gi," ")
    .replace(/<!--([\s\S]*?)-->/g," ")
    .replace(/<\/(p|div|li|h[1-6]|section|article|br|tr)>/gi," ")
    .replace(/<[^>]+>/g," ")
    .replace(/&nbsp;/gi," ").replace(/&amp;/gi,"&")
    .replace(/&lt;/gi,"<").replace(/&gt;/gi,">")
    .replace(/&#39;|&apos;/gi,"'").replace(/&quot;/gi,'"')
    .replace(/\s+/g," ").trim().slice(0,30000);
}
function zipCoverFromHtml(html, slug) {
  const source = String(html || "");
  const og = source.match(/<meta[^>]+(?:property|name)=["'](?:og:image|twitter:image)["'][^>]+content=["']([^"']+)/i)
    || source.match(/<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:og:image|twitter:image)/i);
  const img = source.match(/<img[^>]+src=["']([^"']+)/i);
  const value = (og && og[1]) || (img && img[1]) || "";
  if (!value || value.startsWith("data:")) return "";
  if (/^https?:\/\//i.test(value) || value.startsWith("/")) return value;
  return "/_p/" + encodeURIComponent(slug) + "/" + value.split("/").map(encodeURIComponent).join("/");
}
function pageExcerpt(text, query) {
  const clean = String(text || "").replace(/\s+/g," ").trim();
  if (!clean) return "";
  const terms = query.toLowerCase().split(/\s+/).filter(x=>x.length>1);
  let at = -1;
  for (const term of terms) { at = clean.toLowerCase().indexOf(term); if (at >= 0) break; }
  const start = Math.max(0, (at < 0 ? 0 : at) - 100);
  return (start ? "…" : "") + clean.slice(start,start+360) + (start+360<clean.length ? "…" : "");
}

async function allPublic(env) {
  const settings = await getSettings(env);
  let pages = await safeAll(
    env,
    `SELECT p.slug,p.title_en,p.title_ne,p.description_en,p.description_ne,p.thumbnail_image,p.thumbnail_title_en,p.thumbnail_title_ne,p.thumbnail_summary_en,p.thumbnail_summary_ne,p.thumbnail_alt,p.thumbnail_focal_x,p.thumbnail_focal_y,p.updated_at,p.department_id,p.is_popular,d.name_en AS dept_en,d.name_ne AS dept_ne,d.slug AS dept_slug FROM pages p LEFT JOIN departments d ON d.id=p.department_id WHERE p.published=1 ORDER BY p.updated_at DESC LIMIT 300`
  );
  if (!pages.length) {
    pages = await safeAll(
      env,
      `SELECT slug,title_en,title_ne,description_en,description_ne,updated_at FROM pages WHERE published=1 ORDER BY updated_at DESC LIMIT 100`
    );
  }
  let depts = await safeAll(
    env,
    "SELECT id,name_en,name_ne,description_en,description_ne,url,icon,email,image,slug,sort_order FROM departments WHERE visible=1 ORDER BY sort_order"
  );
  if (!depts.length) {
    depts = await safeAll(
      env,
      "SELECT id,name_en,name_ne,description_en,description_ne,url,icon,email,image,sort_order FROM departments WHERE visible=1 ORDER BY sort_order"
    );
  }
  const menus = await safeAll(
    env,
    "SELECT id,label_en,label_ne,url,parent_id,sort_order FROM menus WHERE visible=1 ORDER BY sort_order"
  );
  const latest = pages.slice(0, 8);
  const popular = pages.filter((p) => p.is_popular == 1).slice(0, 8);
  return { settings, pages, departments: depts, menus, latest, popular };
}

function renderBlocks(content) {
  let blocks = [];
  try {
    blocks = typeof content === "string" ? JSON.parse(content) : content || [];
  } catch {
    blocks = [];
  }
  return blocks
    .map((b) => {
      const t = b.type;
      if (t === "heading") {
        const level = Math.min(Math.max(Number(b.level) || 2, 1), 4);
        return `<h${level} class="blk-h">${escapeHtml( b.text || "" )}</h${level}>`;
      }
      if (t === "paragraph")
        return `<p class="blk-p">${escapeHtml(b.text || "").replace( /\n/g, "<br>" )}</p>`;
      if (t === "image" && b.url)
        return `<figure class="blk-img"><img src="${escapeHtml( b.url )}" alt="${escapeHtml(b.alt || "")}" loading="lazy">${ b.caption ? `<figcaption>${escapeHtml(b.caption)}</figcaption>` : "" }</figure>`;
      if (t === "button" && b.url)
        return `<p class="blk-btn"><a class="btn" href="${escapeHtml( b.url )}">${escapeHtml(b.text || "Learn more")}</a></p>`;
      if (t === "html") return `<div class="blk-html">${b.html || ""}</div>`;
      if (t === "spacer")
        return `<div style="height:${Number(b.height) || 32}px"></div>`;
      if (t === "divider") return `<hr class="blk-hr">`;
      if (t === "quote")
        return `<blockquote class="blk-quote"><p>${escapeHtml( b.text || "" )}</p>${ b.cite ? `<cite>${escapeHtml(b.cite)}</cite>` : "" }</blockquote>`;
      if (t === "columns") {
        const cols = Array.isArray(b.columns) ? b.columns : [];
        return `<div class="blk-cols" style="--cols:${cols.length || 2}">${cols .map( (c) => `<div class="blk-col">${escapeHtml(c.text || "").replace( /\n/g, "<br>" )}</div>` ) .join("")}</div>`;
      }
      if (t === "cards") {
        const cards = Array.isArray(b.cards) ? b.cards : [];
        return `<div class="blk-cards">${cards .map( (c) => `<article class="blk-card">${ c.icon ? `<div class="ico">${escapeHtml(c.icon)}</div>` : "" }<h3>${escapeHtml(c.title || "")}</h3><p>${escapeHtml( c.text || "" )}</p>${ c.url ? `<a href="${escapeHtml(c.url)}">${escapeHtml( c.linktext || "→" )}</a>` : "" }</article>` ) .join("")}</div>`;
      }
      if (t === "hero")
        return `<section class="blk-hero" style="background-image:url('${escapeHtml( b.image || "" )}')"><div class="blk-hero-inner"><h1>${escapeHtml( b.title || "" )}</h1><p>${escapeHtml(b.subtitle || "")}</p>${ b.button_url ? `<a class="btn" href="${escapeHtml(b.button_url)}">${escapeHtml( b.button_text || "Explore" )}</a>` : "" }</div></section>`;
      if (t === "video" && b.url) {
        const src = escapeHtml(b.url);
        if (
          src.includes("youtube") ||
          src.includes("youtu.be") ||
          src.includes("vimeo")
        )
          return `<div class="blk-video"><iframe src="${src}" frameborder="0" allowfullscreen loading="lazy"></iframe></div>`;
        return `<div class="blk-video"><video src="${src}" controls playsinline></video></div>`;
      }
      return "";
    })
    .join("\n");
}

function pageChrome(title, desc, bodyHtml, settings, lang = "en") {
  const brand = settings.brand_name || "Granshi";
  const primary = settings.primary_color || "#101a2c";
  const accent = settings.accent_color || "#e5c77e";
  return `<!doctype html><html lang="${lang}"><head> <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"> <title>${escapeHtml(title)} · ${escapeHtml(brand)}</title> <meta name="description" content="${escapeHtml(desc || "")}"> <meta name="theme-color" content="${escapeHtml(primary)}"> <style> :root{--navy:${escapeHtml(primary)};--gold:${escapeHtml( accent )};--paper:#f6f7fb;--ink:#172033;--muted:#667085} *{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;color:var(--ink);background:var(--paper)} a{text-decoration:none;color:inherit}.wrap{width:min(960px,92%);margin:auto} header{position:sticky;top:0;z-index:5;background:#101a2cf5;color:#fff;border-bottom:1px solid #ffffff20} .nav{height:64px;display:flex;align-items:center;justify-content:space-between} .brand{font-weight:900;letter-spacing:1px}.btn{display:inline-block;padding:12px 18px;border-radius:10px;font-weight:700;background:linear-gradient(135deg,#f3dfa9,var(--gold));color:#182235} .page-hero{background:var(--navy);color:#fff;padding:48px 0 36px}.page-hero h1{margin:0;font-size:clamp(28px,5vw,42px)}.page-hero p{color:#c7d0dc} article{padding:36px 0 60px}.blk-h{margin:28px 0 12px}.blk-p{line-height:1.75;color:#334} .blk-img img{max-width:100%;border-radius:12px}.blk-quote{border-left:4px solid var(--gold);padding:8px 20px;background:#fff;margin:24px 0} .blk-hr{border:0;border-top:1px solid #e2e6ef;margin:28px 0} .blk-cols{display:grid;grid-template-columns:repeat(var(--cols,2),1fr);gap:20px;margin:20px 0} .blk-col{background:#fff;padding:18px;border-radius:12px;border:1px solid #e8ecf3} .blk-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px} .blk-card{background:#fff;border:1px solid #e8ecf3;border-radius:14px;padding:18px} .blk-hero{min-height:280px;background-size:cover;background-position:center;color:#fff;border-radius:16px;position:relative;margin:12px 0 28px} .blk-hero:before{content:"";position:absolute;inset:0;background:linear-gradient(90deg,#101a2ce0,#101a2c66);border-radius:16px} .blk-hero-inner{position:relative;padding:40px} .blk-video{position:relative;padding-bottom:56.25%;height:0;margin:20px 0} .blk-video iframe,.blk-video video{position:absolute;inset:0;width:100%;height:100%} footer{background:var(--navy);color:#aab;padding:24px 0;text-align:center;font-size:14px} @media(max-width:700px){.blk-cols{grid-template-columns:1fr}} </style></head><body> <header><div class="wrap nav"><a class="brand" href="/">GRANSHI</a><a class="btn" href="/">← Home</a></div></header> ${bodyHtml} <footer><div class="wrap">${escapeHtml( settings.footer_text || "© Granshi" )}</div></footer> </body></html>`;
}

async function sendEmail(env, { to, subject, html, replyTo, attachments = [] }) {
  if (!env.RESEND_API_KEY || !to) return { sent: false, error: "Email service is not configured." };
  try {
    const outbound = [];
    let totalAttachmentBytes = 0;
    for (const item of attachments.slice(0, 10)) {
      const key = String(item.key || "");
      if (!key.startsWith("replies/") || !env.MEDIA) continue;
      const object = await env.MEDIA.get(key);
      if (!object) throw new Error("An attachment is missing from storage.");
      const bytes = new Uint8Array(await object.arrayBuffer());
      if (bytes.byteLength > 15 * 1024 * 1024) throw new Error("An attachment exceeds 15 MB.");
      totalAttachmentBytes += bytes.byteLength;
      if (totalAttachmentBytes > 20 * 1024 * 1024) throw new Error("Combined attachments must be 20 MB or less.");
      let binary = "";
      const chunk = 0x8000;
      for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
      }
      outbound.push({
        filename: String(item.name || "attachment").replace(/[^a-zA-Z0-9._-]/g, "_"),
        content: btoa(binary),
      });
    }
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "Granshi <noreply.info@gopalkoirala.com.np>",
        to: [to],
        subject,
        html,
        reply_to: replyTo,
        ...(outbound.length ? { attachments: outbound } : {}),
      }),
    });
    if (!res.ok) return { sent: false, error: (await res.text()).slice(0, 500) };
    return { sent: true };
  } catch (error) {
    return { sent: false, error: String(error).slice(0, 500) };
  }
}

async function verifyResendWebhook(req, raw, secret) {
  if (!secret) return false;
  const id = req.headers.get("svix-id") || "";
  const timestamp = req.headers.get("svix-timestamp") || "";
  const signatures = req.headers.get("svix-signature") || "";
  if (!id || !timestamp || !signatures) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now()/1000-ts)>300) return false;
  const keyText = secret.startsWith("whsec_") ? secret.slice(6) : secret;
  let key;
  try { key = Uint8Array.from(atob(keyText), ch => ch.charCodeAt(0)); } catch { return false; }
  const cryptoKey = await crypto.subtle.importKey("raw", key, {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const signed = new TextEncoder().encode(id+"."+timestamp+"."+raw);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC",cryptoKey,signed));
  let binary=""; digest.forEach(v=>binary+=String.fromCharCode(v));
  const expected=btoa(binary);
  return signatures.split(" ").some(part=>part.startsWith("v1,") && part.slice(3)===expected);
}
async function handleResendWebhook(req, env) {
  const raw=await req.text();
  if (!(await verifyResendWebhook(req,raw,env.RESEND_WEBHOOK_SECRET))) return json({error:"Invalid webhook signature."},401);
  let event; try { event=JSON.parse(raw); } catch { return json({error:"Invalid JSON."},400); }
  if (event.type!=="email.received") return json({received:true,ignored:true});
  const meta=event.data||{}, emailId=String(meta.email_id||"");
  if (!emailId || !env.RESEND_API_KEY || !env.DB) return json({error:"Receiving is not configured."},503);
  const exists=await env.DB.prepare("SELECT id FROM inbound_email_events WHERE resend_email_id=?").bind(emailId).first();
  if (exists) return json({received:true,duplicate:true});
  const response=await fetch("https://api.resend.com/emails/receiving/"+encodeURIComponent(emailId),{headers:{Authorization:"Bearer "+env.RESEND_API_KEY}});
  if(!response.ok) return json({error:"Could not retrieve received email from Resend."},502);
  const payload=await response.json(), mail=payload.data||payload;
  const from=String(mail.from||meta.from||"").slice(0,250);
  const match=from.match(/<([^>]+)>/), address=(match?match[1]:from).trim();
  const name=(match?from.replace(match[0],"").replace(/["']/g,"").trim():address).slice(0,120)||address;
  const to=Array.isArray(mail.to)?mail.to:(Array.isArray(meta.to)?meta.to:[String(mail.to||"")]);
  const subject=String(mail.subject||meta.subject||"Incoming email").slice(0,200);
  const textBody=String(mail.text||"").slice(0,30000);
  const htmlBody=String(mail.html||"").slice(0,60000);
  const received=String(mail.created_at||event.created_at||new Date().toISOString());
  const attachmentRows=[];
  const listed=Array.isArray(mail.attachments)?mail.attachments:[];
  for(const item of listed.slice(0,10)){
    if(!env.MEDIA) break;
    const aid=String(item.id||""); if(!aid) continue;
    const ar=await fetch("https://api.resend.com/emails/receiving/"+encodeURIComponent(emailId)+"/attachments/"+encodeURIComponent(aid),{headers:{Authorization:"Bearer "+env.RESEND_API_KEY}});
    if(!ar.ok) continue;
    const ad=await ar.json(), obj=ad.data||ad, download=obj.download_url||obj.url;
    if(!download) continue;
    const file=await fetch(download); if(!file.ok) continue;
    const bytes=await file.arrayBuffer(); if(bytes.byteLength>15*1024*1024) continue;
    const filename=String(item.filename||obj.filename||"attachment").replace(/[^a-zA-Z0-9._-]/g,"_");
    const key="inbound/"+crypto.randomUUID()+"-"+filename;
    await env.MEDIA.put(key,bytes,{httpMetadata:{contentType:item.content_type||"application/octet-stream"}});
    attachmentRows.push({key,url:"/api/admin/messages/attachment?key="+encodeURIComponent(key),name:filename,content_type:item.content_type||"",size:bytes.byteLength});
  }
  const cleanText = textBody || String(htmlBody||"").replace(/<\/(p|div|br|li|h[1-6])>/gi,"\n").replace(/<[^>]*>/g," ").replace(/&nbsp;/g," ").replace(/&amp;/g,"&").trim() || "(No message body)";
  const inserted=await env.DB.prepare("INSERT INTO messages(name,email,subject,body,status,created_at,reply_text,replied_at) VALUES(?,?,?,?,?,?,?,?)")
    .bind(name,address,subject,cleanText.slice(0,30000), "new",received, JSON.stringify({inbound:true,html:htmlBody,attachments:attachmentRows}),null).run();
  await env.DB.prepare("INSERT INTO inbound_email_events(id,resend_email_id,message_id,sender,recipients,subject,body_text,body_html,headers_json,attachments_json,received_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(crypto.randomUUID(),emailId,inserted.meta?.last_row_id||null,from,JSON.stringify(to),subject,textBody,htmlBody,JSON.stringify(mail.headers||{}),JSON.stringify(attachmentRows),received,new Date().toISOString()).run();
  return json({received:true});
}

async function api(req, env) {
  const u = new URL(req.url);
  const p = u.pathname;
  const method = req.method;

  if (p === "/api/webhooks/resend" && method === "POST") return handleResendWebhook(req,env);
  if (p === "/api/health") return json({ ok: true, v: 4 });
  if (p === "/api/public" && method === "GET")
    return json(await allPublic(env));
  if (p === "/api/pages" && method === "GET") {
    const limit = Math.max(1,Math.min(60,Number(u.searchParams.get("limit")||24)));
    const offset = Math.max(0,Math.min(100000,Number(u.searchParams.get("offset")||0)));
    const pages = await safeAll(env,
      "SELECT p.slug,p.title_en,p.title_ne,p.description_en,p.description_ne,p.thumbnail_image,p.thumbnail_title_en,p.thumbnail_title_ne,p.thumbnail_summary_en,p.thumbnail_summary_ne,p.thumbnail_alt,p.thumbnail_focal_x,p.thumbnail_focal_y,p.updated_at,p.department_id,p.is_popular,d.name_en AS dept_en,d.name_ne AS dept_ne,d.slug AS dept_slug FROM pages p LEFT JOIN departments d ON d.id=p.department_id WHERE p.published=1 ORDER BY p.updated_at DESC LIMIT ? OFFSET ?",
      limit,offset);
    return json({pages,hasMore:pages.length===limit});
  }

  if (p === "/api/search" && method === "POST") {
    const x = await body(req);
    const query = String(x.query || "").trim().slice(0,240);
    if (query.length < 2) return json({ answer:"", results:[], message:"Type at least two characters." },400);
    const words = [...new Set(query.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(w=>w.length>1))].slice(0,8);
    if (!words.length) return json({ answer:"", results:[] });
    const where = words.map(()=>"(i.title LIKE ? OR i.description LIKE ? OR i.body_text LIKE ?)").join(" OR ");
    const binds = words.flatMap(w=>{const q="%"+w+"%";return [q,q,q]});
    const rows = await safeAll(env,
      "SELECT i.page_slug,i.title,i.description,i.body_text,p.thumbnail_image,p.thumbnail_title_en,p.thumbnail_title_ne,p.thumbnail_summary_en,p.thumbnail_summary_ne,p.department_id,d.name_en AS dept_en,d.name_ne AS dept_ne FROM page_search_index i JOIN pages p ON p.slug=i.page_slug LEFT JOIN departments d ON d.id=p.department_id WHERE p.published=1 AND ("+where+") ORDER BY p.updated_at DESC LIMIT 8",
      ...binds);
    const results = rows.map(r=>({
      slug:r.page_slug,title:r.thumbnail_title_en||r.title,title_ne:r.thumbnail_title_ne||"",
      summary:r.thumbnail_summary_en||r.description||pageExcerpt(r.body_text,query),
      summary_ne:r.thumbnail_summary_ne||"",image:r.thumbnail_image||"",department:r.dept_en||"",
      excerpt:pageExcerpt(r.body_text,query),url:"/"+encodeURIComponent(r.page_slug)
    }));
    const answer = results.slice(0,3).map(r=>r.excerpt||r.summary).filter(Boolean).join(" ");
    return json({ query, answer, results, grounded:results.length>0,
      message:results.length ? "" : "Granshi मा यस प्रश्नको पर्याप्त प्रकाशित जानकारी भेटिएन।" });
  }


  // Public comments / feedback on pages
  if (p === "/api/comments" && method === "GET") {
    const slug = slugify(u.searchParams.get("slug") || "");
    if (!slug) return json({ error: "slug required" }, 400);
    const rows = await safeAll(
      env,
      "SELECT id,name,body,created_at FROM comments WHERE page_slug=? AND status='approved' ORDER BY created_at DESC LIMIT 100",
      slug
    );
    return json({ comments: rows });
  }
  if (p === "/api/comments" && method === "POST") {
    const x = await body(req);
    // honeypot
    if (x.website) return json({ ok: true });
    const slug = slugify(x.page_slug || x.slug || "");
    const name = String(x.name || "")
      .trim()
      .slice(0, 80);
    const email = String(x.email || "")
      .trim()
      .slice(0, 180);
    const bodyText = String(x.body || x.comment || "")
      .trim()
      .slice(0, 2000);
    if (!slug || !name || !bodyText)
      return json({ error: "Name and comment required." }, 400);
    if (bodyText.length < 3) return json({ error: "Comment too short." }, 400);
    try {
      await env.DB.prepare(
        "INSERT INTO comments(page_slug,name,email,body,status,created_at) VALUES(?,?,?,?,?,?)"
      )
        .bind(slug, name, email, bodyText, "pending", new Date().toISOString())
        .run();
    } catch (e) {
      return json(
        {
          error: "Comments not ready. Create comments table in D1.",
          detail: String(e),
        },
        503
      );
    }
    return json({
      ok: true,
      message: "Thanks! Your feedback is awaiting approval.",
    });
  }

  if (p === "/api/contact" && method === "POST") {
    const x = await body(req);
    const name = String(x.name || "")
      .trim()
      .slice(0, 120);
    const email = String(x.email || "")
      .trim()
      .slice(0, 180);
    const subject = String(x.subject || "")
      .trim()
      .slice(0, 200);
    const msg = String(x.body || x.message || "")
      .trim()
      .slice(0, 5000);
    const departmentId = x.department_id ? Number(x.department_id) : null;
    if (!name || !email || !msg)
      return json({ error: "Name, email and message required." }, 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return json({ error: "Invalid email." }, 400);
    let deptEmail = null;
    if (departmentId) {
      const d = await env.DB.prepare("SELECT email FROM departments WHERE id=?")
        .bind(departmentId)
        .first();
      deptEmail = d?.email || null;
    }
    await env.DB.prepare(
      "INSERT INTO messages(department_id,name,email,subject,body,status,created_at) VALUES(?,?,?,?,?,?,?)"
    )
      .bind(
        departmentId,
        name,
        email,
        subject || "Contact",
        msg,
        "new",
        new Date().toISOString()
      )
      .run();
    const settings = await getSettings(env);
    const target = deptEmail || settings.contact_email || null;
    if (target) {
      await sendEmail(env, {
        to: target,
        subject: `[Granshi] ${subject || "Message"} — ${name}`,
        replyTo: email,
        html: `<p><b>From:</b> ${escapeHtml(name)} &lt;${escapeHtml( email )}&gt;</p><p>${escapeHtml(msg).replace(/\n/g, "<br>")}</p>`,
      });
    }
    return json({ ok: true });
  }

  if (p === "/api/setup/status" && method === "GET") {
    const x = await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first();
    return json({ initialized: (x?.n || 0) > 0 });
  }
  if (p === "/api/setup" && method === "POST") {
    const x = await body(req);
    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM admins"
    ).first();
    if ((count?.n || 0) > 0)
      return json({ error: "Admin already initialized." }, 409);
    if (!env.SETUP_TOKEN || x.setupToken !== env.SETUP_TOKEN)
      return json({ error: "Invalid setup token." }, 403);
    if (!x.email || !x.password || String(x.password).length < 12)
      return json({ error: "Email + password (12+) required." }, 400);
    const h = await passwordHash(String(x.password));
    await env.DB.prepare(
      "INSERT INTO admins(email,salt,password_hash,created_at) VALUES(?,?,?,?)"
    )
      .bind(
        String(x.email).toLowerCase(),
        h.salt,
        h.hash,
        new Date().toISOString()
      )
      .run();
    return json({ ok: true }, 200, {
      "set-cookie": sessionCookie(
        await sessionToken(env, String(x.email).toLowerCase())
      ),
    });
  }
  if (p === "/api/auth/login" && method === "POST") {
    const x = await body(req);
    const a = await env.DB.prepare(
      "SELECT email,salt,password_hash FROM admins WHERE email=?"
    )
      .bind(String(x.email || "").toLowerCase())
      .first();
    if (
      !a ||
      !(await verifyPassword(String(x.password || ""), a.salt, a.password_hash))
    )
      return json({ error: "Incorrect email or password." }, 401);
    return json({ ok: true }, 200, {
      "set-cookie": sessionCookie(await sessionToken(env, a.email)),
    });
  }
  if (p === "/api/auth/logout" && method === "POST")
    return json({ ok: true }, 200, { "set-cookie": clearCookie });

  const who = await auth(req, env);
  if (!who) return json({ error: "Please log in." }, 401);
  if (p === "/api/auth/me") return json({ email: who });

  if (p === "/api/admin/messages/attachment" && method === "GET") {
    const key = String(u.searchParams.get("key") || "");
    if (!key.startsWith("inbound/") || key.includes("..")) return json({ error: "Invalid attachment." }, 400);
    if (!env.MEDIA) return json({ error: "Storage unavailable." }, 503);
    const object = await env.MEDIA.get(key);
    if (!object) return json({ error: "Attachment not found." }, 404);
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("cache-control", "private, no-store");
    headers.set("content-disposition", "attachment; filename*=UTF-8''" + encodeURIComponent(key.split("/").pop()));
    return new Response(object.body, { headers });
  }

  if (p === "/api/admin/overview") {
    const pub = await allPublic(env);
    const msgNew = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM messages WHERE status='new'"
    ).first();
    return json({ email: who, new_messages: msgNew?.n || 0, ...pub });
  }

  // Departments
  if (p === "/api/admin/departments" && method === "GET") {
    return json(
      (
        await env.DB.prepare(
          "SELECT * FROM departments ORDER BY sort_order"
        ).all()
      ).results || []
    );
  }
  if (p === "/api/admin/departments" && method === "POST") {
    const x = await body(req);
    const slug = slugify(x.slug || x.name_en);
    if (x.id) {
      await env.DB.prepare(
        "UPDATE departments SET name_en=?,name_ne=?,description_en=?,description_ne=?,url=?,icon=?,email=?,image=?,slug=?,visible=?,sort_order=? WHERE id=?"
      )
        .bind(
          x.name_en,
          x.name_ne || "",
          x.description_en || "",
          x.description_ne || "",
          x.url || `/dept/${slug}`,
          x.icon || "✦",
          x.email || "",
          x.image || "",
          slug,
          x.visible ? 1 : 0,
          Number(x.sort_order || 0),
          x.id
        )
        .run();
    } else {
      await env.DB.prepare(
        "INSERT INTO departments(name_en,name_ne,description_en,description_ne,url,icon,email,image,slug,visible,sort_order) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
      )
        .bind(
          x.name_en,
          x.name_ne || "",
          x.description_en || "",
          x.description_ne || "",
          x.url || `/dept/${slug}`,
          x.icon || "✦",
          x.email || "",
          x.image || "",
          slug,
          x.visible === false ? 0 : 1,
          Number(x.sort_order || 0)
        )
        .run();
    }
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/departments/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM departments WHERE id=?")
      .bind(p.split("/").pop())
      .run();
    return json({ ok: true });
  }
  // Department detail bundle (pages + categories + media)
  if (p.match(/^\/api\/admin\/departments\/\d+\/bundle$/) && method === "GET") {
    const id = Number(p.split("/")[4]);
    const dept = await env.DB.prepare("SELECT * FROM departments WHERE id=?")
      .bind(id)
      .first();
    if (!dept) return json({ error: "Not found" }, 404);
    let pages = await safeAll(
      env,
      "SELECT * FROM pages WHERE department_id=? ORDER BY sort_order,updated_at DESC",
      id
    );
    // fallback: all pages if column missing (so UI still opens)
    if (!pages.length) {
      try {
        await env.DB.prepare("SELECT department_id FROM pages LIMIT 1").first();
      } catch {
        pages = await safeAll(
          env,
          "SELECT * FROM pages ORDER BY updated_at DESC LIMIT 50"
        );
      }
    }
    const cats = await safeAll(
      env,
      "SELECT * FROM categories WHERE department_id=? ORDER BY sort_order",
      id
    );
    let media = await safeAll(
      env,
      "SELECT * FROM media WHERE department_id=? ORDER BY created_at DESC",
      id
    );
    if (!media.length)
      media = await safeAll(
        env,
        "SELECT * FROM media ORDER BY created_at DESC LIMIT 100"
      );
    return json({ department: dept, pages, categories: cats, media });
  }

  // Pages
  if (p === "/api/admin/pages" && method === "GET") {
    const dept = u.searchParams.get("department_id");
    if (dept) {
      return json(
        (
          await env.DB.prepare(
            "SELECT * FROM pages WHERE department_id=? ORDER BY sort_order,updated_at DESC"
          )
            .bind(Number(dept))
            .all()
        ).results || []
      );
    }
    return json(
      (
        await env.DB.prepare(
          `SELECT p.*, d.name_en AS dept_name FROM pages p LEFT JOIN departments d ON d.id=p.department_id ORDER BY p.updated_at DESC`
        ).all()
      ).results || []
    );
  }
  if (p === "/api/admin/pages" && method === "POST") {
    const x = await body(req);
    const slug = slugify(x.slug || x.title_en);
    if (!slug || !x.title_en)
      return json({ error: "Title and slug required." }, 400);
    const sourceType = x.source_type === "zip" ? "zip" : "blocks";
    const entryFile = String(x.entry_file || "index.html").replace(/^\/+/, "");
    // content for zip pages stores file list JSON; for blocks stores blocks
    const contentStr =
      typeof x.content === "string"
        ? x.content
        : JSON.stringify(x.content || []);
    const updatedAt = new Date().toISOString();
    let thumbnailImage = String(x.thumbnail_image || "").trim().slice(0,1000);
    if (!thumbnailImage && sourceType === "blocks") {
      try { const blocks=JSON.parse(contentStr); const first=blocks.find(b=>b&&((b.type==="image"&&b.url)||(b.type==="hero"&&b.image))); if(first) thumbnailImage=String(first.url||first.image||"").slice(0,1000); } catch {}
    }
    if (!thumbnailImage && sourceType === "zip") {
      const media = await env.DB.prepare("SELECT url FROM media WHERE page_slug=? AND content_type LIKE 'image/%' ORDER BY created_at LIMIT 1").bind(slug).first();
      if (media) thumbnailImage = media.url;
    }
    let searchText = searchablePageText(contentStr);
    if (sourceType === "zip" && env.MEDIA) {
      const entryObject = await env.MEDIA.get(`pages/${slug}/${entryFile}`);
      if (entryObject) {
        const html = await entryObject.text();
        searchText = htmlToSearchText(html);
        const extractedCover = zipCoverFromHtml(html,slug);\n        if (extractedCover) thumbnailImage = extractedCover;
      }
    }
    await env.DB.prepare(
      `INSERT INTO pages(slug,title_en,title_ne,description_en,description_ne,content,template,department_id,category_id,is_popular,published,sort_order,updated_at,thumbnail_image,thumbnail_title_en,thumbnail_title_ne,thumbnail_summary_en,thumbnail_summary_ne,thumbnail_alt,thumbnail_focal_x,thumbnail_focal_y)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(slug) DO UPDATE SET title_en=excluded.title_en,title_ne=excluded.title_ne,description_en=excluded.description_en,description_ne=excluded.description_ne,content=excluded.content,template=excluded.template,department_id=excluded.department_id,category_id=excluded.category_id,is_popular=excluded.is_popular,published=excluded.published,sort_order=excluded.sort_order,updated_at=excluded.updated_at,thumbnail_image=excluded.thumbnail_image,thumbnail_title_en=excluded.thumbnail_title_en,thumbnail_title_ne=excluded.thumbnail_title_ne,thumbnail_summary_en=excluded.thumbnail_summary_en,thumbnail_summary_ne=excluded.thumbnail_summary_ne,thumbnail_alt=excluded.thumbnail_alt,thumbnail_focal_x=excluded.thumbnail_focal_x,thumbnail_focal_y=excluded.thumbnail_focal_y`
    ).bind(slug,x.title_en,x.title_ne||"",x.description_en||"",x.description_ne||"",contentStr,sourceType==="zip"?`zip:${entryFile}`:x.template||"default",x.department_id||null,x.category_id||null,x.is_popular?1:0,x.published?1:0,Number(x.sort_order||0),updatedAt,thumbnailImage,String(x.thumbnail_title_en||"").slice(0,180),String(x.thumbnail_title_ne||"").slice(0,180),String(x.thumbnail_summary_en||x.description_en||searchText.slice(0,260)).slice(0,400),String(x.thumbnail_summary_ne||x.description_ne||searchText.slice(0,260)).slice(0,400),String(x.thumbnail_alt||"").slice(0,250),Math.max(0,Math.min(100,Number(x.thumbnail_focal_x??50))),Math.max(0,Math.min(100,Number(x.thumbnail_focal_y??50)))).run();
    if (x.published) {
      await env.DB.prepare("INSERT INTO page_search_index(page_slug,title,description,body_text,department_id,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(page_slug) DO UPDATE SET title=excluded.title,description=excluded.description,body_text=excluded.body_text,department_id=excluded.department_id,updated_at=excluded.updated_at")
        .bind(slug,[x.title_en,x.title_ne].join(" "),[x.description_en,x.description_ne].join(" "),searchText,x.department_id||null,updatedAt).run();
    } else {
      await env.DB.prepare("DELETE FROM page_search_index WHERE page_slug=?").bind(slug).run();
    }
    return json({
      ok: true,
      slug,
      source_type: sourceType,
      entry_file: entryFile,
      preview: `/_preview/${slug}`,
    });
  }
  // Upload ZIP asset or gallery add/replace → R2 + media table
  if (p === "/api/admin/pages/asset" && method === "POST") {
    if (!env.MEDIA) return json({ error: "R2 not configured." }, 503);
    const slug = slugify(req.headers.get("x-page-slug") || "");
    let rel = decodeURIComponent(req.headers.get("x-rel-path") || "index.html")
      .replace(/\\/g, "/")
      .replace(/^\/+/, "");
    if (!slug || !rel || rel.includes(".."))
      return json({ error: "slug and relative path required." }, 400);
    const file = await req.arrayBuffer();
    if (file.byteLength > 25 * 1024 * 1024)
      return json({ error: "File max 25 MB." }, 413);
    const type = req.headers.get("content-type") || "application/octet-stream";
    const departmentId = req.headers.get("x-department-id")
      ? Number(req.headers.get("x-department-id"))
      : null;
    const key = `pages/${slug}/${rel}`;
    await env.MEDIA.put(key, file, { httpMetadata: { contentType: type } });
    const url = `/_p/${slug}/${rel}`;
    const name = rel.split("/").pop() || rel;
    await env.DB.prepare("DELETE FROM media WHERE key=?").bind(key).run();
    await env.DB.prepare(
      "INSERT INTO media(key,name,url,content_type,size,department_id,page_slug,created_at) VALUES(?,?,?,?,?,?,?,?)"
    )
      .bind(
        key,
        name,
        url,
        type,
        file.byteLength,
        departmentId,
        slug,
        new Date().toISOString()
      )
      .run();
    return json({
      ok: true,
      key,
      url,
      name,
      page_slug: slug,
      department_id: departmentId,
    });
  }
  if (p.startsWith("/api/admin/pages/") && method === "DELETE") {
    const slug = decodeURIComponent(p.split("/").pop());
    await env.DB.prepare("DELETE FROM pages WHERE slug=?").bind(slug).run();
    await env.DB.prepare("DELETE FROM page_search_index WHERE page_slug=?").bind(slug).run();
    // best-effort: list/delete R2 not available without list permission pattern — leave orphans ok
    return json({ ok: true });
  }

  // Categories (department-scoped)
  if (p === "/api/admin/categories" && method === "GET") {
    const dept = u.searchParams.get("department_id");
    if (dept)
      return json(
        (
          await env.DB.prepare(
            "SELECT * FROM categories WHERE department_id=? ORDER BY sort_order"
          )
            .bind(Number(dept))
            .all()
        ).results || []
      );
    return json(
      (
        await env.DB.prepare(
          "SELECT * FROM categories ORDER BY sort_order"
        ).all()
      ).results || []
    );
  }
  if (p === "/api/admin/categories" && method === "POST") {
    const x = await body(req);
    const slug = slugify(x.slug || x.name_en);
    if (!x.name_en || !x.department_id)
      return json({ error: "Name and department required." }, 400);
    if (x.id) {
      await env.DB.prepare(
        "UPDATE categories SET name_en=?,name_ne=?,slug=?,description_en=?,description_ne=?,image=?,department_id=?,visible=?,sort_order=? WHERE id=?"
      )
        .bind(
          x.name_en,
          x.name_ne || "",
          slug,
          x.description_en || "",
          x.description_ne || "",
          x.image || "",
          x.department_id,
          x.visible ? 1 : 0,
          Number(x.sort_order || 0),
          x.id
        )
        .run();
    } else {
      await env.DB.prepare(
        "INSERT INTO categories(name_en,name_ne,slug,description_en,description_ne,image,department_id,visible,sort_order) VALUES(?,?,?,?,?,?,?,?,?)"
      )
        .bind(
          x.name_en,
          x.name_ne || "",
          slug,
          x.description_en || "",
          x.description_ne || "",
          x.image || "",
          x.department_id,
          1,
          Number(x.sort_order || 0)
        )
        .run();
    }
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/categories/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM categories WHERE id=?")
      .bind(p.split("/").pop())
      .run();
    return json({ ok: true });
  }

  // Menus / Settings
  if (p === "/api/admin/menus" && method === "GET")
    return json(
      (await env.DB.prepare("SELECT * FROM menus ORDER BY sort_order").all())
        .results || []
    );
  if (p === "/api/admin/menus" && method === "POST") {
    const x = await body(req);
    if (x.id)
      await env.DB.prepare(
        "UPDATE menus SET label_en=?,label_ne=?,url=?,visible=?,sort_order=? WHERE id=?"
      )
        .bind(
          x.label_en,
          x.label_ne || "",
          x.url || "#",
          x.visible ? 1 : 0,
          Number(x.sort_order || 0),
          x.id
        )
        .run();
    else
      await env.DB.prepare(
        "INSERT INTO menus(label_en,label_ne,url,visible,sort_order) VALUES(?,?,?,?,?)"
      )
        .bind(
          x.label_en,
          x.label_ne || "",
          x.url || "#",
          1,
          Number(x.sort_order || 0)
        )
        .run();
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/menus/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM menus WHERE id=?")
      .bind(p.split("/").pop())
      .run();
    return json({ ok: true });
  }
  if (p === "/api/admin/settings" && method === "POST") {
    const x = await body(req);
    for (const [k, v] of Object.entries(x)) {
      await env.DB.prepare(
        "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      )
        .bind(k, String(v))
        .run();
    }
    return json({ ok: true });
  }

  // Media
  if (p === "/api/admin/media" && method === "GET") {
    const dept = u.searchParams.get("department_id");
    const pageSlug = u.searchParams.get("page_slug");
    if (dept)
      return json(
        (
          await env.DB.prepare(
            "SELECT * FROM media WHERE department_id=? ORDER BY created_at DESC"
          )
            .bind(Number(dept))
            .all()
        ).results || []
      );
    if (pageSlug)
      return json(
        (
          await env.DB.prepare(
            "SELECT * FROM media WHERE page_slug=? ORDER BY created_at DESC"
          )
            .bind(pageSlug)
            .all()
        ).results || []
      );
    return json(
      (
        await env.DB.prepare(
          "SELECT * FROM media ORDER BY created_at DESC LIMIT 200"
        ).all()
      ).results || []
    );
  }
  if (p === "/api/admin/media/upload" && method === "POST") {
    if (!env.MEDIA) return json({ error: "R2 not configured." }, 503);
    const file = await req.arrayBuffer();
    const type = req.headers.get("content-type") || "application/octet-stream";
    const name = decodeURIComponent(
      req.headers.get("x-file-name") || "upload.bin"
    ).replace(/[^a-zA-Z0-9._-]/g, "_");
    const departmentId = req.headers.get("x-department-id")
      ? Number(req.headers.get("x-department-id"))
      : null;
    const pageSlug = req.headers.get("x-page-slug") || null;
    if (file.byteLength > 25 * 1024 * 1024)
      return json({ error: "Max 25 MB." }, 413);
    const key = `uploads/${crypto.randomUUID()}-${name}`;
    await env.MEDIA.put(key, file, { httpMetadata: { contentType: type } });
    const url = `/media/${key}`;
    await env.DB.prepare(
      "INSERT INTO media(key,name,url,content_type,size,department_id,page_slug,created_at) VALUES(?,?,?,?,?,?,?,?)"
    )
      .bind(
        key,
        name,
        url,
        type,
        file.byteLength,
        departmentId,
        pageSlug,
        new Date().toISOString()
      )
      .run();
    return json({ ok: true, key, url });
  }
  if (p.startsWith("/api/admin/media/") && method === "DELETE") {
    const key = decodeURIComponent(p.split("/").pop());
    if (env.MEDIA) await env.MEDIA.delete(key);
    await env.DB.prepare("DELETE FROM media WHERE key=?").bind(key).run();
    return json({ ok: true });
  }

  // Messages + reply (text + optional attachments)
  if (p === "/api/admin/messages" && method === "GET") {
    return json(
      (
        await env.DB.prepare(
          `SELECT m.*, d.name_en AS department_name FROM messages m LEFT JOIN departments d ON d.id=m.department_id ORDER BY m.created_at DESC LIMIT 300`
        ).all()
      ).results || []
    );
  }
  // Upload reply attachment → returns url (call before reply POST)
  if (p === "/api/admin/messages/attach" && method === "POST") {
    if (!env.MEDIA) return json({ error: "R2 not configured." }, 503);
    const file = await req.arrayBuffer();
    const type = req.headers.get("content-type") || "application/octet-stream";
    const name = decodeURIComponent(
      req.headers.get("x-file-name") || "attach.bin"
    ).replace(/[^a-zA-Z0-9._-]/g, "_");
    if (file.byteLength > 15 * 1024 * 1024)
      return json({ error: "Attachment max 15 MB." }, 413);
    const key = `replies/${crypto.randomUUID()}-${name}`;
    await env.MEDIA.put(key, file, { httpMetadata: { contentType: type } });
    const url = `/media/${key}`;
    return json({
      ok: true,
      key,
      url,
      name,
      content_type: type,
      size: file.byteLength,
    });
  }
  if (p.match(/^\/api\/admin\/messages\/\d+\/reply$/) && method === "POST") {
    const id = p.split("/")[4];
    const x = await body(req);
    const reply = String(x.reply_text || x.reply || "")
      .trim()
      .slice(0, 5000);
    if (!reply) return json({ error: "Reply text required." }, 400);
    const attachments = Array.isArray(x.attachments)
      ? x.attachments.slice(0, 10)
      : [];
    const msg = await env.DB.prepare("SELECT * FROM messages WHERE id=?")
      .bind(id)
      .first();
    if (!msg) return json({ error: "Not found" }, 404);
    // Store attachments JSON at end of reply_text marker (no schema change required)
    const stored =
      attachments.length > 0
        ? reply + "\n\n<!--ATTACH:" + JSON.stringify(attachments) + "-->"
        : reply;
    const attHtml = attachments
      .map((a) => {
        const u = escapeHtml(a.url || "");
        const n = escapeHtml(a.name || "file");
        const isImg =
          /\.(png|jpe?g|gif|webp)$/i.test(a.name || "") ||
          (a.content_type || "").startsWith("image/");
        if (isImg)
          return `<p><a href="${u}"><img src="${u}" alt="${n}" style="max-width:240px;border-radius:8px"></a></p>`;
        return `<p>Attachment: <a href="${u}">${n}</a></p>`;
      })
      .join("");
    const delivery = await sendEmail(env, {
      to: msg.email,
      subject: `Re: ${msg.subject || "Your message to Granshi"}`,
      replyTo: "info@gopalkoirala.com.np",
      html: `<p>Hello ${escapeHtml(msg.name)},</p><p>${escapeHtml( reply ).replace(/\n/g, "<br>")}</p>${attHtml}<hr><p>Original: ${escapeHtml( msg.body || "" )}</p>`,
      attachments,
    });
    if (!delivery.sent) return json({ error: "Reply could not be sent.", detail: delivery.error || "Email service unavailable." }, 502);
    await env.DB.prepare(
      "UPDATE messages SET reply_text=?,replied_at=?,status=? WHERE id=?"
    )
      .bind(stored, new Date().toISOString(), "replied", id)
      .run();
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/messages/") && method === "POST") {
    const x = await body(req);
    if (x.status)
      await env.DB.prepare("UPDATE messages SET status=? WHERE id=?")
        .bind(x.status, p.split("/").pop())
        .run();
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/messages/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM messages WHERE id=?")
      .bind(p.split("/").pop())
      .run();
    return json({ ok: true });
  }

  if (p === "/api/admin/password" && method === "POST") {
    const x = await body(req);
    if (String(x.newPassword || "").length < 12)
      return json({ error: "Min 12 characters." }, 400);
    const old = await env.DB.prepare(
      "SELECT salt,password_hash FROM admins WHERE email=?"
    )
      .bind(who)
      .first();
    if (
      !old ||
      !(await verifyPassword(
        String(x.currentPassword || ""),
        old.salt,
        old.password_hash
      ))
    )
      return json({ error: "Current password incorrect." }, 401);
    const h = await passwordHash(x.newPassword);
    await env.DB.prepare(
      "UPDATE admins SET salt=?,password_hash=? WHERE email=?"
    )
      .bind(h.salt, h.hash, who)
      .run();
    return json({ ok: true });
  }

  // Admin: comments moderation
  if (p === "/api/admin/comments" && method === "GET") {
    const rows = await safeAll(
      env,
      "SELECT * FROM comments ORDER BY created_at DESC LIMIT 300"
    );
    return json(rows);
  }
  if (p.match(/^\/api\/admin\/comments\/\d+$/) && method === "POST") {
    const id = p.split("/").pop();
    const x = await body(req);
    if (
      x.status === "approved" ||
      x.status === "pending" ||
      x.status === "spam"
    ) {
      await env.DB.prepare("UPDATE comments SET status=? WHERE id=?")
        .bind(x.status, id)
        .run();
    }
    return json({ ok: true });
  }
  if (p.match(/^\/api\/admin\/comments\/\d+$/) && method === "DELETE") {
    await env.DB.prepare("DELETE FROM comments WHERE id=?")
      .bind(p.split("/").pop())
      .run();
    return json({ ok: true });
  }

  return json({ error: "API route not found." }, 404);
}

function commentsWidgetHtml(slug) {
  const s = escapeHtml(slug);
  return ` <section id="granshi-comments" class="g-comments" data-slug="${s}"> <h2 class="g-c-title">Comments / Feedback</h2> <div id="g-c-list" class="g-c-list"><p class="g-c-muted">Loading…</p></div> <form id="g-c-form" class="g-c-form"> <p class="g-c-muted">Share your thoughts. Comments appear after approval.</p> <label>Name *</label> <input name="name" required maxlength="80" autocomplete="name"> <label>Email (optional)</label> <input name="email" type="email" maxlength="180" autocomplete="email"> <label style="position:absolute;left:-9999px">Website</label> <input name="website" tabindex="-1" autocomplete="off" style="position:absolute;left:-9999px"> <label>Comment *</label> <textarea name="body" required maxlength="2000" rows="4"></textarea> <button type="submit">Send feedback</button> <p id="g-c-msg" class="g-c-msg"></p> </form> </section> <style> .g-comments{max-width:720px;margin:40px auto;padding:24px 16px;border-top:1px solid #e5e9ef;font-family:system-ui,sans-serif;color:#172033} .g-c-title{font-size:1.25rem;margin:0 0 16px} .g-c-list{margin-bottom:24px} .g-c-item{background:#f7f8fb;border-radius:12px;padding:12px 14px;margin:10px 0} .g-c-item b{font-size:14px}.g-c-item time{font-size:12px;color:#667085;margin-left:8px} .g-c-item p{margin:8px 0 0;line-height:1.55;white-space:pre-wrap} .g-c-muted{color:#667085;font-size:13px} .g-c-form label{display:block;font-size:12px;font-weight:700;margin:10px 0 4px} .g-c-form input,.g-c-form textarea{width:100%;padding:10px 12px;border:1px solid #dfe4ec;border-radius:8px;font:inherit;box-sizing:border-box} .g-c-form button{margin-top:12px;padding:10px 16px;border:0;border-radius:8px;background:#172640;color:#fff;font-weight:700;cursor:pointer} .g-c-msg{font-size:13px;margin-top:8px} .g-c-msg.ok{color:#1b7a3d}.g-c-msg.err{color:#a83333} </style> <script> (function(){ var root=document.getElementById('granshi-comments'); if(!root)return; var slug=root.getAttribute('data-slug'); var list=document.getElementById('g-c-list'); var form=document.getElementById('g-c-form'); var msg=document.getElementById('g-c-msg'); function esc(t){return String(t||'').replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})} function load(){ fetch('/api/comments?slug='+encodeURIComponent(slug)).then(function(r){return r.json()}).then(function(d){ var rows=d.comments||[]; if(!rows.length){list.innerHTML='<p class="g-c-muted">No comments yet. Be the first.</p>';return} list.innerHTML=rows.map(function(c){ var t=(c.created_at||'').replace('T',' ').slice(0,16); return '<div class="g-c-item"><b>'+esc(c.name)+'</b><time>'+esc(t)+'</time><p>'+esc(c.body)+'</p></div>'; }).join(''); }).catch(function(){list.innerHTML='<p class="g-c-muted">Could not load comments.</p>'}); } form.addEventListener('submit',function(e){ e.preventDefault(); msg.className='g-c-msg';msg.textContent='Sending…'; var fd=new FormData(form); fetch('/api/comments',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ page_slug:slug,name:fd.get('name'),email:fd.get('email'),body:fd.get('body'),website:fd.get('website') })}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d}})}).then(function(x){ if(!x.ok)throw new Error(x.d.error||'Failed'); msg.className='g-c-msg ok';msg.textContent=x.d.message||'Thank you!'; form.reset(); }).catch(function(err){msg.className='g-c-msg err';msg.textContent=err.message||'Error'}); }); load(); })(); </script>`;
}

export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (u.pathname.startsWith("/api/")) {
      try {
        return await api(req, env);
      } catch (e) {
        return json({ error: "Server error", detail: String(e) }, 500);
      }
    }
    if (u.pathname.startsWith("/media/")) {
      if (!env.MEDIA)
        return new Response("Media not configured", { status: 503 });
      const key = u.pathname.slice(7);
      if (key.startsWith("inbound/")) return new Response("Not found", { status: 404 });
      const obj = await env.MEDIA.get(key);
      if (!obj) return new Response("Not found", { status: 404 });
      const h = new Headers();
      obj.writeHttpMetadata(h);
      h.set("etag", obj.httpEtag);
      h.set("cache-control", "public, max-age=86400");
      return new Response(obj.body, { headers: h });
    }
    // Static files for ZIP pages: /_p/{slug}/path
    if (u.pathname.startsWith("/_p/") && env.MEDIA) {
      const rest = u.pathname.slice(4); // slug/path
      const key = `pages/${rest}`;
      const obj = await env.MEDIA.get(key);
      if (!obj) return new Response("Not found", { status: 404 });
      const h = new Headers();
      obj.writeHttpMetadata(h);
      h.set("cache-control", "public, max-age=120");
      return new Response(obj.body, { headers: h });
    }
    // Admin/public preview of zip or blocks page (auth for unpublished)
    if (u.pathname.startsWith("/_preview/")) {
      const slug = u.pathname.slice(10).replace(/\/$/, "");
      try {
        const page = await env.DB.prepare("SELECT * FROM pages WHERE slug=?")
          .bind(slug)
          .first();
        if (!page) return new Response("Not found", { status: 404 });
        if (!page.published) {
          const who = await auth(req, env);
          if (!who)
            return new Response("Login required for preview", { status: 401 });
        }
        return await renderAnyPage(page, env, u);
      } catch (e) {
        return new Response("Preview error: " + String(e), { status: 500 });
      }
    }
    // Department listing page
    if (u.pathname.startsWith("/dept/")) {
      const slug = u.pathname.slice(6).replace(/\/$/, "");
      try {
        let dept = null;
        if (/^\d+$/.test(slug)) {
          dept = await env.DB.prepare(
            "SELECT * FROM departments WHERE id=? AND visible=1"
          )
            .bind(Number(slug))
            .first();
        }
        if (!dept) {
          try {
            dept = await env.DB.prepare(
              "SELECT * FROM departments WHERE slug=? AND visible=1"
            )
              .bind(slug)
              .first();
          } catch (_) {
            dept = null;
          }
        }
        if (!dept) {
          const all = await safeAll(
            env,
            "SELECT * FROM departments WHERE visible=1"
          );
          dept =
            all.find(
              (d) => (d.slug && d.slug === slug) || String(d.id) === slug
            ) || null;
        }
        if (dept) {
          const settings = await getSettings(env);
          const pages = await env.DB.prepare(
            "SELECT slug,title_en,title_ne,description_en,description_ne,thumbnail_image,thumbnail_title_en,thumbnail_title_ne,thumbnail_summary_en,thumbnail_summary_ne,thumbnail_alt,thumbnail_focal_x,thumbnail_focal_y,updated_at FROM pages WHERE department_id=? AND published=1 ORDER BY sort_order,updated_at DESC"
          )
            .bind(dept.id)
            .all();
          const lang = u.searchParams.get("lang") === "ne" ? "ne" : "en";
          const title =
            lang === "ne" && dept.name_ne ? dept.name_ne : dept.name_en;
          const palette = ["#14233d","#173c45","#3a2a52","#3d3442","#23415c","#3d3b25","#24433d","#3d2b26"];
          const list = (pages.results || []).map((pg,i) => {
            const image = pg.thumbnail_image ? `<img src="${escapeHtml(pg.thumbnail_image)}" alt="${escapeHtml(pg.thumbnail_alt||"")}" loading="lazy" style="object-position:${Number(pg.thumbnail_focal_x??50)}% ${Number(pg.thumbnail_focal_y??50)}%">` : `<div class="dept-art" style="background:linear-gradient(135deg,${palette[i%palette.length]},#0c1525)"><span>${escapeHtml(dept.icon||"✦")}</span></div>`;
            const cardTitle = lang==="ne" && pg.thumbnail_title_ne ? pg.thumbnail_title_ne : (pg.thumbnail_title_en || (lang==="ne"&&pg.title_ne?pg.title_ne:pg.title_en));
            const summary = lang==="ne" ? (pg.thumbnail_summary_ne||pg.description_ne||"") : (pg.thumbnail_summary_en||pg.description_en||"");
            return `<a class="dept-page" href="/${escapeHtml(pg.slug)}${lang==="ne"?"?lang=ne":""}">${image}<div class="dept-card-copy"><span class="dept-card-label">${escapeHtml(dept.name_en)}</span><h3>${escapeHtml(cardTitle)}</h3><p>${escapeHtml(summary.slice(0,150))}</p><b>Explore →</b></div></a>`;
          }).join("");
          const body = `<section class="page-hero"><div class="wrap"><span class="dept-kicker">GRANSHI DEPARTMENT</span><h1>${escapeHtml(title)}</h1><p>${escapeHtml(lang==="ne"&&dept.description_ne?dept.description_ne:dept.description_en||"")}</p><span class="dept-count">${(pages.results||[]).length} published pages</span></div></section><article class="wrap"><div class="dept-list">${list||"<p>No published pages yet.</p>"}</div><style>.dept-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(245px,1fr));gap:20px;margin:28px 0 50px}.dept-page{overflow:hidden;background:#fff;border:1px solid #e5e9ef;border-radius:18px;box-shadow:0 8px 28px #14233d0b;transition:.2s}.dept-page:hover{transform:translateY(-4px);box-shadow:0 16px 36px #14233d18}.dept-page>img,.dept-art{display:block;width:100%;height:170px;object-fit:cover}.dept-art{display:grid;place-items:center;color:#f2d99e;font-size:54px}.dept-card-copy{padding:16px}.dept-card-label,.dept-kicker{font-size:10px;letter-spacing:2px;font-weight:800;color:#a47b32}.dept-card-copy h3{margin:8px 0;font-size:18px;line-height:1.3}.dept-card-copy p{margin:0 0 14px;color:#667085;font-size:13px;line-height:1.6;min-height:40px}.dept-card-copy b{font-size:12px;color:#9a742e}.dept-count{display:inline-block;margin-top:8px;font-size:12px;color:#d9dfeb}</style></article>`;
          return new Response(
            pageChrome(title, dept.description_en || "", body, settings, lang),
            {
              headers: { "content-type": "text/html; charset=utf-8" },
            }
          );
        }
      } catch (_) {}
    }
    if (
      u.pathname !== "/" &&
      !u.pathname.startsWith("/admin") &&
      !u.pathname.startsWith("/_")
    ) {
      const slug = u.pathname.slice(1).replace(/\/$/, "").split("/")[0];
      if (slug && !slug.includes(".")) {
        try {
          const page = await env.DB.prepare(
            "SELECT * FROM pages WHERE slug=? AND published=1"
          )
            .bind(slug)
            .first();
          if (page) return await renderAnyPage(page, env, u);
        } catch (_) {}
      }
    }
    return env.ASSETS.fetch(req);
  },
};

async function renderAnyPage(page, env, u) {
  const settings = await getSettings(env);
  const lang = u.searchParams.get("lang") === "ne" ? "ne" : "en";
  const title = lang === "ne" && page.title_ne ? page.title_ne : page.title_en;
  const desc =
    lang === "ne" && page.description_ne
      ? page.description_ne
      : page.description_en || "";
  const commentsOn = settings.comments_enabled !== "0";
  const widget = commentsOn ? commentsWidgetHtml(page.slug) : "";
  const isZip = String(page.template || "").startsWith("zip:");
  if (isZip && env.MEDIA) {
    const entry = String(page.template).slice(4) || "index.html";
    const obj = await env.MEDIA.get(`pages/${page.slug}/${entry}`);
    if (!obj) {
      return new Response(
        `ZIP page missing entry: ${entry}. Re-upload the package.`,
        { status: 404 }
      );
    }
    let html = await obj.text();
    const base = `/_p/${page.slug}/`;
    if (/<base\s/i.test(html)) {
      html = html.replace(/<base[^>]*>/i, `<base href="${base}">`);
    } else if (/<head[^>]*>/i.test(html)) {
      html = html.replace(/<head[^>]*>/i, (m) => `${m}\n<base href="${base}">`);
    } else {
      html = `<base href="${base}">` + html;
    }
    if (widget) {
      if (/<\/body>/i.test(html))
        html = html.replace(/<\/body>/i, widget + "\n</body>");
      else html += widget;
    }
    return new Response(html, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "public, max-age=30",
      },
    });
  }
  const body = `<section class="page-hero"><div class="wrap"><h1>${escapeHtml( title )}</h1>${ desc ? `<p>${escapeHtml(desc)}</p>` : "" }</div></section><article class="wrap">${renderBlocks( page.content )}</article>${widget}`;
  return new Response(pageChrome(title, desc, body, settings, lang), {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=60",
    },
  });
}
