/**
 * Granshi CMS Worker v3
 * Free-tier: Workers + D1 + R2
 * Drag-drop page builder + marketplace-ready APIs
 */

const enc = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });

async function hmac(secret, value) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC", k, enc.encode(value)));
}

async function passwordHash(password, salt = b64(crypto.getRandomValues(new Uint8Array(16)))) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: unb64(salt), iterations: 180000, hash: "SHA-256" }, key, 256);
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
  const payload = b64(enc.encode(JSON.stringify({ email, exp: Date.now() + 7 * 86400000 })));
  return payload + "." + (await hmac(env.SESSION_SECRET, payload));
}

async function auth(req, env) {
  try {
    const [p, s] = cookie(req, "granshi_session").split(".");
    if (!p || !s || (await hmac(env.SESSION_SECRET, p)) !== s) return null;
    const v = JSON.parse(new TextDecoder().decode(unb64(p)));
    if (v.exp < Date.now()) return null;
    const a = await env.DB.prepare("SELECT email FROM admins WHERE email=?").bind(v.email).first();
    return a ? a.email : null;
  } catch {
    return null;
  }
}

const sessionCookie = (token) =>
  `granshi_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
const clearCookie = "granshi_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";

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

/* ---------- Public data ---------- */
async function getSettings(env) {
  const r = await env.DB.prepare("SELECT key,value FROM settings").all();
  return Object.fromEntries((r.results || []).map((x) => [x.key, x.value]));
}

async function allPublic(env) {
  const [settings, pages, depts, menus, products, categories] = await Promise.all([
    getSettings(env),
    env.DB.prepare(
      "SELECT slug,title_en,title_ne,description_en,description_ne,content,template,updated_at FROM pages WHERE published=1 ORDER BY sort_order,title_en"
    ).all(),
    env.DB.prepare(
      "SELECT id,name_en,name_ne,description_en,description_ne,url,icon,email,image,sort_order FROM departments WHERE visible=1 ORDER BY sort_order"
    ).all(),
    env.DB.prepare("SELECT id,label_en,label_ne,url,parent_id,sort_order FROM menus WHERE visible=1 ORDER BY sort_order").all(),
    env.DB.prepare(
      "SELECT id,name_en,name_ne,slug,price,compare_price,currency,image,status,featured FROM products WHERE status='published' ORDER BY sort_order,name_en LIMIT 50"
    ).all(),
    env.DB.prepare("SELECT id,name_en,name_ne,slug,image FROM categories WHERE visible=1 ORDER BY sort_order").all(),
  ]);
  return {
    settings,
    pages: pages.results || [],
    departments: depts.results || [],
    menus: menus.results || [],
    products: products.results || [],
    categories: categories.results || [],
  };
}

/* ---------- Block renderer ---------- */
function renderBlocks(content, settings = {}) {
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
        return `<h${level} class="blk-h">${escapeHtml(b.text || "")}</h${level}>`;
      }
      if (t === "paragraph") return `<p class="blk-p">${escapeHtml(b.text || "").replace(/\n/g, "<br>")}</p>`;
      if (t === "image" && b.url) {
        return `<figure class="blk-img"><img src="${escapeHtml(b.url)}" alt="${escapeHtml(b.alt || "")}" loading="lazy">${
          b.caption ? `<figcaption>${escapeHtml(b.caption)}</figcaption>` : ""
        }</figure>`;
      }
      if (t === "button" && b.url)
        return `<p class="blk-btn"><a class="btn" href="${escapeHtml(b.url)}" ${b.newtab ? 'target="_blank" rel="noopener"' : ""}>${escapeHtml(
          b.text || "Learn more"
        )}</a></p>`;
      if (t === "html") return `<div class="blk-html">${b.html || ""}</div>`;
      if (t === "spacer") return `<div class="blk-spacer" style="height:${Number(b.height) || 32}px"></div>`;
      if (t === "divider") return `<hr class="blk-hr">`;
      if (t === "quote")
        return `<blockquote class="blk-quote"><p>${escapeHtml(b.text || "")}</p>${
          b.cite ? `<cite>${escapeHtml(b.cite)}</cite>` : ""
        }</blockquote>`;
      if (t === "columns") {
        const cols = Array.isArray(b.columns) ? b.columns : [];
        return `<div class="blk-cols" style="--cols:${cols.length || 2}">${cols
          .map((c) => `<div class="blk-col">${escapeHtml(c.text || "").replace(/\n/g, "<br>")}</div>`)
          .join("")}</div>`;
      }
      if (t === "cards") {
        const cards = Array.isArray(b.cards) ? b.cards : [];
        return `<div class="blk-cards">${cards
          .map(
            (c) =>
              `<article class="blk-card">${c.icon ? `<div class="ico">${escapeHtml(c.icon)}</div>` : ""}${
                c.image ? `<img src="${escapeHtml(c.image)}" alt="">` : ""
              }<h3>${escapeHtml(c.title || "")}</h3><p>${escapeHtml(c.text || "")}</p>${
                c.url ? `<a href="${escapeHtml(c.url)}">${escapeHtml(c.linktext || "→")}</a>` : ""
              }</article>`
          )
          .join("")}</div>`;
      }
      if (t === "hero") {
        return `<section class="blk-hero" style="background-image:url('${escapeHtml(b.image || settings.hero_image || "")}')">
          <div class="blk-hero-inner"><h1>${escapeHtml(b.title || "")}</h1><p>${escapeHtml(b.subtitle || "")}</p>
          ${b.button_url ? `<a class="btn" href="${escapeHtml(b.button_url)}">${escapeHtml(b.button_text || "Explore")}</a>` : ""}
          </div></section>`;
      }
      if (t === "video" && b.url) {
        const src = escapeHtml(b.url);
        if (src.includes("youtube") || src.includes("youtu.be") || src.includes("vimeo")) {
          return `<div class="blk-video"><iframe src="${src}" frameborder="0" allowfullscreen loading="lazy"></iframe></div>`;
        }
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
  const heroImg = settings.hero_image || "/assets-brand.png";
  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} · ${escapeHtml(brand)}</title>
<meta name="description" content="${escapeHtml(desc || "")}">
<meta property="og:title" content="${escapeHtml(title)}">
<meta property="og:description" content="${escapeHtml(desc || "")}">
<meta property="og:image" content="${escapeHtml(heroImg)}">
<meta name="theme-color" content="${escapeHtml(primary)}">
<style>
:root{--navy:${escapeHtml(primary)};--gold:${escapeHtml(accent)};--paper:#f6f7fb;--ink:#172033;--muted:#667085}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);background:var(--paper)}
a{text-decoration:none;color:inherit}.wrap{width:min(960px,92%);margin:auto}
header{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--navy) 96%,transparent);color:#fff;border-bottom:1px solid #ffffff20;backdrop-filter:blur(8px)}
.nav{height:64px;display:flex;align-items:center;justify-content:space-between}
.brand{display:flex;align-items:center;gap:10px;font-weight:900;letter-spacing:1px}
.mark{border:2px solid var(--gold);border-radius:12px;width:38px;height:38px;display:grid;place-items:center;color:var(--gold)}
.btn{display:inline-block;padding:12px 18px;border-radius:10px;font-weight:700;background:linear-gradient(135deg,#f3dfa9,var(--gold));color:#182235}
.page-hero{background:var(--navy);color:#fff;padding:48px 0 36px}
.page-hero h1{margin:0;font-size:clamp(28px,5vw,42px)}.page-hero p{color:#c7d0dc;margin:12px 0 0}
article{padding:36px 0 60px}
.blk-h{margin:28px 0 12px}.blk-p{line-height:1.75;color:#334}
.blk-img{margin:24px 0}.blk-img img{max-width:100%;border-radius:12px;display:block}
.blk-img figcaption{font-size:13px;color:var(--muted);margin-top:8px}
.blk-quote{border-left:4px solid var(--gold);margin:24px 0;padding:8px 20px;background:#fff;border-radius:0 12px 12px 0}
.blk-quote cite{display:block;margin-top:8px;font-size:13px;color:var(--muted)}
.blk-hr{border:0;border-top:1px solid #e2e6ef;margin:28px 0}
.blk-cols{display:grid;grid-template-columns:repeat(var(--cols,2),1fr);gap:20px;margin:20px 0}
.blk-col{background:#fff;padding:18px;border-radius:12px;border:1px solid #e8ecf3;line-height:1.6}
.blk-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px;margin:20px 0}
.blk-card{background:#fff;border:1px solid #e8ecf3;border-radius:14px;padding:18px}
.blk-card img{width:100%;border-radius:10px;margin-bottom:10px}
.blk-card h3{margin:0 0 6px;font-size:17px}.blk-card p{margin:0;color:var(--muted);font-size:14px}
.blk-card a{display:inline-block;margin-top:10px;color:#8a6b2a;font-weight:700;font-size:13px}
.blk-hero{min-height:320px;background-size:cover;background-position:center;color:#fff;display:flex;align-items:center;border-radius:16px;overflow:hidden;margin:12px 0 28px;position:relative}
.blk-hero:before{content:"";position:absolute;inset:0;background:linear-gradient(90deg,#101a2ce0,#101a2c66)}
.blk-hero-inner{position:relative;padding:40px;max-width:640px}
.blk-hero h1{margin:0 0 10px;font-size:clamp(26px,4vw,40px)}
.blk-video{position:relative;padding-bottom:56.25%;height:0;margin:20px 0;border-radius:12px;overflow:hidden}
.blk-video iframe,.blk-video video{position:absolute;inset:0;width:100%;height:100%}
footer{background:var(--navy);color:#aab;padding:24px 0;font-size:14px;text-align:center}
@media(max-width:700px){.blk-cols{grid-template-columns:1fr}}
</style>
</head>
<body>
<header><div class="wrap nav">
  <a class="brand" href="/"><span class="mark">G</span><span>GRANSHI</span></a>
  <a class="btn" href="/">← Home</a>
</div></header>
${bodyHtml}
<footer><div class="wrap">${escapeHtml(settings.footer_text || "© Granshi")}</div></footer>
</body></html>`;
}

function renderPageHtml(page, settings, lang = "en") {
  const title = lang === "ne" && page.title_ne ? page.title_ne : page.title_en;
  const desc = lang === "ne" && page.description_ne ? page.description_ne : page.description_en || "";
  const body = `<section class="page-hero"><div class="wrap"><h1>${escapeHtml(title)}</h1>${
    desc ? `<p>${escapeHtml(desc)}</p>` : ""
  }</div></section><article class="wrap">${renderBlocks(page.content, settings)}</article>`;
  return pageChrome(title, desc, body, settings, lang);
}

/* ---------- Email (optional Resend) ---------- */
async function sendEmail(env, { to, subject, html, replyTo }) {
  if (!env.RESEND_API_KEY || !to) return { sent: false, reason: "no_api_key_or_to" };
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "Granshi <noreply@gopalkoirala.com.np>",
        to: [to],
        subject,
        html,
        reply_to: replyTo || undefined,
      }),
    });
    if (!res.ok) return { sent: false, reason: await res.text() };
    return { sent: true };
  } catch (e) {
    return { sent: false, reason: String(e) };
  }
}

/* ---------- API ---------- */
async function api(req, env) {
  const u = new URL(req.url);
  const p = u.pathname;
  const method = req.method;

  if (p === "/api/health") return json({ ok: true, service: "Granshi CMS v3", database: !!env.DB, media: !!env.MEDIA });
  if (p === "/api/public" && method === "GET") return json(await allPublic(env));

  // Contact
  if (p === "/api/contact" && method === "POST") {
    const x = await body(req);
    const name = String(x.name || "").trim().slice(0, 120);
    const email = String(x.email || "").trim().slice(0, 180);
    const subject = String(x.subject || "").trim().slice(0, 200);
    const msg = String(x.body || x.message || "").trim().slice(0, 5000);
    const departmentId = x.department_id ? Number(x.department_id) : null;
    if (!name || !email || !msg) return json({ error: "Name, email and message are required." }, 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Invalid email." }, 400);

    let deptEmail = null,
      deptName = null;
    if (departmentId) {
      const d = await env.DB.prepare("SELECT name_en,email FROM departments WHERE id=? AND visible=1").bind(departmentId).first();
      if (d) {
        deptEmail = d.email || null;
        deptName = d.name_en;
      }
    }
    await env.DB.prepare("INSERT INTO messages(department_id,name,email,subject,body,status,created_at) VALUES(?,?,?,?,?,?,?)")
      .bind(departmentId, name, email, subject || "Contact form", msg, "new", new Date().toISOString())
      .run();

    const settings = await getSettings(env);
    const target = deptEmail || settings.contact_email || null;
    let emailResult = { sent: false };
    if (target) {
      emailResult = await sendEmail(env, {
        to: target,
        subject: `[Granshi] ${subject || "New message"} — ${name}`,
        replyTo: email,
        html: `<p><b>From:</b> ${escapeHtml(name)} &lt;${escapeHtml(email)}&gt;</p>
               <p><b>Department:</b> ${escapeHtml(deptName || "General")}</p>
               <p><b>Subject:</b> ${escapeHtml(subject || "-")}</p><hr>
               <p>${escapeHtml(msg).replace(/\n/g, "<br>")}</p>`,
      });
    }
    return json({ ok: true, emailed: emailResult.sent });
  }

  // Setup + Auth
  if (p === "/api/setup/status" && method === "GET") {
    const x = await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first();
    return json({ initialized: (x?.n || 0) > 0 });
  }
  if (p === "/api/setup" && method === "POST") {
    const x = await body(req);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first();
    if ((count?.n || 0) > 0) return json({ error: "Admin already initialized." }, 409);
    if (!env.SETUP_TOKEN || x.setupToken !== env.SETUP_TOKEN) return json({ error: "Invalid setup token." }, 403);
    if (!x.email || !x.password || String(x.password).length < 12)
      return json({ error: "Email + password (12+ chars) required." }, 400);
    const h = await passwordHash(String(x.password));
    await env.DB.prepare("INSERT INTO admins(email,salt,password_hash,created_at) VALUES(?,?,?,?)")
      .bind(String(x.email).toLowerCase(), h.salt, h.hash, new Date().toISOString())
      .run();
    return json({ ok: true }, 200, { "set-cookie": sessionCookie(await sessionToken(env, String(x.email).toLowerCase())) });
  }
  if (p === "/api/auth/login" && method === "POST") {
    const x = await body(req);
    const a = await env.DB.prepare("SELECT email,salt,password_hash FROM admins WHERE email=?")
      .bind(String(x.email || "").toLowerCase())
      .first();
    if (!a || !(await verifyPassword(String(x.password || ""), a.salt, a.password_hash)))
      return json({ error: "Email or password incorrect." }, 401);
    return json({ ok: true }, 200, { "set-cookie": sessionCookie(await sessionToken(env, a.email)) });
  }
  if (p === "/api/auth/logout" && method === "POST") return json({ ok: true }, 200, { "set-cookie": clearCookie });

  const who = await auth(req, env);
  if (!who) return json({ error: "Please log in." }, 401);
  if (p === "/api/auth/me") return json({ email: who });
  if (p === "/api/admin/overview") {
    const pub = await allPublic(env);
    const msgNew = await env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE status='new'").first();
    const prodCount = await env.DB.prepare("SELECT COUNT(*) AS n FROM products").first();
    return json({ email: who, new_messages: msgNew?.n || 0, product_count: prodCount?.n || 0, ...pub });
  }

  // Pages
  if (p === "/api/admin/pages" && method === "GET") {
    const r = await env.DB.prepare("SELECT * FROM pages ORDER BY sort_order,updated_at DESC").all();
    return json(r.results || []);
  }
  if (p === "/api/admin/pages" && method === "POST") {
    const x = await body(req);
    const slug = slugify(x.slug || x.title_en);
    if (!slug || !x.title_en) return json({ error: "Title and slug required." }, 400);
    await env.DB.prepare(
      `INSERT INTO pages(slug,title_en,title_ne,description_en,description_ne,content,template,published,sort_order,updated_at)
       VALUES(?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(slug) DO UPDATE SET
         title_en=excluded.title_en,title_ne=excluded.title_ne,
         description_en=excluded.description_en,description_ne=excluded.description_ne,
         content=excluded.content,template=excluded.template,published=excluded.published,
         sort_order=excluded.sort_order,updated_at=excluded.updated_at`
    )
      .bind(
        slug,
        x.title_en,
        x.title_ne || "",
        x.description_en || "",
        x.description_ne || "",
        JSON.stringify(x.content || []),
        x.template || "default",
        x.published ? 1 : 0,
        Number(x.sort_order || 0),
        new Date().toISOString()
      )
      .run();
    return json({ ok: true, slug });
  }
  if (p.startsWith("/api/admin/pages/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM pages WHERE slug=?").bind(decodeURIComponent(p.split("/").pop())).run();
    return json({ ok: true });
  }

  // Departments
  if (p === "/api/admin/departments" && method === "GET") {
    return json((await env.DB.prepare("SELECT * FROM departments ORDER BY sort_order").all()).results || []);
  }
  if (p === "/api/admin/departments" && method === "POST") {
    const x = await body(req);
    if (x.id) {
      await env.DB.prepare(
        "UPDATE departments SET name_en=?,name_ne=?,description_en=?,description_ne=?,url=?,icon=?,email=?,image=?,visible=?,sort_order=? WHERE id=?"
      )
        .bind(x.name_en, x.name_ne || "", x.description_en || "", x.description_ne || "", x.url || "#", x.icon || "✦", x.email || "", x.image || "", x.visible ? 1 : 0, Number(x.sort_order || 0), x.id)
        .run();
    } else {
      await env.DB.prepare(
        "INSERT INTO departments(name_en,name_ne,description_en,description_ne,url,icon,email,image,visible,sort_order) VALUES(?,?,?,?,?,?,?,?,?,?)"
      )
        .bind(x.name_en, x.name_ne || "", x.description_en || "", x.description_ne || "", x.url || "#", x.icon || "✦", x.email || "", x.image || "", x.visible === false ? 0 : 1, Number(x.sort_order || 0))
        .run();
    }
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/departments/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM departments WHERE id=?").bind(p.split("/").pop()).run();
    return json({ ok: true });
  }

  // Menus
  if (p === "/api/admin/menus" && method === "GET") {
    return json((await env.DB.prepare("SELECT * FROM menus ORDER BY sort_order").all()).results || []);
  }
  if (p === "/api/admin/menus" && method === "POST") {
    const x = await body(req);
    if (x.id)
      await env.DB.prepare("UPDATE menus SET label_en=?,label_ne=?,url=?,parent_id=?,visible=?,sort_order=? WHERE id=?")
        .bind(x.label_en, x.label_ne || "", x.url || "#", x.parent_id || null, x.visible ? 1 : 0, Number(x.sort_order || 0), x.id)
        .run();
    else
      await env.DB.prepare("INSERT INTO menus(label_en,label_ne,url,parent_id,visible,sort_order) VALUES(?,?,?,?,?,?)")
        .bind(x.label_en, x.label_ne || "", x.url || "#", x.parent_id || null, 1, Number(x.sort_order || 0))
        .run();
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/menus/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM menus WHERE id=?").bind(p.split("/").pop()).run();
    return json({ ok: true });
  }

  // Settings
  if (p === "/api/admin/settings" && method === "POST") {
    const x = await body(req);
    for (const [k, v] of Object.entries(x)) {
      await env.DB.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(k, String(v))
        .run();
    }
    return json({ ok: true });
  }

  // Media
  if (p === "/api/admin/media" && method === "GET") {
    return json((await env.DB.prepare("SELECT * FROM media ORDER BY created_at DESC").all()).results || []);
  }
  if (p === "/api/admin/media/upload" && method === "POST") {
    if (!env.MEDIA) return json({ error: "R2 not configured." }, 503);
    const file = await req.arrayBuffer();
    const type = req.headers.get("content-type") || "application/octet-stream";
    const name = decodeURIComponent(req.headers.get("x-file-name") || "upload.bin").replace(/[^a-zA-Z0-9._-]/g, "_");
    if (file.byteLength > 25 * 1024 * 1024) return json({ error: "Max 25 MB." }, 413);
    const key = `uploads/${crypto.randomUUID()}-${name}`;
    await env.MEDIA.put(key, file, { httpMetadata: { contentType: type } });
    const url = `/media/${key}`;
    await env.DB.prepare("INSERT INTO media(key,name,url,content_type,size,created_at) VALUES(?,?,?,?,?,?)")
      .bind(key, name, url, type, file.byteLength, new Date().toISOString())
      .run();
    return json({ ok: true, key, url });
  }
  if (p.startsWith("/api/admin/media/") && method === "DELETE") {
    const key = decodeURIComponent(p.split("/").pop());
    if (env.MEDIA) await env.MEDIA.delete(key);
    await env.DB.prepare("DELETE FROM media WHERE key=?").bind(key).run();
    return json({ ok: true });
  }

  // Messages
  if (p === "/api/admin/messages" && method === "GET") {
    return json(
      (
        await env.DB.prepare(
          `SELECT m.*, d.name_en AS department_name FROM messages m LEFT JOIN departments d ON d.id=m.department_id ORDER BY m.created_at DESC LIMIT 300`
        ).all()
      ).results || []
    );
  }
  if (p.startsWith("/api/admin/messages/") && method === "POST") {
    const x = await body(req);
    if (x.status) await env.DB.prepare("UPDATE messages SET status=? WHERE id=?").bind(x.status, p.split("/").pop()).run();
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/messages/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM messages WHERE id=?").bind(p.split("/").pop()).run();
    return json({ ok: true });
  }

  // Password
  if (p === "/api/admin/password" && method === "POST") {
    const x = await body(req);
    if (String(x.newPassword || "").length < 12) return json({ error: "Min 12 characters." }, 400);
    const old = await env.DB.prepare("SELECT salt,password_hash FROM admins WHERE email=?").bind(who).first();
    if (!old || !(await verifyPassword(String(x.currentPassword || ""), old.salt, old.password_hash)))
      return json({ error: "Current password incorrect." }, 401);
    const h = await passwordHash(x.newPassword);
    await env.DB.prepare("UPDATE admins SET salt=?,password_hash=? WHERE email=?").bind(h.salt, h.hash, who).run();
    return json({ ok: true });
  }

  // ---- Marketplace (ready) ----
  if (p === "/api/admin/categories" && method === "GET") {
    return json((await env.DB.prepare("SELECT * FROM categories ORDER BY sort_order").all()).results || []);
  }
  if (p === "/api/admin/categories" && method === "POST") {
    const x = await body(req);
    const slug = slugify(x.slug || x.name_en);
    if (!x.name_en || !slug) return json({ error: "Name required." }, 400);
    if (x.id) {
      await env.DB.prepare(
        "UPDATE categories SET name_en=?,name_ne=?,slug=?,description_en=?,description_ne=?,image=?,parent_id=?,visible=?,sort_order=? WHERE id=?"
      )
        .bind(x.name_en, x.name_ne || "", slug, x.description_en || "", x.description_ne || "", x.image || "", x.parent_id || null, x.visible ? 1 : 0, Number(x.sort_order || 0), x.id)
        .run();
    } else {
      await env.DB.prepare(
        "INSERT INTO categories(name_en,name_ne,slug,description_en,description_ne,image,parent_id,visible,sort_order) VALUES(?,?,?,?,?,?,?,?,?)"
      )
        .bind(x.name_en, x.name_ne || "", slug, x.description_en || "", x.description_ne || "", x.image || "", x.parent_id || null, 1, Number(x.sort_order || 0))
        .run();
    }
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/categories/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM categories WHERE id=?").bind(p.split("/").pop()).run();
    return json({ ok: true });
  }

  if (p === "/api/admin/products" && method === "GET") {
    return json((await env.DB.prepare("SELECT * FROM products ORDER BY sort_order,updated_at DESC").all()).results || []);
  }
  if (p === "/api/admin/products" && method === "POST") {
    const x = await body(req);
    const slug = slugify(x.slug || x.name_en);
    if (!x.name_en || !slug) return json({ error: "Name required." }, 400);
    const now = new Date().toISOString();
    if (x.id) {
      await env.DB.prepare(
        `UPDATE products SET name_en=?,name_ne=?,slug=?,description_en=?,description_ne=?,price=?,compare_price=?,currency=?,image=?,images=?,category_id=?,stock=?,sku=?,status=?,featured=?,sort_order=?,updated_at=? WHERE id=?`
      )
        .bind(
          x.name_en, x.name_ne || "", slug, x.description_en || "", x.description_ne || "",
          Number(x.price || 0), x.compare_price != null ? Number(x.compare_price) : null, x.currency || "NPR",
          x.image || "", JSON.stringify(x.images || []), x.category_id || null, Number(x.stock || 0), x.sku || "",
          x.status || "draft", x.featured ? 1 : 0, Number(x.sort_order || 0), now, x.id
        )
        .run();
    } else {
      await env.DB.prepare(
        `INSERT INTO products(name_en,name_ne,slug,description_en,description_ne,price,compare_price,currency,image,images,category_id,stock,sku,status,featured,sort_order,created_at,updated_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      )
        .bind(
          x.name_en, x.name_ne || "", slug, x.description_en || "", x.description_ne || "",
          Number(x.price || 0), x.compare_price != null ? Number(x.compare_price) : null, x.currency || "NPR",
          x.image || "", JSON.stringify(x.images || []), x.category_id || null, Number(x.stock || 0), x.sku || "",
          x.status || "draft", x.featured ? 1 : 0, Number(x.sort_order || 0), now, now
        )
        .run();
    }
    return json({ ok: true, slug });
  }
  if (p.startsWith("/api/admin/products/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM products WHERE id=?").bind(p.split("/").pop()).run();
    return json({ ok: true });
  }

  if (p === "/api/admin/orders" && method === "GET") {
    return json((await env.DB.prepare("SELECT * FROM orders ORDER BY created_at DESC LIMIT 200").all()).results || []);
  }
  if (p.startsWith("/api/admin/orders/") && method === "POST") {
    const x = await body(req);
    if (x.status)
      await env.DB.prepare("UPDATE orders SET status=?,updated_at=? WHERE id=?")
        .bind(x.status, new Date().toISOString(), p.split("/").pop())
        .run();
    return json({ ok: true });
  }

  return json({ error: "API route not found." }, 404);
}

/* ---------- Main ---------- */
export default {
  async fetch(req, env) {
    const u = new URL(req.url);

    if (u.pathname.startsWith("/api/")) {
      try {
        return await api(req, env);
      }
    } catch (e) {
  console.error("GRANSHI API ERROR:", e?.stack || e);
  return json({ error: "Server error" }, 500);
}
    if (u.pathname.startsWith("/media/")) {
      if (!env.MEDIA) return new Response("Media not configured", { status: 503 });
      const key = u.pathname.slice(7);
      const obj = await env.MEDIA.get(key);
      if (!obj) return new Response("Not found", { status: 404 });
      const h = new Headers();
      obj.writeHttpMetadata(h);
      h.set("etag", obj.httpEtag);
      h.set("cache-control", "public, max-age=86400");
      return new Response(obj.body, { headers: h });
    }

    // CMS page SSR
    if (u.pathname !== "/" && !u.pathname.startsWith("/admin") && !u.pathname.includes(".")) {
      const slug = u.pathname.slice(1).replace(/\/$/, "");
      if (slug) {
        try {
          const page = await env.DB.prepare("SELECT * FROM pages WHERE slug=? AND published=1").bind(slug).first();
          if (page) {
            const settings = await getSettings(env);
            const lang = u.searchParams.get("lang") === "ne" ? "ne" : "en";
            return new Response(renderPageHtml(page, settings, lang), {
              headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=60" },
            });
          }
          // Product page (marketplace ready)
          const product = await env.DB.prepare("SELECT * FROM products WHERE slug=? AND status='published'").bind(slug).first();
          if (product) {
            const settings = await getSettings(env);
            const lang = u.searchParams.get("lang") === "ne" ? "ne" : "en";
            const title = lang === "ne" && product.name_ne ? product.name_ne : product.name_en;
            const desc = lang === "ne" && product.description_ne ? product.description_ne : product.description_en || "";
            const body = `<section class="page-hero"><div class="wrap"><h1>${escapeHtml(title)}</h1>
              <p style="font-size:22px;color:var(--gold);margin-top:12px">${escapeHtml(String(product.price))} ${escapeHtml(product.currency || "NPR")}</p>
              ${desc ? `<p>${escapeHtml(desc)}</p>` : ""}</div></section>
              <article class="wrap">${product.image ? `<figure class="blk-img"><img src="${escapeHtml(product.image)}" alt="${escapeHtml(title)}"></figure>` : ""}
              <p class="blk-p">${escapeHtml(desc).replace(/\n/g, "<br>")}</p></article>`;
            return new Response(pageChrome(title, desc, body, settings, lang), {
              headers: { "content-type": "text/html; charset=utf-8" },
            });
          }
        } catch (_) {}
      }
    }

    return env.ASSETS.fetch(req);
  },
};
