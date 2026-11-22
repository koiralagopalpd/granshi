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
async function passwordHash( password, salt = b64(crypto.getRandomValues(new Uint8Array(16))), iterations = 100000 ) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: unb64(salt), iterations, hash: "SHA-256" },
    key,
    256
  );
  const prefix = iterations === 100000 ? "v2:" : "";
  return { salt, hash: prefix + b64(bits) };
}
async function verifyPassword(password, salt, storedHash) {
  const isV2 = String(storedHash || "").startsWith("v2:");
  const iterations = isV2 ? 100000 : 10000;
  const x = await passwordHash(password, salt, iterations);
  return x.hash === storedHash;
}
function cookie(req, name) {
  const c = req.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : "";
}
async function sessionToken(env, email) {
  const admin = await env.DB.prepare("SELECT session_version FROM admins WHERE email=?").bind(email).first();
  const payload = b64(enc.encode(JSON.stringify({ email, version: Number(admin?.session_version || 0), exp: Date.now() + 7 * 86400000 })));
  return payload + "." + (await hmac(env.SESSION_SECRET, payload));
}
async function auth(req, env) {
  try {
    const [p, s] = cookie(req, "granshi_session").split(".");
    if (!p || !s || (await hmac(env.SESSION_SECRET, p)) !== s) return null;
    const v = JSON.parse(new TextDecoder().decode(unb64(p)));
    if (v.exp < Date.now()) return null;
    const a = await env.DB.prepare("SELECT email,session_version,locked_at FROM admins WHERE email=?").bind(v.email).first();
    if (!a || a.locked_at || Number(v.version) !== Number(a.session_version || 0)) return null;
    return a.email;
  } catch { return null; }
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
async function ensurePushTable(env) {
  if (!env.DB) return;
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS push_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_email TEXT NOT NULL, endpoint TEXT NOT NULL UNIQUE, p256dh TEXT NOT NULL, auth TEXT NOT NULL, user_agent TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
  ).run();
}
function concatUint8(...arrays) {
  const len = arrays.reduce((acc, a) => acc + a.byteLength, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.byteLength;
  }
  return out;
}
async function hmacSha256Raw(keyBytes, dataBytes) {
  const k = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, dataBytes));
}
async function hkdfExpandSingle(prk, info, length) {
  const out = await hmacSha256Raw(prk, concatUint8(info, new Uint8Array([1])));
  return out.slice(0, length);
}
function getVapidConfig(env) {
  const publicKey = String(env.VAPID_PUBLIC_KEY || "").trim();
  const privateKey = String(env.VAPID_PRIVATE_KEY || "").trim();
  const subject = String(env.VAPID_SUBJECT || "mailto:info@gopalkoirala.com.np").trim() || "mailto:info@gopalkoirala.com.np";
  return { publicKey, privateKey, subject, configured: Boolean(publicKey && privateKey) };
}
function isSafePushEndpoint(rawUrl) {
  try {
    const parsed = new URL(String(rawUrl || ""));
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
    if (!host || host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".local")) return false;
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.)/.test(host)) return false;
    return true;
  } catch {
    return false;
  }
}
async function importVapidPrivateKey(publicKeyB64, privateKeyB64) {
  const pubRaw = unb64(publicKeyB64);
  if (pubRaw.length !== 65 || pubRaw[0] !== 4) {
    throw new Error("VAPID_PUBLIC_KEY must be an uncompressed 65-byte P-256 key.");
  }
  const privRaw = unb64(privateKeyB64);
  if (privRaw.length !== 32) {
    throw new Error("VAPID_PRIVATE_KEY must be a 32-byte P-256 private key.");
  }
  const x = b64(pubRaw.slice(1, 33));
  const y = b64(pubRaw.slice(33, 65));
  const d = b64(privRaw);
  return await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x, y, d, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}
async function createVapidJwt(endpointUrl, vapidKey, subject) {
  const aud = new URL(endpointUrl).origin;
  const exp = Math.floor(Date.now() / 1000) + 12 * 3600;
  const header = b64(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64(enc.encode(JSON.stringify({ aud, exp, sub: subject })));
  const input = `${header}.${claims}`;
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, vapidKey, enc.encode(input));
  return `${input}.${b64(sig)}`;
}
async function encryptWebPushPayload(sub, payloadText) {
  const uaPub = unb64(sub.p256dh);
  const authSecret = unb64(sub.auth);
  if (uaPub.length !== 65 || uaPub[0] !== 4) throw new Error("Invalid subscription p256dh key.");
  if (authSecret.length !== 16) throw new Error("Invalid subscription auth secret.");
  const asPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", asPair.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asPair.privateKey, 256));
  const prkKey = await hmacSha256Raw(authSecret, sharedSecret);
  const keyInfo = concatUint8(enc.encode("WebPush: info\0"), uaPub, asPub);
  const ikm = await hkdfExpandSingle(prkKey, keyInfo, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmacSha256Raw(salt, ikm);
  const cek = await hkdfExpandSingle(prk, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdfExpandSingle(prk, enc.encode("Content-Encoding: nonce\0"), 12);
  const aesKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const plaintext = concatUint8(enc.encode(payloadText), new Uint8Array([2]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, aesKey, plaintext));
  const header = new Uint8Array(21 + asPub.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096, false);
  header[20] = asPub.length;
  header.set(asPub, 21);
  return concatUint8(header, ciphertext);
}
async function notifyAdminsPush(env, payloadObj) {
  const cfg = getVapidConfig(env);
  if (!cfg.configured || !env.DB) return { attempted: 0, sent: 0, removed: 0, error: "VAPID secrets not set." };
  await ensurePushTable(env);
  const subs = await safeAll(env, "SELECT * FROM push_subscriptions ORDER BY updated_at DESC LIMIT 25");
  if (!subs.length) return { attempted: 0, sent: 0, removed: 0, error: "No subscribed devices." };
  const vapidKey = await importVapidPrivateKey(cfg.publicKey, cfg.privateKey);
  const payloadText = JSON.stringify(payloadObj || {});
  let sent = 0, removed = 0;
  const details = [];
  await Promise.all(subs.map(async (sub) => {
    try {
      if (!isSafePushEndpoint(sub.endpoint)) throw new Error("Unsafe push endpoint");
      const jwt = await createVapidJwt(sub.endpoint, vapidKey, cfg.subject);
      const bodyBytes = await encryptWebPushPayload(sub, payloadText);
      const res = await fetch(sub.endpoint, {
        method: "POST",
        headers: {
          "authorization": `vapid t=${jwt}, k=${cfg.publicKey}`,
          "content-encoding": "aes128gcm",
          "content-type": "application/octet-stream",
          "ttl": "86400",
          "urgency": "high"
        },
        body: bodyBytes,
        signal: AbortSignal.timeout(6500)
      });
      if (res.status >= 200 && res.status < 300) {
        sent++;
        details.push({ status: res.status, ok: true });
      } else if (res.status === 404 || res.status === 410) {
        removed++;
        await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint=?").bind(sub.endpoint).run().catch(() => {});
        details.push({ status: res.status, removed: true });
      } else {
        const errText = await res.text().catch(() => "");
        details.push({ status: res.status, error: errText.slice(0, 120) });
      }
    } catch (e) {
      details.push({ error: String(e).slice(0, 120) });
    }
  }));
  return { attempted: subs.length, sent, removed, details };
}
function queueAdminPush(ctx, env, payloadObj) {
  const work = notifyAdminsPush(env, payloadObj).catch(() => {});
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(work);
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
    }).join(" ").replace(/<[^>]*>/g," ").replace(/\s+/g," ").trim().slice(0,30000);
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
  let source = String(text || "");
  try { const parsed=JSON.parse(source); if(Array.isArray(parsed)) source=searchablePageText(parsed); } catch {}
  const clean = source.replace(/\s+/g," ").trim();
  if (!clean) return "";
  const terms = query.toLowerCase().split(/\s+/).filter(x=>x.length>1);
  let at = -1;
  for (const term of terms) { at = clean.toLowerCase().indexOf(term); if (at >= 0) break; }
  const start = Math.max(0, (at < 0 ? 0 : at) - 100);
  return (start ? "…" : "") + clean.slice(start,start+360) + (start+360<clean.length ? "…" : "");
}

async function ensureQaTable(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS site_qa_index (id INTEGER PRIMARY KEY AUTOINCREMENT, page_slug TEXT NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL, keywords TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)"
  ).run();
}

function decodeBasicEntities(s) {
  return String(s || "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&quot;/gi, '"')
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractQaPairsFromPage(page, searchText, rawHtml = "") {
  const pairs = [];
  const seenQ = new Set();
  const slug = String(page.slug || "");
  const titleEn = String(page.title_en || slug).trim();
  const titleNe = String(page.title_ne || "").trim();
  const descEn = String(page.description_en || page.thumbnail_summary_en || "").trim();
  const descNe = String(page.description_ne || page.thumbnail_summary_ne || "").trim();
  const bodyClean = String(searchText || "").replace(/\s+/g, " ").trim();
  const title = titleEn || titleNe || slug;
  const pageUrl = "/" + encodeURIComponent(slug);
  const kwList = [...new Set((title + " " + titleNe + " " + descEn + " " + bodyClean.slice(0, 1200))
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((w) => w.length > 2))].slice(0, 45).join(" ");

  const pushQa = (q, a) => {
    const cleanQ = String(q || "").replace(/\s+/g, " ").trim().slice(0, 220);
    const cleanA = String(a || "").replace(/\s+/g, " ").trim().slice(0, 750);
    if (cleanQ.length < 4 || cleanA.length < 12) return;
    const key = cleanQ.toLowerCase();
    if (seenQ.has(key)) return;
    seenQ.add(key);
    pairs.push({ page_slug: slug, question: cleanQ, answer: cleanA, keywords: kwList, title, url: pageUrl });
  };

  const isLink = String(page.template || "").startsWith("link:");
  const overviewAnsEn = [descEn, bodyClean.slice(0, 380)].filter(Boolean).join(" ").trim();
  if (titleEn && overviewAnsEn) {
    pushQa(isLink ? `What is ${titleEn} app and how does it work?` : `What is ${titleEn}?`, overviewAnsEn);
    if (isLink) {
      pushQa(`Where can I access or open ${titleEn}?`, `${overviewAnsEn} You can open it directly from the ${titleEn} page on this site.`);
    }
  }
  if (titleNe && (descNe || overviewAnsEn)) {
    pushQa(`${titleNe} के हो र यसमा के छ?`, descNe || overviewAnsEn);
  }

  // Extract section-level Q&A from Blocks JSON
  if (!String(page.template || "").startsWith("zip:") && !isLink) {
    try {
      const blocks = typeof page.content === "string" ? JSON.parse(page.content) : page.content;
      if (Array.isArray(blocks)) {
        let curHeading = "";
        let curChunks = [];
        const flush = () => {
          if (curHeading && curChunks.length) {
            const qText = /\?$|के|कसरी|किन|कहाँ|कति|What|How|Why|When|Where/i.test(curHeading)
              ? curHeading
              : `${curHeading} — ${title}`;
            pushQa(qText, curChunks.join(" "));
          }
          curHeading = "";
          curChunks = [];
        };
        for (const b of blocks) {
          if (!b || typeof b !== "object") continue;
          if (b.type === "heading" && b.text) {
            flush();
            curHeading = String(b.text).trim();
          } else if (["paragraph", "quote"].includes(b.type) && b.text) {
            curChunks.push(String(b.text).trim());
          } else if (b.type === "columns" && Array.isArray(b.columns)) {
            curChunks.push(b.columns.map((c) => c.text || "").join(" "));
          } else if (b.type === "cards" && Array.isArray(b.cards)) {
            for (const c of b.cards) {
              if (c.title && c.text) pushQa(`${c.title} (${title})`, c.text);
            }
          }
        }
        flush();
      }
    } catch {}
  }

  // Extract heading + paragraph pairs from uploaded HTML (ZIP/single HTML)
  if (rawHtml) {
    const cleanHtml = String(rawHtml)
      .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
      .replace(/<style\b[\s\S]*?<\/style>/gi, " ");
    const secRe = /<h([1-4])\b[^>]*>([\s\S]*?)<\/h\1>([\s\S]*?)(?=<h[1-4]\b|<footer\b|<\/body>|$)/gi;
    let match;
    let count = 0;
    while ((match = secRe.exec(cleanHtml)) !== null && count < 12) {
      const h = decodeBasicEntities(match[2]);
      const secBody = decodeBasicEntities(match[3]).slice(0, 520);
      if (h.length >= 3 && secBody.length >= 20) {
        const qText = /\?$|के|कसरी|किन|What|How|Why|Which|When|Where/i.test(h) ? h : `${h} (${title})`;
        pushQa(qText, secBody);
        count++;
      }
    }
  }

  return pairs.slice(0, 16);
}

async function syncPageQa(env, page, searchText = "", rawHtml = "") {
  try {
    await ensureQaTable(env);
    await env.DB.prepare("DELETE FROM site_qa_index WHERE page_slug=?").bind(page.slug).run();
    if (!page.published) return;
    const pairs = extractQaPairsFromPage(page, searchText, rawHtml);
    const now = new Date().toISOString();
    for (const item of pairs) {
      await env.DB.prepare(
        "INSERT INTO site_qa_index(page_slug,question,answer,keywords,title,url,updated_at) VALUES(?,?,?,?,?,?,?)"
      ).bind(item.page_slug, item.question, item.answer, item.keywords, item.title, item.url, now).run();
    }
  } catch {}
}

async function syncSiteProfileQa(env, settings) {
  try {
    await ensureQaTable(env);
    await env.DB.prepare("DELETE FROM site_qa_index WHERE page_slug=?").bind("_site_profile").run();
    const brand = String(settings.brand_name || "Granshi").split("—")[0].trim() || "Granshi";
    const aboutEn = String(settings.about_en || settings.hero_desc_en || "").trim();
    const aboutNe = String(settings.about_ne || settings.hero_desc_ne || "").trim();
    const now = new Date().toISOString();
    const profilePairs = [
      {
        q: `Who is the owner of ${brand} website?`,
        a: `${brand} is the personal website owned and operated by Gopal Prasad Koirala (gopalkoirala.com.np). ${aboutEn}`.trim(),
        kw: `owner gopal prasad koirala ${brand.toLowerCase()} personal website about contact`
      },
      {
        q: `यो वेबसाइट (${brand}) कसको हो र यहाँ के पाइन्छ?`,
        a: `यो वेबसाइट गोपाल प्रसाद कोइराला (Gopal Prasad Koirala) को व्यक्तिगत वेबसाइट हो, जसको ब्रान्ड नाम ${brand} हो। ${aboutNe || aboutEn}`.trim(),
        kw: `gopal prasad koirala गोपाल प्रसाद कोइराला व्यक्तिगत वेबसाइट परिचय ${brand.toLowerCase()}`
      }
    ];
    for (const item of profilePairs) {
      await env.DB.prepare(
        "INSERT INTO site_qa_index(page_slug,question,answer,keywords,title,url,updated_at) VALUES(?,?,?,?,?,?,?)"
      ).bind("_site_profile", item.q, item.a, item.kw, `${brand} — Gopal Prasad Koirala`, "/legal/about", now).run();
    }
  } catch {}
}

async function rebuildAllQa(env) {
  await ensureQaTable(env);
  const settings = await getSettings(env);
  await env.DB.prepare("DELETE FROM site_qa_index").run();
  await syncSiteProfileQa(env, settings);
  const pages = await safeAll(env, "SELECT * FROM pages WHERE published=1 ORDER BY updated_at DESC LIMIT 500");
  let indexedPages = 0;
  for (const pg of pages) {
    let rawHtml = "";
    let text = searchablePageText(pg.content);
    const tmpl = String(pg.template || "");
    if (tmpl.startsWith("zip:") && env.MEDIA) {
      const entry = tmpl.slice(4) || "index.html";
      const obj = await env.MEDIA.get(`pages/${pg.slug}/${entry}`);
      if (obj) {
        rawHtml = await obj.text();
        text = htmlToSearchText(rawHtml);
      }
    } else if (tmpl.startsWith("link:")) {
      text = [pg.description_en, pg.description_ne, pg.thumbnail_summary_en, pg.thumbnail_summary_ne].filter(Boolean).join(" ");
    }
    await syncPageQa(env, pg, text, rawHtml);
    indexedPages++;
  }
  const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM site_qa_index").first();
  return { pages: indexedPages, questions: Number(cnt?.n || 0) };
}

async function ensureQaPopulated(env) {
  try {
    await ensureQaTable(env);
    const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM site_qa_index").first();
    if (Number(cnt?.n || 0) === 0) {
      await rebuildAllQa(env);
    }
  } catch {}
}

function isDisallowedHost(hostname) {
  const h = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || h === "::1") return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a, b] = h.split(".").map(Number);
    if (a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return true;
  }
  if (/^(fc|fd|fe80)/i.test(h)) return true;
  return false;
}

function makeLinkThumbnailSvg(title, domain) {
  const cleanTitle = escapeHtml(String(title || domain || "Web App").slice(0, 46));
  const cleanDomain = escapeHtml(String(domain || "gopalkoirala.com.np").slice(0, 42));
  const initial = escapeHtml(String(title || domain || "A").trim().slice(0, 1).toUpperCase());
  return `<svg xmlns="http://www.w3.org/2000/svg" width="800" height="500" viewBox="0 0 800 500">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0f172a"/>
      <stop offset="100%" stop-color="#1e3a5f"/>
    </linearGradient>
  </defs>
  <rect width="800" height="500" fill="url(#bg)"/>
  <circle cx="700" cy="95" r="140" fill="#d8b46a" fill-opacity="0.10"/>
  <rect x="64" y="64" width="68" height="68" rx="16" fill="#d8b46a"/>
  <text x="98" y="112" text-anchor="middle" font-family="Georgia,serif" font-size="36" font-weight="700" fill="#0f172a">${initial}</text>
  <text x="64" y="218" font-family="system-ui,-apple-system,sans-serif" font-size="22" font-weight="600" fill="#f5e4ba">${cleanDomain}</text>
  <text x="64" y="278" font-family="Georgia,serif" font-size="38" font-weight="700" fill="#ffffff">${cleanTitle}</text>
  <line x1="64" y1="350" x2="736" y2="350" stroke="#ffffff" stroke-opacity="0.18" stroke-width="1"/>
  <text x="64" y="405" font-family="system-ui,sans-serif" font-size="20" fill="#cbd5e1">Interactive App &amp; Curated Resource · Granshi</text>
</svg>`;
}

async function allPublic(env) {
  const settings = await getSettings(env);
  let pages = await safeAll(
    env,
    `SELECT p.slug,p.title_en,p.title_ne,p.description_en,p.description_ne,p.thumbnail_image,p.thumbnail_title_en,p.thumbnail_title_ne,p.thumbnail_summary_en,p.thumbnail_summary_ne,p.thumbnail_alt,p.thumbnail_focal_x,p.thumbnail_focal_y,p.updated_at,p.department_id,p.is_popular,CASE WHEN (p.thumbnail_summary_en='' OR p.thumbnail_summary_en IS NULL) AND (p.description_en='' OR p.description_en IS NULL) THEN p.content ELSE '' END AS content,d.name_en AS dept_en,d.name_ne AS dept_ne,d.slug AS dept_slug FROM pages p LEFT JOIN departments d ON d.id=p.department_id WHERE p.published=1 ORDER BY p.updated_at DESC LIMIT 300`
  );
  if (!pages.length) {
    pages = await safeAll(
      env,
      `SELECT slug,title_en,title_ne,description_en,description_ne,updated_at FROM pages WHERE published=1 ORDER BY updated_at DESC LIMIT 100`
    );
  }
  pages = pages.map((pg) => {
    if (!pg.thumbnail_summary_en && !pg.description_en && pg.content) pg.thumbnail_summary_en = pageExcerpt(searchablePageText(pg.content), "");
    if (!pg.thumbnail_summary_ne && !pg.description_ne) pg.thumbnail_summary_ne = pg.thumbnail_summary_en || "";
    delete pg.content;
    return pg;
  });
  let depts = await safeAll(
    env,
    "SELECT id,name_en,name_ne,description_en,description_ne,url,icon,image,slug,sort_order FROM departments WHERE visible=1 ORDER BY sort_order"
  );
  if (!depts.length) {
    depts = await safeAll(
      env,
      "SELECT id,name_en,name_ne,description_en,description_ne,url,icon,image,sort_order FROM departments WHERE visible=1 ORDER BY sort_order"
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

function granshiHeader(lang = "en", settings = {}) {
  const nextLang = lang === "en" ? "ne" : "en";
  const shortBrand = String(settings.brand_name || "Granshi").split("—")[0].trim() || "Granshi";
  const initial = shortBrand.slice(0, 1).toUpperCase();
  const homeUrl = lang === "ne" ? "/?lang=ne" : "/";
  return '<header id="granshi-site-header"><div class="granshi-header-inner"><a class="granshi-header-logo" href="' + homeUrl + '" aria-label="' + escapeHtml(shortBrand) + ' Home"><span class="granshi-header-mark" aria-hidden="true">' + escapeHtml(initial) + '</span><span class="granshi-header-wordmark">' + escapeHtml(shortBrand) + '</span></a><nav class="granshi-header-actions" aria-label="Website controls"><a class="granshi-header-home" href="' + homeUrl + '">' + (lang === "en" ? "← Home" : "← गृहपृष्ठ") + '</a><a class="granshi-header-language" href="?lang=' + nextLang + '">' + (lang === "en" ? "नेपाली" : "English") + '</a></nav></div></header>';
}

const GRANSHI_HEADER_CSS = `
  #granshi-site-header{position:sticky;top:0;z-index:10000;width:100%;margin:0;background:rgba(250,249,246,.94);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);color:#111827;border-bottom:1px solid #e5e7eb;font-family:"Plus Jakarta Sans","Noto Sans Devanagari",system-ui,-apple-system,sans-serif}
  #granshi-site-header *{box-sizing:border-box}
  #granshi-site-header .granshi-header-inner{width:min(1100px,92%);min-height:66px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:16px}
  #granshi-site-header .granshi-header-logo{display:inline-flex;align-items:center;gap:10px;min-width:0;text-decoration:none;color:#111827}
  #granshi-site-header .granshi-header-mark{width:30px;height:30px;border-radius:8px;background:var(--navy,#0f172a);color:#f5e4ba;display:grid;place-items:center;font-family:"Fraunces",Georgia,serif;font-weight:700;font-size:16px;flex-shrink:0}
  #granshi-site-header .granshi-header-wordmark{font-family:"Fraunces","Noto Sans Devanagari",Georgia,serif;font-weight:700;font-size:18px;letter-spacing:-0.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:46vw}
  #granshi-site-header .granshi-header-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;margin:0;padding:0;flex-shrink:0}
  #granshi-site-header .granshi-header-actions a{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:0 13px;border-radius:8px;text-decoration:none;white-space:nowrap;font:600 13px/1 "Plus Jakarta Sans","Noto Sans Devanagari",system-ui,sans-serif}
  #granshi-site-header .granshi-header-language{color:#111827;border:1px solid #d1d5db;background:#fff}
  #granshi-site-header .granshi-header-home{color:#111827;background:transparent}
  #granshi-site-header .granshi-header-home:hover{background:#f3f1ec}
  #granshi-site-header .granshi-header-language:hover{border-color:#111827}
  @media(max-width:520px){#granshi-site-header .granshi-header-inner{min-height:58px;gap:8px}#granshi-site-header .granshi-header-actions a{min-height:36px;padding:0 10px;font-size:12px}}
`;
function pageChrome(title, desc, bodyHtml, settings, lang = "en") {
  const brand = settings.brand_name || "Granshi";
  const shortBrand = String(brand).split("—")[0].trim() || "Granshi";
  const primary = settings.primary_color || "#0f172a";
  const accent = settings.accent_color || "#b8862d";
  const noteHtml = lang === "ne"
    ? `<p style="margin:0"><strong>सामग्रीसम्बन्धी सूचना:</strong> यस पेजमा प्रस्तुत जानकारी अध्ययन, अनुभव र सार्वजनिक सन्दर्भहरूमा आधारित हुन सक्छ। महत्त्वपूर्ण निर्णय गर्नुअघि आधिकारिक मूल स्रोतबाट पुष्टि गर्नुहोस्। कुनै सुझाव वा सुधार आवश्यक देखिएमा <a href="/legal/contact?lang=ne" style="color:#f5e4ba;text-decoration:underline">सम्पर्क पेज</a> मार्फत जानकारी दिनुहोस्।</p>`
    : `<p style="margin:0"><strong>Content Note:</strong> Information on this page is shared for general reading and learning and may draw on public references. Please verify critical details with authoritative sources. Corrections and feedback are welcome via <a href="/legal/contact" style="color:#f5e4ba;text-decoration:underline">Contact</a>.</p>`;
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} · ${escapeHtml(shortBrand)}</title><meta name="description" content="${escapeHtml(desc || "")}"><meta name="theme-color" content="${escapeHtml(primary)}"><link rel="manifest" href="/manifest.webmanifest"><link rel="icon" type="image/svg+xml" href="/icon.svg"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="${escapeHtml(shortBrand)}"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=Noto+Sans+Devanagari:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet"><style>:root{--navy:${escapeHtml(primary)};--gold:${escapeHtml(accent)};--paper:#faf9f6;--surface:#ffffff;--ink:#111827;--muted:#525d70;--line:#e5e7eb}*{box-sizing:border-box}body{margin:0;font-family:"Plus Jakarta Sans","Noto Sans Devanagari",system-ui,sans-serif;color:var(--ink);background:var(--paper);line-height:1.7;-webkit-font-smoothing:antialiased}a{text-decoration:none;color:inherit}.wrap{width:min(1060px,92%);margin:auto}.btn{display:inline-flex;align-items:center;padding:11px 18px;border-radius:9px;font-weight:600;font-size:14px;background:var(--navy);color:#fff}${GRANSHI_HEADER_CSS}.page-hero{background:var(--surface);border-bottom:1px solid var(--line);padding:42px 0 32px}.page-hero h1{margin:0;font-family:"Fraunces","Noto Sans Devanagari",Georgia,serif;font-size:clamp(1.85rem,4vw,2.75rem);line-height:1.15;letter-spacing:-0.02em;color:var(--ink);text-wrap:balance;max-width:24ch}.page-hero p{color:var(--muted);margin:12px 0 0;max-width:62ch;font-size:16px}article{padding:36px 0 56px}article.wrap{max-width:min(800px,92%)}.blk-h{margin:30px 0 12px;font-family:"Fraunces","Noto Sans Devanagari",Georgia,serif;line-height:1.25;color:var(--ink)}.blk-p{line-height:1.78;color:#27303f;margin:0 0 16px;font-size:16px}.blk-img{margin:24px 0}.blk-img img{max-width:100%;border-radius:12px;border:1px solid var(--line)}.blk-img figcaption{font-size:13px;color:var(--muted);margin-top:8px}.blk-quote{border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:18px 4px;margin:26px 0;font-family:"Fraunces","Noto Sans Devanagari",Georgia,serif;font-size:1.12rem;color:var(--ink)}.blk-quote p{margin:0}.blk-quote cite{display:block;margin-top:8px;font-family:"Plus Jakarta Sans",sans-serif;font-size:13px;font-style:normal;color:var(--muted)}.blk-hr{border:0;border-top:1px solid var(--line);margin:32px 0}.blk-cols{display:grid;grid-template-columns:repeat(var(--cols,2),1fr);gap:18px;margin:22px 0}.blk-col{background:var(--surface);padding:18px;border-radius:12px;border:1px solid var(--line)}.blk-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:16px;margin:22px 0}.blk-card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:18px}.blk-card h3{margin:6px 0 8px;font-size:16px}.blk-card p{margin:0 0 10px;color:var(--muted);font-size:14px}.blk-card a{font-size:13px;font-weight:600;color:var(--navy)}.blk-hero{min-height:260px;background-size:cover;background-position:center;color:#fff;border-radius:16px;position:relative;margin:12px 0 28px;overflow:hidden}.blk-hero:before{content:"";position:absolute;inset:0;background:linear-gradient(90deg,#0f172ae6,#0f172a70)}.blk-hero-inner{position:relative;padding:38px}.blk-video{position:relative;padding-bottom:56.25%;height:0;margin:22px 0;border-radius:12px;overflow:hidden;border:1px solid var(--line)}.blk-video iframe,.blk-video video{position:absolute;inset:0;width:100%;height:100%}footer.site-foot{background:var(--navy);color:#cbd5e1;padding:32px 0 28px;font-size:13.5px}.legal-footer-policies{margin:16px 0 0;border-top:1px solid rgba(255,255,255,.14);padding-top:14px;text-align:left}.legal-footer-policies summary{cursor:pointer;color:#f5e4ba;font-weight:600;font-size:13px}.legal-footer-policies nav{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:10px}.legal-footer-policies a{color:#cbd5e1;font-size:12.5px}.legal-footer-policies a:hover{color:#fff}@media(max-width:700px){.blk-cols{grid-template-columns:1fr}.page-hero{padding:30px 0 24px}}</style></head><body>${granshiHeader(lang, settings)}${bodyHtml}<footer class="site-foot"><div class="wrap"><div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><span>${escapeHtml(settings.footer_text || "© Granshi — Gopal Prasad Koirala")}</span><a href="/sitemap?lang=${lang}" style="color:#cbd5e1">${lang === "ne" ? "साइट नक्सा (Sitemap)" : "Site Directory"}</a></div><details class="legal-footer-policies"><summary>${lang === "ne" ? "बारेमा तथा नीतिहरू" : "About &amp; Policies"}</summary><nav aria-label="About and website policies"><a href="/legal/about?lang=${lang}">${lang === "ne" ? "हाम्रोबारे" : "About"}</a><a href="/legal/contact?lang=${lang}">${lang === "ne" ? "सम्पर्क" : "Contact"}</a><a href="/legal/privacy?lang=${lang}">${lang === "ne" ? "गोपनीयता नीति" : "Privacy Policy"}</a><a href="/legal/terms?lang=${lang}">${lang === "ne" ? "प्रयोगका सर्तहरू" : "Terms &amp; Conditions"}</a><a href="/legal/disclaimer?lang=${lang}">${lang === "ne" ? "अस्वीकरण" : "Disclaimer"}</a><a href="/legal/cookies?lang=${lang}">${lang === "ne" ? "कुकी नीति" : "Cookie Policy"}</a><a href="/legal/copyright?lang=${lang}">${lang === "ne" ? "प्रतिलिपि अधिकार" : "Copyright Policy"}</a></nav></details><div style="margin:14px 0 0;border-top:1px solid rgba(255,255,255,.14);padding-top:12px;font-size:12px;line-height:1.65;color:#94a3b8">${noteHtml}</div></div></footer></body></html>`;
}

async function sendEmail(env, { to, subject, html, replyTo, attachments = [], from = "info@gopalkoirala.com.np" }) {
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

    const brandedFooter = '<div style="margin:24px 0 0;padding:14px 0 0;border-top:1px solid #e7eaf0;font:12px/1.55 Arial,sans-serif;color:#667085"><a href="https://gopalkoirala.com.np" style="display:inline-block;text-decoration:none"><img src="https://gopalkoirala.com.np/granshi-brand.webp" alt="Granshi" width="72" style="display:block;width:72px;max-width:100%;height:auto;border:0"></a><p style="margin:8px 0 0">Granshi · Learn Together · Explore Freely · Grow Together</p></div>';
    const emailHtml = String(html || '');
    const footerHtml = brandedFooter.replace('<div style=', '<div id="granshi-email-footer" style=');
    const finalHtml = emailHtml.includes('granshi-email-footer') ? emailHtml : /<\/body>/i.test(emailHtml) ? emailHtml.replace(/<\/body>/i, footerHtml + '</body>') : emailHtml + footerHtml;
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: `Granshi <${from}>`,
        to: [to],
        subject,
        html: finalHtml,
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

async function importReceivedEmail(env, emailId, fallback = {}) {
  if (!emailId || !env.RESEND_API_KEY || !env.DB) return false;
  const exists=await env.DB.prepare("SELECT id FROM inbound_email_events WHERE resend_email_id=?").bind(emailId).first();
  if (exists) return false;
  const response=await fetch("https://api.resend.com/emails/receiving/"+encodeURIComponent(emailId),{headers:{Authorization:"Bearer "+env.RESEND_API_KEY}});
  if(!response.ok) throw new Error("Resend could not retrieve email "+emailId+": "+response.status);
  const payload=await response.json(), mail=payload.data||payload;
  const from=String(mail.from||fallback.from||"").slice(0,250);
  const match=from.match(/<([^>]+)>/), address=(match?match[1]:from).trim();
  const name=(match?from.replace(match[0],"").replace(/["']/g,"").trim():address).slice(0,120)||address;
  const to=Array.isArray(mail.to)?mail.to:(Array.isArray(fallback.to)?fallback.to:[String(mail.to||"")]);
  const recipientAddresses=to.map(v=>{const s=String(v||"").toLowerCase();const m=s.match(/<([^>]+)>/);return (m?m[1]:s).trim()});
  if(!recipientAddresses.includes("info@gopalkoirala.com.np")) return false;
  const subject=String(mail.subject||fallback.subject||"Incoming email").slice(0,200);
  const textBody=String(mail.text||"").slice(0,30000);
  const htmlBody=String(mail.html||"").slice(0,60000);
  const received=String(mail.created_at||fallback.created_at||new Date().toISOString());
  const attachmentRows=[];
  for(const item of (Array.isArray(mail.attachments)?mail.attachments:[]).slice(0,10)){
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
  const cleanText=textBody||String(htmlBody||"").replace(/<\/(p|div|br|li|h[1-6])>/gi,"\n").replace(/<[^>]*>/g," ").replace(/&nbsp;/g," ").replace(/&amp;/g,"&").trim()||"(No message body)";
  const inserted=await env.DB.prepare("INSERT INTO messages(name,email,subject,body,status,created_at,reply_text,replied_at) VALUES(?,?,?,?,?,?,?,?)")
    .bind(name,address,subject,cleanText.slice(0,30000),"new",received,JSON.stringify({inbound:true,html:htmlBody,attachments:attachmentRows}),null).run();
  await env.DB.prepare("INSERT INTO inbound_email_events(id,resend_email_id,message_id,sender,recipients,subject,body_text,body_html,headers_json,attachments_json,received_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(crypto.randomUUID(),emailId,inserted.meta?.last_row_id||null,from,JSON.stringify(to),subject,textBody,htmlBody,JSON.stringify(mail.headers||{}),JSON.stringify(attachmentRows),received,new Date().toISOString()).run();
  return true;
}

async function handleResendWebhook(req, env, ctx = null) {
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
  const recipientAddresses=to.map(v=>{const s=String(v||"").toLowerCase();const m=s.match(/<([^>]+)>/);return (m?m[1]:s).trim()});
  if(!recipientAddresses.includes("info@gopalkoirala.com.np")){
    await env.DB.prepare("INSERT INTO inbound_email_events(id,resend_email_id,message_id,sender,recipients,subject,body_text,body_html,headers_json,attachments_json,received_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(crypto.randomUUID(),emailId,null,String(mail.from||meta.from||""),JSON.stringify(to),String(mail.subject||meta.subject||""),"","","{}", "[]",String(mail.created_at||event.created_at||new Date().toISOString()),new Date().toISOString()).run();
    return json({received:true,ignored:true,reason:"Recipient is not the Granshi info mailbox."});
  }
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
  queueAdminPush(ctx, env, {
    title: "New Email · info@gopalkoirala.com.np",
    body: `${name}: ${subject}`,
    url: "/admin#messages",
    tag: "granshi-email-" + (inserted.meta?.last_row_id || Date.now())
  });
  return json({received:true});
}


const DIAG_PUBLIC_ORIGIN = "https://gopalkoirala.com.np";
const DIAG_BATCH_SIZE = 10;
async function buildDiagnosisChecks(env) {
  const checks = [];
  const add = (id,label,kind,target,solution,cause,affected,can_fix="developer") =>
    checks.push({id,label,kind,target:target||"",status:"pending",ok:null,detail:"Waiting",solution,cause,affected,can_fix,resolved:false});
  add("d1_connection","D1 database connection","d1","","Verify the Worker D1 binding named DB and database availability.","D1 binding, database availability or query failure.","Cloudflare Worker → D1 binding DB");
  for (const table of ["pages","departments","messages","admin_message_reads","inbound_email_events","pending_work_items","diagnostics_state"]) {
    add("table_"+table,"D1 table: "+table,"table",table,"Apply the required D1 migration and confirm the table exists.","The table may be missing or the migration may not have been applied.","D1 database schema: "+table,"developer");
  }
  add("r2_connection","R2 bucket connection","r2","","Check Worker R2 binding MEDIA and bucket granshi-media.","Missing binding, bucket permission or R2 service error.","Worker R2 binding MEDIA → granshi-media","developer");
  for (const path of ["/","/sitemap.xml","/robots.txt","/api/health"]) {
    add("url_"+path.replace(/[^a-z0-9]/gi,"_"),"Public route: "+path,"url",path,"Check Cloudflare route, asset deployment and the relevant public file or API route.","The route may be unavailable, misrouted or returning an HTTP error.","Public URL "+path,"developer");
  }
  let pages=[];
  try { pages=(await env.DB.prepare("SELECT slug,title_en,title_ne,description_en,description_ne,thumbnail_summary_en,thumbnail_image FROM pages WHERE published=1 ORDER BY updated_at DESC LIMIT 80").all()).results||[]; }
  catch(e) { add("pages_query","Published pages query","d1_query","","Repair the pages table or database permissions, then rerun diagnosis.",String(e).slice(0,220),"D1 pages table","developer"); }
  for (const pg of pages) {
    const slug=String(pg.slug||"");
    if (!slug) continue;
    add("page_"+slug,"Published page: /"+slug,"url","/"+encodeURIComponent(slug),"Check the page publication state, slug and Worker page rendering.","The page may be unpublished, missing or failing during render.","D1 pages.slug="+slug+" and public route","admin");
    if (pg.thumbnail_image && /^\//.test(pg.thumbnail_image))
      add("thumb_"+slug,"Thumbnail: /"+slug,"url",pg.thumbnail_image,"Check the image URL and confirm the referenced object exists in R2.","The thumbnail path may be invalid or the R2 object may be missing.","Page "+slug+" → thumbnail_image","admin");
  }
  const missingTitle=pages.filter(p=>!String(p.title_en||p.title_ne||"").trim()).length;
  const missingDesc=pages.filter(p=>!String(p.description_en||p.description_ne||p.thumbnail_summary_en||"").trim()).length;
  add("seo_metadata","Published page SEO metadata","seo","", "Edit missing title and description fields in Departments → Pages.","Published pages are missing one or more search metadata fields.","D1 pages.title_en/title_ne and description_en/description_ne","admin");
  checks.find(x=>x.id==="seo_metadata").seo={total:pages.length,missingTitle,missingDesc};
  return checks;
}
async function runDiagnosisCheckInner(env, check) {
  try {
    if (check.kind==="d1") {
      const row=await env.DB.prepare("SELECT 1 AS ok").first();
      return {ok:!!row?.ok,detail:"D1 SELECT 1 "+(row?.ok?"succeeded":"returned no result")};
    }
    if (check.kind==="table") {
      const row=await env.DB.prepare("SELECT COUNT(*) AS n FROM "+check.target).first();
      return {ok:true,detail:"Table accessible · "+Number(row?.n||0)+" rows"};
    }
    if (check.kind==="d1_query") {
      const row=await env.DB.prepare("SELECT COUNT(*) AS n FROM pages").first();
      return {ok:true,detail:"Published pages query succeeded · "+Number(row?.n||0)+" rows"};
    }
    if (check.kind==="r2") {
      if(!env.MEDIA) throw new Error("MEDIA binding missing");
      const r=await env.MEDIA.list({limit:1});
      return {ok:true,detail:"R2 bucket listing succeeded · "+(r.objects||[]).length+" sample object(s) returned"};
    }
    if (check.kind==="url") {
      const controller=new AbortController();
      const timer=setTimeout(()=>controller.abort("Check timed out after 5 seconds"),5000);
      try {
        const response=await fetch(DIAG_PUBLIC_ORIGIN+check.target,{method:check.target==="/api/health"?"GET":"HEAD",cache:"no-store",signal:controller.signal});
        return {ok:response.ok,detail:"HTTP "+response.status+(response.ok?" · reachable":" · route returned an error")};
      } finally { clearTimeout(timer); }
    }
    if (check.kind==="seo") {
      const s=check.seo||{};
      const ok=!s.missingTitle&&!s.missingDesc;
      return {ok,detail:s.total+" published pages · "+s.missingTitle+" missing titles · "+s.missingDesc+" missing descriptions"};
    }
    return {ok:false,detail:"Unsupported diagnostic check type"};
  } catch(e) {
    const timed=String(e).toLowerCase().includes("abort")||String(e).toLowerCase().includes("timeout");
    return {ok:false,detail:(timed?"TIMEOUT · ":"")+String(e).slice(0,260),timeout:timed};
  }
}
async function runDiagnosisCheck(env, check) {
  let timer;
  try {
    return await Promise.race([
      runDiagnosisCheckInner(env,check),
      new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error("TIMEOUT · check exceeded 5 seconds")),5000);})
    ]);
  } catch(e) {
    const detail=String(e).slice(0,260);
    return {ok:false,detail,timeout:/timeout/i.test(detail)};
  } finally { if(timer) clearTimeout(timer); }
}
async function createDiagnosisRun(env, triggerType="manual") {
  const checks=await buildDiagnosisChecks(env);
  const now=new Date().toISOString();
  const old=await env.DB.prepare("SELECT latest_report_json FROM diagnostics_state WHERE id=1").first();
  await env.DB.prepare("INSERT INTO diagnostics_state(id,status,trigger_type,run_id,started_at,updated_at,completed_at,current_index,checks_json,latest_report_json) VALUES(1,'running',?,?,?, ?,NULL,0,?,?) ON CONFLICT(id) DO UPDATE SET status='running',trigger_type=excluded.trigger_type,run_id=excluded.run_id,started_at=excluded.started_at,updated_at=excluded.updated_at,completed_at=NULL,current_index=0,checks_json=excluded.checks_json")
    .bind(triggerType,crypto.randomUUID(),now,now,JSON.stringify(checks),old?.latest_report_json||null).run();
}
async function advanceDiagnosis(env) {
  const nowDate=new Date();
  const now=nowDate.toISOString();
  const leaseUntil=new Date(nowDate.getTime()+45000).toISOString();
  const claim=await env.DB.prepare("UPDATE diagnostics_state SET lease_until=? WHERE id=1 AND status='running' AND (lease_until IS NULL OR lease_until<?)")
    .bind(leaseUntil,now).run();
  if(!claim.meta?.changes) return await env.DB.prepare("SELECT * FROM diagnostics_state WHERE id=1").first();
  try {
    const state=await env.DB.prepare("SELECT * FROM diagnostics_state WHERE id=1").first();
    if(!state || state.status!=="running") return state;
    const checks=JSON.parse(state.checks_json||"[]");
    let index=Number(state.current_index||0);
    const end=Math.min(checks.length,index+DIAG_BATCH_SIZE);
    const batchResults=await Promise.all(checks.slice(index,end).map(check=>runDiagnosisCheck(env,check)));
    for(let offset=0;offset<batchResults.length;offset++) {
      const result=batchResults[offset],checkIndex=index+offset;
      checks[checkIndex]={...checks[checkIndex],...result,status:result.ok?"pass":"issue",checked_at:new Date().toISOString()};
    }
    index=end;
    const updated=new Date().toISOString();
    if(index>=checks.length) {
      const evaluable=checks.filter(x=>x.status==="pass"||x.status==="issue");
      const issues=evaluable.filter(x=>!x.ok);
      const documented=issues.filter(x=>String(x.solution||"").trim()).length;
      const report={run_id:state.run_id,trigger_type:state.trigger_type,started_at:state.started_at,completed_at:updated,checks,total_checks:checks.length,evaluable_checks:evaluable.length,passed:evaluable.length-issues.length,issues:issues.length,health_percent:evaluable.length?Math.round((evaluable.length-issues.length)/evaluable.length*100):0,solution_percent:issues.length?Math.round(documented/issues.length*100):null,verified_resolutions:issues.filter(x=>x.resolved===true).length,limitations:["Browser console errors, private account billing metrics and Cloudflare runtime logs are not available to this scheduled Worker scan.","R2 inventory size is checked separately in the Storage card; it is not the Cloudflare monthly GB-month billing meter."]};
      await env.DB.prepare("UPDATE diagnostics_state SET status='complete',updated_at=?,completed_at=?,current_index=?,checks_json=?,latest_report_json=?,lease_until=NULL WHERE id=1")
        .bind(updated,updated,index,JSON.stringify(checks),JSON.stringify(report)).run();
    } else {
      await env.DB.prepare("UPDATE diagnostics_state SET updated_at=?,current_index=?,checks_json=?,lease_until=NULL WHERE id=1")
        .bind(updated,index,JSON.stringify(checks)).run();
    }
  } catch(e) {
    await env.DB.prepare("UPDATE diagnostics_state SET lease_until=NULL,updated_at=? WHERE id=1").bind(new Date().toISOString()).run();
    throw e;
  }
  return await env.DB.prepare("SELECT * FROM diagnostics_state WHERE id=1").first();
}
async function runScheduledDiagnosis(env, scheduledTime) {
  const date=new Date(scheduledTime);
  const hour=date.getUTCHours();
  if(hour<0||hour>4) return;
  let state=await env.DB.prepare("SELECT * FROM diagnostics_state WHERE id=1").first();
  if(state?.status==="running") { await advanceDiagnosis(env); return; }
  if(hour!==1) return;
  const today=date.toISOString().slice(0,10);
  if(state?.completed_at && state.completed_at.slice(0,10)===today) return;
  await createDiagnosisRun(env,"nightly");
  await advanceDiagnosis(env);
}
async function diagnosisStateResponse(env) {
  const state=await env.DB.prepare("SELECT status,trigger_type,run_id,started_at,updated_at,completed_at,current_index,checks_json,latest_report_json FROM diagnostics_state WHERE id=1").first();
  if(!state) return {status:"not_scanned",active:false,latest_report:null,checks:[],progress:0};
  const checks=JSON.parse(state.checks_json||"[]");
  const latest=state.latest_report_json?JSON.parse(state.latest_report_json):null;
  return {status:state.status,active:state.status==="running",trigger_type:state.trigger_type,run_id:state.run_id,started_at:state.started_at,updated_at:state.updated_at,completed_at:state.completed_at,current_index:Number(state.current_index||0),total_checks:checks.length,checks,progress:checks.length?Math.round(Number(state.current_index||0)/checks.length*100):0,latest_report:latest};
}

async function api(req, env, ctx = null) {
  const u = new URL(req.url);
  const p = u.pathname;
  const method = req.method;

  if (p === "/api/webhooks/resend" && method === "POST") return handleResendWebhook(req, env, ctx);
  if (p === "/api/health") return json({ ok: true, v: 4 });
  if (p === "/api/public" && method === "GET")
    return json(await allPublic(env));
  if (p === "/api/pages" && method === "GET") {
    const limit = Math.max(1,Math.min(60,Number(u.searchParams.get("limit")||24)));
    const offset = Math.max(0,Math.min(100000,Number(u.searchParams.get("offset")||0)));
    const pages = await safeAll(env,
      "SELECT p.slug,p.title_en,p.title_ne,p.description_en,p.description_ne,p.thumbnail_image,p.thumbnail_title_en,p.thumbnail_title_ne,p.thumbnail_summary_en,p.thumbnail_summary_ne,p.thumbnail_alt,p.thumbnail_focal_x,p.thumbnail_focal_y,p.updated_at,p.department_id,p.is_popular,CASE WHEN (p.thumbnail_summary_en='' OR p.thumbnail_summary_en IS NULL) AND (p.description_en='' OR p.description_en IS NULL) THEN p.content ELSE '' END AS content,d.name_en AS dept_en,d.name_ne AS dept_ne,d.slug AS dept_slug FROM pages p LEFT JOIN departments d ON d.id=p.department_id WHERE p.published=1 ORDER BY p.updated_at DESC LIMIT ? OFFSET ?",
      limit,offset);
    const enriched=pages.map((pg)=>{if(!pg.thumbnail_summary_en&&!pg.description_en&&pg.content)pg.thumbnail_summary_en=pageExcerpt(searchablePageText(pg.content),"");if(!pg.thumbnail_summary_ne&&!pg.description_ne)pg.thumbnail_summary_ne=pg.thumbnail_summary_en||"";delete pg.content;return pg;});
    return json({pages:enriched,hasMore:pages.length===limit});
  }

  if (p === "/api/qa/suggest" && method === "GET") {
    const q = String(u.searchParams.get("q") || "").trim().slice(0, 120);
    await ensureQaPopulated(env);
    if (q.length < 2) {
      const top = await safeAll(env, "SELECT question,page_slug,title,url FROM site_qa_index ORDER BY id ASC LIMIT 6");
      return json({ suggestions: top });
    }
    const words = [...new Set(q.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter((w) => w.length > 1))].slice(0, 6);
    if (!words.length) return json({ suggestions: [] });
    const where = words.map(() => "(LOWER(question) LIKE ? OR LOWER(keywords) LIKE ? OR LOWER(title) LIKE ?)").join(" OR ");
    const binds = words.flatMap((w) => { const pat = "%" + w + "%"; return [pat, pat, pat]; });
    const rows = await safeAll(
      env,
      "SELECT DISTINCT question,page_slug,title,url FROM site_qa_index WHERE " + where + " LIMIT 20",
      ...binds
    );
    const scored = rows.map((r) => {
      const hay = (r.question + " " + r.title).toLowerCase();
      let score = hay.includes(q.toLowerCase()) ? 10 : 0;
      for (const w of words) if (hay.includes(w)) score += 3;
      return { ...r, score };
    }).sort((a, b) => b.score - a.score);
    return json({ suggestions: scored.slice(0, 6).map(({ question, page_slug, title, url }) => ({ question, page_slug, title, url })) });
  }

  if (p === "/api/search" && method === "POST") {
    const x = await body(req);
    const query = String(x.query || "").trim().slice(0, 240);
    const lang = x.lang === "ne" ? "ne" : "en";
    if (query.length < 2) return json({ answer: "", results: [], message: "Type at least two characters." }, 400);
    await ensureQaPopulated(env);
    const words = [...new Set(query.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter((w) => w.length > 1))].slice(0, 8);
    if (!words.length) return json({ answer: "", results: [], matched_questions: [], grounded: false });

    const qaWhere = words.map(() => "(LOWER(question) LIKE ? OR LOWER(answer) LIKE ? OR LOWER(keywords) LIKE ? OR LOWER(title) LIKE ?)").join(" OR ");
    const qaBinds = words.flatMap((w) => { const q = "%" + w + "%"; return [q, q, q, q]; });
    const qaRows = await safeAll(
      env,
      "SELECT page_slug,question,answer,keywords,title,url FROM site_qa_index WHERE " + qaWhere + " LIMIT 24",
      ...qaBinds
    );
    const rankedQa = qaRows.map((row) => {
      const ql = row.question.toLowerCase();
      const al = row.answer.toLowerCase();
      let score = ql.includes(query.toLowerCase()) ? 15 : 0;
      for (const w of words) {
        if (ql.includes(w)) score += 4;
        if (row.title.toLowerCase().includes(w)) score += 3;
        if (al.includes(w)) score += 2;
      }
      return { ...row, score };
    }).sort((a, b) => b.score - a.score);

    const where = words.map(() => "(LOWER(i.title) LIKE ? OR LOWER(i.description) LIKE ? OR LOWER(i.body_text) LIKE ?)").join(" OR ");
    const binds = words.flatMap((w) => { const q = "%" + w + "%"; return [q, q, q]; });
    const rows = await safeAll(env,
      "SELECT i.page_slug,i.title,i.description,i.body_text,p.thumbnail_image,p.thumbnail_title_en,p.thumbnail_title_ne,p.thumbnail_summary_en,p.thumbnail_summary_ne,p.department_id,d.name_en AS dept_en,d.name_ne AS dept_ne FROM page_search_index i JOIN pages p ON p.slug=i.page_slug LEFT JOIN departments d ON d.id=p.department_id WHERE p.published=1 AND (" + where + ") ORDER BY p.updated_at DESC LIMIT 8",
      ...binds);
    const results = rows.map((r) => ({
      slug: r.page_slug,
      title: r.thumbnail_title_en || r.title,
      title_ne: r.thumbnail_title_ne || "",
      summary: r.thumbnail_summary_en || r.description || pageExcerpt(r.body_text, query),
      summary_ne: r.thumbnail_summary_ne || "",
      image: r.thumbnail_image || "",
      department: r.dept_en || "",
      excerpt: pageExcerpt(r.body_text, query),
      url: "/" + encodeURIComponent(r.page_slug)
    }));

    const qaAnswer = rankedQa.slice(0, 2).map((item) => item.answer).filter(Boolean).join("\n\n");
    const pageAnswer = results.slice(0, 2).map((r) => r.excerpt || r.summary).filter(Boolean).join(" ");
    const answer = qaAnswer || pageAnswer;
    const grounded = Boolean(answer);
    const disclaimer = lang === "ne"
      ? "नोट: यो उत्तर गोपाल प्रसाद कोइरालाको Granshi वेबसाइटमा प्रकाशित सामग्रीबाट तयार गरिएको सामान्य जानकारी मात्र हो, आधिकारिक वा कानुनी सल्लाह होइन।"
      : "Note: This response is compiled from content published on Gopal Prasad Koirala's Granshi website for general information only—not official or legal advice.";

    return json({
      query,
      answer,
      grounded,
      disclaimer,
      matched_questions: rankedQa.slice(0, 4).map(({ question, answer: ans, page_slug, title, url }) => ({ question, answer: ans, page_slug, title, url })),
      results,
      external_ai_url: "https://www.google.com/search?udm=50&q=" + encodeURIComponent(query),
      external_gemini_url: "https://gemini.google.com/app",
      message: grounded ? "" : (lang === "ne"
        ? "यस विषयमा वेबसाइटमा पर्याप्त प्रकाशित जानकारी भेटिएन। तलको बटन थिची यही प्रश्नसहित बाह्य AI मा सोध्न सक्नुहुन्छ।"
        : "Not enough matching content was found on this site. You can continue with your exact question on an external AI below.")
    });
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
      const targetPage = await env.DB.prepare("SELECT slug FROM pages WHERE slug=? AND published=1").bind(slug).first();
      if (!targetPage) return json({ error: "Published page not found." }, 404);
      const recentCutoff = new Date(Date.now() - 60000).toISOString();
      const recentCount = await env.DB.prepare("SELECT COUNT(*) AS n FROM comments WHERE page_slug=? AND created_at>?").bind(slug, recentCutoff).first();
      if (Number(recentCount?.n || 0) >= 8) return json({ error: "Too many comments submitted recently. Please wait a minute." }, 429);
      const dup = await env.DB.prepare("SELECT id FROM comments WHERE page_slug=? AND name=? AND body=? AND created_at>? LIMIT 1").bind(slug, name, bodyText, recentCutoff).first();
      if (dup) return json({ ok: true, message: "Thanks! Your feedback is awaiting approval." });
      await env.DB.prepare(
        "INSERT INTO comments(page_slug,name,email,body,status,created_at) VALUES(?,?,?,?,?,?)"
      )
        .bind(slug, name, email, bodyText, "pending", new Date().toISOString())
        .run();
      queueAdminPush(ctx, env, {
        title: "New Comment on /" + slug,
        body: `${name}: ${bodyText.slice(0, 90)}`,
        url: "/admin#comments",
        tag: "granshi-comment-" + slug
      });
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
    const insertedMsg = await env.DB.prepare(
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
    queueAdminPush(ctx, env, {
      title: "New Message on Granshi",
      body: `${name}: ${subject || msg.slice(0, 90)}`,
      url: "/admin#messages",
      tag: "granshi-contact-" + (insertedMsg?.meta?.last_row_id || Date.now())
    });
    // Contact Us submissions belong only to the Messages module.
    // Do not forward them into the real info@ mailbox.
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
  if (p === "/api/admin/recover-lock" && method === "POST") {
    const x = await body(req);
    if (!env.SETUP_TOKEN || x.setupToken !== env.SETUP_TOKEN) return json({ error: "Invalid recovery token." }, 403);
    const email = String(x.email || "").trim().toLowerCase();
    const a = await env.DB.prepare("SELECT email,locked_at,recovery_authorized FROM admins WHERE email=?").bind(email).first();
    if (!a || !a.locked_at || Number(a.recovery_authorized) !== 1) return json({ error: "Run the one-time D1 recovery authorization SQL first." }, 409);
    await env.DB.prepare("UPDATE admins SET failed_login_attempts=0,locked_at=NULL,recovery_authorized=0,session_version=session_version+1 WHERE email=?").bind(email).run();
    return json({ ok: true, message: "Admin unlocked. All previous sessions have been revoked." });
  }
  if (p === "/api/auth/login" && method === "POST") {
    const x = await body(req);
    const email = String(x.email || "").trim().toLowerCase();
    const a = await env.DB.prepare("SELECT email,salt,password_hash,failed_login_attempts,locked_at FROM admins WHERE email=?").bind(email).first();
    if (!a) return json({ error: "Incorrect email or password." }, 401);
    if (a.locked_at || Number(a.failed_login_attempts || 0) >= 5)
      return json({ error: "Admin account is locked. Use the secure recovery procedure." }, 423);
    const valid = await verifyPassword(String(x.password || ""), a.salt, a.password_hash);
    if (!valid) {
      const result = await env.DB.prepare("UPDATE admins SET failed_login_attempts=failed_login_attempts+1, locked_at=CASE WHEN failed_login_attempts+1>=5 THEN CURRENT_TIMESTAMP ELSE locked_at END WHERE email=? RETURNING failed_login_attempts,locked_at").bind(email).first();
      const attempts = Number(result?.failed_login_attempts || 1);
      const ip = String(req.headers.get("CF-Connecting-IP") || "Unavailable").slice(0,100);
      const ua = String(req.headers.get("User-Agent") || "Unavailable").slice(0,500);
      const stamp = new Date().toISOString();
      let alertResult = { sent: false, error: "Alert threshold not reached." };
      if (attempts === 4) {
        const cfg = await getSettings(env);
        const alertTo = String(cfg.security_alert_email || cfg.contact_email || a.email || "").trim();
        alertResult = await sendEmail(env, {
          to: alertTo,
          subject: "Granshi Admin security alert: failed login",
          html: "<p>Four failed Admin login attempts detected.</p><p>Time (UTC): "+escapeHtml(stamp)+"</p><p>IP: "+escapeHtml(ip)+"</p><p>Browser/device: "+escapeHtml(ua)+"</p><p>Failed attempts: 4 of 5. Account is not yet locked.</p><p>No password or session token is included.</p>"
        });
      }
      await env.DB.prepare("INSERT INTO admin_security_events(event_type,attempt_count,ip_address,user_agent,email_alert_status,email_alert_error,created_at) VALUES(?,?,?,?,?,?,?)")
        .bind("failed_login",attempts,ip,ua,attempts===4?(alertResult.sent?"sent":"failed"):"not_due",attempts===4?String(alertResult.error||"").slice(0,500):null,stamp).run();
      if (attempts >= 5) return json({ error: "Admin account locked after five failed attempts." }, 423);
      if (attempts === 3) return json({ error: "Incorrect password. Final warning: one more failed attempt will lock the Admin account." }, 401);
      return json({ error: "Incorrect email or password." }, 401);
    }
    if (!String(a.password_hash || "").startsWith("v2:")) {
      const upgraded = await passwordHash(String(x.password || ""));
      await env.DB.prepare("UPDATE admins SET failed_login_attempts=0,salt=?,password_hash=? WHERE email=?").bind(upgraded.salt, upgraded.hash, email).run();
    } else {
      await env.DB.prepare("UPDATE admins SET failed_login_attempts=0 WHERE email=?").bind(email).run();
    }
    return json({ ok: true }, 200, { "set-cookie": sessionCookie(await sessionToken(env, a.email)) });
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


  if (p === "/api/admin/diagnostics/status" && method === "GET") return json(await diagnosisStateResponse(env));
  if (p === "/api/admin/diagnostics/start" && method === "POST") {
    const current=await env.DB.prepare("SELECT status FROM diagnostics_state WHERE id=1").first();
    if(current?.status!=="running") await createDiagnosisRun(env,"manual");
    const state=await advanceDiagnosis(env);
    return json({ok:true,...await diagnosisStateResponse(env)});
  }
  if (p === "/api/admin/diagnostics/continue" && method === "POST") {
    const state=await advanceDiagnosis(env);
    return json({ok:true,...await diagnosisStateResponse(env)});
  }
  if (p === "/api/admin/pending-work" && method === "GET") {
    const items=(await env.DB.prepare("SELECT * FROM pending_work_items ORDER BY status ASC,sort_order ASC,id ASC").all()).results||[];
    return json({items,total:items.length,success:items.filter(x=>x.status==="success").length,remaining:items.filter(x=>x.status!=="success").length});
  }
  if (p === "/api/admin/pending-work" && method === "POST") {
    const x=await body(req),title=String(x.title||"").trim().slice(0,240);
    if(!title) return json({error:"Task title is required."},400);
    await env.DB.prepare("INSERT INTO pending_work_items(title,created_at,sort_order) VALUES(?,?,?)").bind(title,new Date().toISOString(),Date.now()).run();
    return json({ok:true});
  }
  if (p.match(/^\/api\/admin\/pending-work\/\d+\/complete$/) && method === "POST") {
    const id=Number(p.split("/")[4]);
    const r=await env.DB.prepare("UPDATE pending_work_items SET status='success',completed_at=? WHERE id=?").bind(new Date().toISOString(),id).run();
    if(!r.meta?.changes) return json({error:"Task not found."},404);
    return json({ok:true});
  }
  if (p.match(/^\/api\/admin\/pending-work\/\d+$/) && method === "DELETE") {
    const id=Number(p.split("/").pop());
    const r=await env.DB.prepare("DELETE FROM pending_work_items WHERE id=? AND status='success'").bind(id).run();
    if(!r.meta?.changes) return json({error:"Only completed tasks can be deleted."},400);
    return json({ok:true});
  }

  // Admin security audit log & session revocation
  if (p === "/api/admin/security/events" && method === "GET") {
    const events = await safeAll(env, "SELECT id,event_type,attempt_count,ip_address,user_agent,email_alert_status,email_alert_error,created_at FROM admin_security_events ORDER BY created_at DESC, id DESC LIMIT 100");
    const adminInfo = await env.DB.prepare("SELECT email,failed_login_attempts,session_version,created_at FROM admins WHERE email=?").bind(who).first();
    return json({ events, admin: adminInfo });
  }
  if (p === "/api/admin/security/revoke-sessions" && method === "POST") {
    await env.DB.prepare("UPDATE admins SET session_version=session_version+1 WHERE email=?").bind(who).run();
    return json({ ok: true }, 200, { "set-cookie": clearCookie });
  }

  // Cross-device synced email drafts (auto-creates table if migration 0011 has not yet been applied)
  if (p.startsWith("/api/admin/email/drafts")) {
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS email_drafts (id TEXT PRIMARY KEY, recipient TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)").run();
    if (p === "/api/admin/email/drafts" && method === "GET") {
      const drafts = await safeAll(env, "SELECT id,recipient AS 'to',subject,body,updated_at AS saved_at FROM email_drafts ORDER BY updated_at DESC LIMIT 100");
      return json(drafts);
    }
    if (p === "/api/admin/email/drafts" && method === "POST") {
      const x = await body(req);
      const id = String(x.id || ("draft-" + Date.now())).slice(0, 100);
      const recipient = String(x.to || "").trim().slice(0, 180);
      const subject = String(x.subject || "").trim().slice(0, 200);
      const textBody = String(x.body || "").slice(0, 20000);
      const now = new Date().toISOString();
      await env.DB.prepare("INSERT INTO email_drafts(id,recipient,subject,body,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET recipient=excluded.recipient,subject=excluded.subject,body=excluded.body,updated_at=excluded.updated_at")
        .bind(id, recipient, subject, textBody, now).run();
      return json({ ok: true, id, saved_at: now });
    }
    if (p.startsWith("/api/admin/email/drafts/") && method === "DELETE") {
      const id = decodeURIComponent(p.slice("/api/admin/email/drafts/".length));
      await env.DB.prepare("DELETE FROM email_drafts WHERE id=?").bind(id).run();
      return json({ ok: true });
    }
  }

  // Admin: Knowledge Q&A store & external link inspector
  if (p === "/api/admin/qa/stats" && method === "GET") {
    await ensureQaPopulated(env);
    const qCnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM site_qa_index").first();
    const pCnt = await env.DB.prepare("SELECT COUNT(DISTINCT page_slug) AS n FROM site_qa_index WHERE page_slug<>'_site_profile'").first();
    return json({ questions: Number(qCnt?.n || 0), pages: Number(pCnt?.n || 0) });
  }
  if (p === "/api/admin/qa/rebuild" && method === "POST") {
    const result = await rebuildAllQa(env);
    return json({ ok: true, ...result });
  }
  if (p === "/api/admin/links/inspect" && method === "POST") {
    const x = await body(req);
    const rawUrl = String(x.url || "").trim();
    let parsed;
    try { parsed = new URL(rawUrl); } catch { return json({ error: "Enter a valid http:// or https:// URL." }, 400); }
    if (!["http:", "https:"].includes(parsed.protocol) || isDisallowedHost(parsed.hostname)) {
      return json({ error: "Only public http/https website URLs are allowed." }, 400);
    }
    let title = parsed.hostname.replace(/^www\./, "");
    let description = "";
    let ogImage = "";
    try {
      const resp = await fetch(parsed.toString(), {
        headers: { "user-agent": "GranshiBot/1.0 (+https://gopalkoirala.com.np)", accept: "text/html,application/xhtml+xml" },
        redirect: "follow",
        signal: AbortSignal.timeout(6000)
      });
      if (resp.ok && (resp.headers.get("content-type") || "").includes("text/html")) {
        const html = (await resp.text()).slice(0, 400000);
        const tMatch = html.match(/<meta[^>]+(?:property|name)=["'](?:og:title|twitter:title)["'][^>]+content=["']([^"']+)/i)
          || html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
        const dMatch = html.match(/<meta[^>]+(?:property|name)=["'](?:og:description|description|twitter:description)["'][^>]+content=["']([^"']+)/i);
        const iMatch = html.match(/<meta[^>]+(?:property|name)=["'](?:og:image|twitter:image)["'][^>]+content=["']([^"']+)/i);
        if (tMatch?.[1]) title = decodeBasicEntities(tMatch[1]).slice(0, 120);
        if (dMatch?.[1]) description = decodeBasicEntities(dMatch[1]).slice(0, 320);
        if (iMatch?.[1]) {
          try {
            const absImg = new URL(iMatch[1], parsed.origin);
            if (["http:", "https:"].includes(absImg.protocol) && !isDisallowedHost(absImg.hostname)) {
              ogImage = absImg.toString();
            }
          } catch {}
        }
      }
    } catch {}

    let generatedThumb = "";
    const thumbSlug = slugify(x.slug || title || parsed.hostname) || ("app-" + Date.now());
    if (env.MEDIA) {
      const svg = makeLinkThumbnailSvg(title, parsed.hostname);
      const key = `thumbs/${thumbSlug}.svg`;
      await env.MEDIA.put(key, svg, { httpMetadata: { contentType: "image/svg+xml; charset=utf-8" } });
      generatedThumb = `/media/${key}`;
    }
    return json({
      ok: true,
      url: parsed.toString(),
      domain: parsed.hostname,
      title,
      description,
      og_image: ogImage,
      generated_thumb: generatedThumb,
      recommended_thumb: ogImage || generatedThumb
    });
  }

  if (p === "/api/admin/translate" && method === "POST") {
    const x = await body(req);
    const text = String(x.text || "").trim().slice(0, 1500);
    const sl = x.source === "ne" ? "ne" : "en";
    const tl = x.target === "en" ? "en" : "ne";
    if (!text || sl === tl) return json({ translated: text, source: sl, target: tl });
    try {
      const r = await fetch(
        `https://translate.googleapis.com/translate_a/single?client=gtx&sl=${sl}&tl=${tl}&dt=t&q=${encodeURIComponent(text)}`,
        {
          headers: { "user-agent": "Mozilla/5.0 (compatible; GranshiCMS/1.0)" },
          signal: AbortSignal.timeout(4500)
        }
      );
      if (r.ok) {
        const data = await r.json();
        const translated = Array.isArray(data?.[0])
          ? data[0].map((part) => (Array.isArray(part) ? String(part[0] || "") : "")).join("").trim()
          : "";
        if (translated) return json({ ok: true, translated, source: sl, target: tl });
      }
    } catch {}
    return json({ ok: false, error: "Translation service temporarily unavailable.", translated: "" }, 503);
  }

  if (p === "/api/admin/notifications" && method === "GET") {
    const contactRows = await safeAll(
      env,
      "SELECT m.id,m.name,m.email,m.subject,m.body,m.created_at,'contact' AS kind FROM messages m LEFT JOIN admin_message_reads r ON r.message_id=m.id AND r.admin_email=? WHERE r.message_id IS NULL AND (m.reply_text IS NULL OR (m.reply_text NOT LIKE ? AND m.reply_text NOT LIKE ?)) ORDER BY m.created_at DESC LIMIT 10",
      who, '{"inbound":true%', '{"outbound":true%'
    );
    const emailRows = await safeAll(
      env,
      "SELECT m.id,m.name,m.email,m.subject,m.body,m.created_at,'email' AS kind FROM messages m JOIN inbound_email_events e ON e.message_id=m.id LEFT JOIN admin_message_reads r ON r.message_id=m.id AND r.admin_email=? WHERE r.message_id IS NULL AND m.reply_text LIKE ? AND m.subject NOT LIKE '[Granshi]%' ORDER BY m.created_at DESC LIMIT 10",
      who, '{"inbound":true%'
    );
    const contactUnread = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM messages m LEFT JOIN admin_message_reads r ON r.message_id=m.id AND r.admin_email=? WHERE r.message_id IS NULL AND (m.reply_text IS NULL OR (m.reply_text NOT LIKE ? AND m.reply_text NOT LIKE ?))"
    ).bind(who,'{"inbound":true%','{"outbound":true%').first();
    const emailUnread = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM messages m JOIN inbound_email_events e ON e.message_id=m.id LEFT JOIN admin_message_reads r ON r.message_id=m.id AND r.admin_email=? WHERE r.message_id IS NULL AND m.reply_text LIKE ? AND m.subject NOT LIKE '[Granshi]%'"
    ).bind(who,'{"inbound":true%').first();
    const merged = [...contactRows, ...emailRows]
      .sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))
      .slice(0, 10)
      .map((item) => ({
        id: item.id,
        kind: item.kind,
        sender: item.name || item.email || "Visitor",
        subject: item.subject || "(no subject)",
        preview: String(item.body || "").slice(0, 100),
        created_at: item.created_at
      }));
    const um = Number(contactUnread?.n || 0);
    const ue = Number(emailUnread?.n || 0);
    return json({
      unread_messages: um,
      unread_emails: ue,
      total_unread: um + ue,
      latest_items: merged
    });
  }

  if (p === "/api/admin/push/status" && method === "GET") {
    await ensurePushTable(env);
    const cfg = getVapidConfig(env);
    const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM push_subscriptions").first().catch(() => ({ n: 0 }));
    return json({
      configured: cfg.configured,
      publicKey: cfg.publicKey,
      subject: cfg.subject,
      subscriptionCount: Number(row?.n || 0)
    });
  }
  if (p === "/api/admin/push/subscribe" && method === "POST") {
    await ensurePushTable(env);
    const x = await body(req);
    const endpoint = String(x.endpoint || "").trim();
    const p256dh = String(x.keys?.p256dh || "").trim();
    const authKey = String(x.keys?.auth || "").trim();
    if (!isSafePushEndpoint(endpoint)) return json({ error: "Valid HTTPS push endpoint required." }, 400);
    try {
      const pub = unb64(p256dh);
      const authBytes = unb64(authKey);
      if (pub.length !== 65 || pub[0] !== 4 || authBytes.length !== 16) {
        return json({ error: "Invalid browser push encryption keys." }, 400);
      }
    } catch {
      return json({ error: "Malformed push encryption keys." }, 400);
    }
    const now = new Date().toISOString();
    const ua = String(req.headers.get("user-agent") || "").slice(0, 200);
    await env.DB.prepare(
      "INSERT INTO push_subscriptions(admin_email,endpoint,p256dh,auth,user_agent,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET admin_email=excluded.admin_email,p256dh=excluded.p256dh,auth=excluded.auth,user_agent=excluded.user_agent,updated_at=excluded.updated_at"
    ).bind(who, endpoint, p256dh, authKey, ua, now, now).run();
    return json({ ok: true });
  }
  if (p === "/api/admin/push/unsubscribe" && method === "POST") {
    await ensurePushTable(env);
    const x = await body(req);
    const endpoint = String(x.endpoint || "").trim();
    if (endpoint) {
      await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint=?").bind(endpoint).run();
    }
    return json({ ok: true });
  }
  if (p === "/api/admin/push/test" && method === "POST") {
    const cfg = getVapidConfig(env);
    if (!cfg.configured) return json({ error: "VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY secrets are not configured yet." }, 400);
    const res = await notifyAdminsPush(env, {
      title: "Granshi Background Push Ready ✓",
      body: "Alerts will arrive even when the browser or app is closed.",
      url: "/admin#messages",
      tag: "granshi-push-test"
    });
    return json({ ok: res.sent > 0, ...res });
  }

  if (p === "/api/admin/overview") {
    const pub = await allPublic(env);
    await ensureQaPopulated(env);
    const qaCnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM site_qa_index").first().catch(() => ({ n: 0 }));
    const contactUnread = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM messages m LEFT JOIN admin_message_reads r ON r.message_id=m.id AND r.admin_email=? WHERE r.message_id IS NULL AND (m.reply_text IS NULL OR (m.reply_text NOT LIKE ? AND m.reply_text NOT LIKE ?))"
    ).bind(who,'{"inbound":true%','{"outbound":true%').first();
    const emailUnread = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM messages m JOIN inbound_email_events e ON e.message_id=m.id LEFT JOIN admin_message_reads r ON r.message_id=m.id AND r.admin_email=? WHERE r.message_id IS NULL AND m.reply_text LIKE ? AND m.subject NOT LIKE '[Granshi]%'"
    ).bind(who,'{"inbound":true%').first();
    return json({ email: who, new_messages: contactUnread?.n || 0, unread_emails: emailUnread?.n || 0, qa_count: Number(qaCnt?.n || 0), ...pub });
  }

  // Mark either a Contact Us message or an inbound mailbox email as read for this admin.
  if (p.match(/^\/api\/admin\/read\/\d+$/) && method === "POST") {
    const id = Number(p.split("/").pop());
    const row = await env.DB.prepare("SELECT id FROM messages WHERE id=?").bind(id).first();
    if (!row) return json({ error: "Message not found." }, 404);
    await env.DB.prepare("INSERT INTO admin_message_reads(admin_email,message_id,read_at) VALUES(?,?,?) ON CONFLICT(admin_email,message_id) DO NOTHING")
      .bind(who,id,new Date().toISOString()).run();
    return json({ ok: true, read: true });
  }

  // R2 inventory is a point-in-time object listing, not Cloudflare's billable GB-month metric.
  if (p === "/api/admin/storage" && method === "GET") {
    if (!env.MEDIA) return json({ error: "R2 binding MEDIA is not available." }, 503);
    let cursor, bytes=0, objects=0, pages=0, truncated=false;
    do {
      const batch = await env.MEDIA.list({ limit: 1000, ...(cursor ? { cursor } : {}) });
      for (const object of (batch.objects || [])) { bytes += Number(object.size || 0); objects++; }
      pages++;
      truncated = !!batch.truncated;
      cursor = batch.truncated ? batch.cursor : undefined;
      if (pages >= 100 && truncated) break;
    } while (truncated);
    const freeBytes = 10 * 1000 * 1000 * 1000;
    return json({ ok:true, bytes, objects, pages_scanned:pages, complete:!truncated,
      free_tier_bytes:freeBytes, percent_of_free_tier:Math.round(bytes/freeBytes*10000)/100,
      note:"Observed current object sizes. Cloudflare bills storage by monthly GB-month average; this is not the invoice usage meter." });
  }

  if (p === "/api/admin/diagnostics" && method === "GET") {
    const checks=[];
    try { await env.DB.prepare("SELECT 1 AS ok").first(); checks.push({id:"d1",label:"D1 database connection",ok:true,detail:"SELECT 1 succeeded"}); }
    catch(e) { checks.push({id:"d1",label:"D1 database connection",ok:false,detail:String(e).slice(0,300),fix:"Check the Worker D1 binding named DB and database availability."}); }
    for (const [table,sql] of [
      ["pages","SELECT COUNT(*) AS n FROM pages"],
      ["departments","SELECT COUNT(*) AS n FROM departments"],
      ["messages","SELECT COUNT(*) AS n FROM messages"],
      ["admin_message_reads","SELECT COUNT(*) AS n FROM admin_message_reads"],
      ["inbound_email_events","SELECT COUNT(*) AS n FROM inbound_email_events"]
    ]) {
      try { const result=await env.DB.prepare(sql).first(); checks.push({id:"table_"+table,label:"Database table: "+table,ok:true,detail:"Accessible · "+Number(result?.n||0)+" rows"}); }
      catch(e) { checks.push({id:"table_"+table,label:"Database table: "+table,ok:false,detail:String(e).slice(0,250),fix:"Apply the pending D1 migration or verify the schema."}); }
    }
    try { if(!env.MEDIA) throw new Error("MEDIA binding missing"); await env.MEDIA.list({limit:1}); checks.push({id:"r2",label:"R2 storage connection",ok:true,detail:"Bucket listing succeeded"}); }
    catch(e) { checks.push({id:"r2",label:"R2 storage connection",ok:false,detail:String(e).slice(0,250),fix:"Check the Worker R2 binding named MEDIA and bucket granshi-media."}); }
    checks.push({id:"email",label:"Resend configuration",ok:!!env.RESEND_API_KEY,detail:env.RESEND_API_KEY?"RESEND_API_KEY is configured":"RESEND_API_KEY is not configured",fix:"If email features are needed, configure the Resend API key as a Worker secret."});
    checks.push({id:"webhook",label:"Resend webhook verification",ok:!!env.RESEND_WEBHOOK_SECRET,detail:env.RESEND_WEBHOOK_SECRET?"Webhook secret is configured":"Webhook secret is not configured",fix:"Configure RESEND_WEBHOOK_SECRET and verify the endpoint in Resend."});
    return json({ok:checks.every(x=>x.ok),checks,checked_at:new Date().toISOString(),
      limitations:["This check cannot read Cloudflare dashboard billing metrics or Worker runtime logs.","Public pages and browser-side errors are checked separately by the Admin browser."]});
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
    const media = await safeAll(
      env,
      "SELECT * FROM media WHERE department_id=? OR (department_id IS NULL AND page_slug IN (SELECT slug FROM pages WHERE department_id=?)) ORDER BY created_at DESC LIMIT 250",
      id,
      id
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
    const sourceType = x.source_type === "zip" ? "zip" : x.source_type === "link" ? "link" : "blocks";
    const entryFile = String(x.entry_file || "index.html").replace(/^\/+/, "");
    let externalUrl = "";
    if (sourceType === "link") {
      const rawUrl = String(x.external_url || "").trim();
      let parsedUrl;
      try { parsedUrl = new URL(rawUrl); } catch { return json({ error: "Valid https:// external app URL required." }, 400); }
      if (!["http:", "https:"].includes(parsedUrl.protocol) || isDisallowedHost(parsedUrl.hostname)) {
        return json({ error: "Only public http/https URLs are allowed." }, 400);
      }
      externalUrl = parsedUrl.toString();
    }
    const contentStr =
      typeof x.content === "string"
        ? x.content
        : JSON.stringify(x.content || (sourceType === "link" ? { url: externalUrl } : []));
    const updatedAt = new Date().toISOString();
    let thumbnailImage = String(x.thumbnail_image || "").trim().slice(0, 1000);
    if (!thumbnailImage && sourceType === "blocks") {
      try { const blocks=JSON.parse(contentStr); const first=blocks.find(b=>b&&((b.type==="image"&&b.url)||(b.type==="hero"&&b.image))); if(first) thumbnailImage=String(first.url||first.image||"").slice(0,1000); } catch {}
    }
    if (!thumbnailImage && sourceType === "zip") {
      const media = await env.DB.prepare("SELECT url FROM media WHERE page_slug=? AND content_type LIKE 'image/%' ORDER BY created_at LIMIT 1").bind(slug).first();
      if (media) thumbnailImage = media.url;
    }
    if (!thumbnailImage && sourceType === "link" && env.MEDIA) {
      let hostLabel = "app";
      try { hostLabel = new URL(externalUrl).hostname; } catch {}
      const svg = makeLinkThumbnailSvg(x.title_en, hostLabel);
      const key = `thumbs/${slug}.svg`;
      await env.MEDIA.put(key, svg, { httpMetadata: { contentType: "image/svg+xml; charset=utf-8" } });
      thumbnailImage = `/media/${key}`;
    }
    let searchText = sourceType === "link"
      ? [x.title_en, x.title_ne, x.description_en, x.description_ne, x.thumbnail_summary_en, x.thumbnail_summary_ne, externalUrl].filter(Boolean).join(" ")
      : searchablePageText(contentStr);
    let rawHtml = "";
    if (sourceType === "zip" && env.MEDIA) {
      const entryObject = await env.MEDIA.get(`pages/${slug}/${entryFile}`);
      if (entryObject) {
        rawHtml = await entryObject.text();
        searchText = htmlToSearchText(rawHtml);
        const extractedCover = zipCoverFromHtml(rawHtml, slug);
        if (!x.thumbnail_image && extractedCover) thumbnailImage = extractedCover;
      }
    }
    const templateValue = sourceType === "zip" ? `zip:${entryFile}` : sourceType === "link" ? `link:${externalUrl}` : (x.template || "default");
    await env.DB.prepare(
      `INSERT INTO pages(slug,title_en,title_ne,description_en,description_ne,content,template,department_id,category_id,is_popular,published,sort_order,updated_at,thumbnail_image,thumbnail_title_en,thumbnail_title_ne,thumbnail_summary_en,thumbnail_summary_ne,thumbnail_alt,thumbnail_focal_x,thumbnail_focal_y)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(slug) DO UPDATE SET title_en=excluded.title_en,title_ne=excluded.title_ne,description_en=excluded.description_en,description_ne=excluded.description_ne,content=excluded.content,template=excluded.template,department_id=excluded.department_id,category_id=excluded.category_id,is_popular=excluded.is_popular,published=excluded.published,sort_order=excluded.sort_order,updated_at=excluded.updated_at,thumbnail_image=excluded.thumbnail_image,thumbnail_title_en=excluded.thumbnail_title_en,thumbnail_title_ne=excluded.thumbnail_title_ne,thumbnail_summary_en=excluded.thumbnail_summary_en,thumbnail_summary_ne=excluded.thumbnail_summary_ne,thumbnail_alt=excluded.thumbnail_alt,thumbnail_focal_x=excluded.thumbnail_focal_x,thumbnail_focal_y=excluded.thumbnail_focal_y`
    ).bind(slug,x.title_en,x.title_ne||"",x.description_en||"",x.description_ne||"",contentStr,templateValue,x.department_id||null,x.category_id||null,x.is_popular?1:0,x.published?1:0,Number(x.sort_order||0),updatedAt,thumbnailImage,String(x.thumbnail_title_en||"").slice(0,180),String(x.thumbnail_title_ne||"").slice(0,180),String(x.thumbnail_summary_en||x.description_en||searchText.slice(0,260)).slice(0,400),String(x.thumbnail_summary_ne||x.description_ne||searchText.slice(0,260)).slice(0,400),String(x.thumbnail_alt||"").slice(0,250),Math.max(0,Math.min(100,Number(x.thumbnail_focal_x??50))),Math.max(0,Math.min(100,Number(x.thumbnail_focal_y??50)))).run();
    if (x.published) {
      await env.DB.prepare("INSERT INTO page_search_index(page_slug,title,description,body_text,department_id,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(page_slug) DO UPDATE SET title=excluded.title,description=excluded.description,body_text=excluded.body_text,department_id=excluded.department_id,updated_at=excluded.updated_at")
        .bind(slug,[x.title_en,x.title_ne].join(" "),[x.description_en,x.description_ne].join(" "),searchText,x.department_id||null,updatedAt).run();
    } else {
      await env.DB.prepare("DELETE FROM page_search_index WHERE page_slug=?").bind(slug).run();
    }
    await syncPageQa(env, {
      slug,
      title_en: x.title_en,
      title_ne: x.title_ne || "",
      description_en: x.description_en || "",
      description_ne: x.description_ne || "",
      thumbnail_summary_en: x.thumbnail_summary_en || "",
      thumbnail_summary_ne: x.thumbnail_summary_ne || "",
      template: templateValue,
      content: contentStr,
      published: !!x.published
    }, searchText, rawHtml);
    return json({
      ok: true,
      slug,
      source_type: sourceType,
      entry_file: entryFile,
      thumbnail_image: thumbnailImage,
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
    const slug = decodeURIComponent(p.slice("/api/admin/pages/".length));
    const mediaRows = await safeAll(env, "SELECT key FROM media WHERE page_slug=?", slug);
    if (env.MEDIA) {
      for (const row of mediaRows) {
        if (row?.key) { try { await env.MEDIA.delete(row.key); } catch {} }
      }
      try { await env.MEDIA.delete(`thumbs/${slug}.svg`); } catch {}
    }
    await env.DB.prepare("DELETE FROM media WHERE page_slug=?").bind(slug).run();
    await env.DB.prepare("DELETE FROM pages WHERE slug=?").bind(slug).run();
    await env.DB.prepare("DELETE FROM page_search_index WHERE page_slug=?").bind(slug).run();
    try { await env.DB.prepare("DELETE FROM site_qa_index WHERE page_slug=?").bind(slug).run(); } catch {}
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
          x.visible === false ? 0 : 1,
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
    await syncSiteProfileQa(env, await getSettings(env));
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
    const key = decodeURIComponent(p.slice("/api/admin/media/".length));
    if (!key || key.includes("..")) return json({ error: "Invalid media key." }, 400);
    if (env.MEDIA) await env.MEDIA.delete(key);
    await env.DB.prepare("DELETE FROM media WHERE key=?").bind(key).run();
    return json({ ok: true });
  }

  // Messages + reply (text + optional attachments)
  if (p === "/api/admin/messages/sync" && method === "POST") {
    if (!env.RESEND_API_KEY || !env.DB) return json({error:"Resend receiving is not configured."},503);
    let imported=0, scanned=0, after="";
    try {
      for(let page=0;page<10;page++){
        const endpoint=new URL("https://api.resend.com/emails/receiving");
        endpoint.searchParams.set("limit","100");
        if(after) endpoint.searchParams.set("after",after);
        const response=await fetch(endpoint.toString(),{headers:{Authorization:"Bearer "+env.RESEND_API_KEY}});
        if(!response.ok) return json({error:"Resend inbox list failed: "+(await response.text()).slice(0,300)},502);
        const payload=await response.json(), data=payload.data||payload;
        const items=Array.isArray(data)?data:(data.data||[]);
        if(!items.length) break;
        for(const item of items){scanned++;const id=String(item.id||item.email_id||"");if(id&&await importReceivedEmail(env,id,item)) imported++;}
        const hasMore=Boolean(data.has_more||payload.has_more);
        after=String(items[items.length-1].id||items[items.length-1].email_id||"");
        if(!hasMore||!after) break;
      }
      return json({ok:true,imported,scanned});
    } catch(error){return json({error:String(error).slice(0,400),imported,scanned},502);}
  }
  // Keep Contact Us messages separate from the real info@ mailbox.
  if (p === "/api/admin/email" && method === "GET") {
    const folder = u.searchParams.get("folder") === "sent" ? "sent" : "inbox";
    if(folder==="sent"){
      const rows=await env.DB.prepare("SELECT m.*,1 AS is_read FROM messages m WHERE m.reply_text LIKE ? ORDER BY m.created_at DESC LIMIT 300").bind('{"outbound":true%').all();
      return json(rows.results||[]);
    }
    const rows=await env.DB.prepare("SELECT m.*,CASE WHEN r.message_id IS NULL THEN 0 ELSE 1 END AS is_read FROM messages m JOIN inbound_email_events e ON e.message_id=m.id LEFT JOIN admin_message_reads r ON r.message_id=m.id AND r.admin_email=? WHERE m.reply_text LIKE ? AND m.subject NOT LIKE '[Granshi]%' ORDER BY m.created_at DESC LIMIT 500").bind(who,'{"inbound":true%').all();
    const allowed=[];
    for(const row of (rows.results||[])){
      const event=await env.DB.prepare("SELECT recipients FROM inbound_email_events WHERE message_id=? LIMIT 1").bind(row.id).first();
      let recipients=[];try{recipients=JSON.parse(event?.recipients||"[]")}catch{}
      const addresses=recipients.map(v=>{const s=String(v||"").toLowerCase();const match=s.match(/<([^>]+)>/);return (match?match[1]:s).trim()});
      if(addresses.includes("info@gopalkoirala.com.np"))allowed.push(row);
    }
    return json(allowed.slice(0,300));
  }
  if (p === "/api/admin/email/send" && method === "POST") {
    const x = await body(req), to = String(x.to || "").trim().slice(0,180);
    const subject = String(x.subject || "").trim().slice(0,200), textBody = String(x.body || "").trim().slice(0,20000);
    const attachments = Array.isArray(x.attachments) ? x.attachments.slice(0,10) : [];
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return json({error:"Valid recipient email required."},400);
    if (!subject || !textBody) return json({error:"Subject and message are required."},400);
    const absUrl = (rawUrl) => { const v = String(rawUrl || ""); return v.startsWith("/") ? u.origin + v : v; };
    const attHtml = attachments.map(a=>'<p>Attachment: <a href="'+escapeHtml(absUrl(a.url))+'">'+escapeHtml(a.name||"file")+'</a></p>').join("");
    const html = '<div style="font:15px/1.7 Arial,sans-serif;white-space:pre-wrap">'+escapeHtml(textBody).replace(/\n/g,"<br>")+'</div>'+attHtml;
    const delivery = await sendEmail(env,{from:"info@gopalkoirala.com.np",to,subject,html,attachments});
    if (!delivery.sent) return json({error:"Email could not be sent.",detail:delivery.error||"Email service unavailable."},502);
    const stored = JSON.stringify({outbound:true,from:"info@gopalkoirala.com.np",attachments});
    await env.DB.prepare("INSERT INTO messages(department_id,name,email,subject,body,status,created_at,reply_text,replied_at) VALUES(NULL,?,?,?,?,?,?,?,?)").bind("Granshi",to,subject,textBody,"sent",new Date().toISOString(),stored,null).run();
    return json({ok:true});
  }
  if (p.match(/^\/api\/admin\/email\/\d+$/) && method === "DELETE") {
    const id=Number(p.split("/").pop());
    const row=await env.DB.prepare("SELECT id,reply_text FROM messages WHERE id=?").bind(id).first();
    if(!row || !(String(row.reply_text||"").startsWith('{"inbound":true') || String(row.reply_text||"").startsWith('{"outbound":true'))) return json({error:"Email not found."},404);
    // Keep the Resend event as a tombstone so manual Sync cannot restore a deleted email.
    await env.DB.prepare("UPDATE inbound_email_events SET message_id=NULL WHERE message_id=?").bind(id).run();
    await env.DB.prepare("DELETE FROM messages WHERE id=?").bind(id).run();
    return json({ok:true});
  }
  if (p.match(/^\/api\/admin\/email\/\d+\/reply$/) && method === "POST") {
    const id = p.split("/")[4], x = await body(req);
    const subject = String(x.subject || "").trim().slice(0,200), textBody = String(x.body || "").trim().slice(0,20000);
    const attachments = Array.isArray(x.attachments) ? x.attachments.slice(0,10) : [];
    const original = await env.DB.prepare("SELECT * FROM messages WHERE id=? AND reply_text LIKE ?").bind(id,'{"inbound":true%').first();
    if (!original) return json({error:"Incoming email not found."},404);
    if (!subject || !textBody) return json({error:"Subject and message are required."},400);
    const absUrl = (rawUrl) => { const v = String(rawUrl || ""); return v.startsWith("/") ? u.origin + v : v; };
    const attHtml = attachments.map(a=>'<p>Attachment: <a href="'+escapeHtml(absUrl(a.url))+'">'+escapeHtml(a.name||"file")+'</a></p>').join("");
    const html = '<div style="font:15px/1.7 Arial,sans-serif;white-space:pre-wrap">'+escapeHtml(textBody).replace(/\n/g,"<br>")+'</div>'+attHtml;
    const delivery = await sendEmail(env,{from:"info@gopalkoirala.com.np",to:original.email,subject,html,attachments});
    if (!delivery.sent) return json({error:"Reply could not be sent.",detail:delivery.error||"Email service unavailable."},502);
    const stored = JSON.stringify({outbound:true,from:"info@gopalkoirala.com.np",in_reply_to:Number(id),attachments});
    await env.DB.prepare("INSERT INTO messages(department_id,name,email,subject,body,status,created_at,reply_text,replied_at) VALUES(NULL,?,?,?,?,?,?,?,?)").bind("Granshi",original.email,subject,textBody,"sent",new Date().toISOString(),stored,null).run();
    return json({ok:true});
  }
  if (p === "/api/admin/messages" && method === "GET") {
    return json((await env.DB.prepare("SELECT m.*,d.name_en AS department_name,CASE WHEN r.message_id IS NULL THEN 0 ELSE 1 END AS is_read FROM messages m LEFT JOIN departments d ON d.id=m.department_id LEFT JOIN admin_message_reads r ON r.message_id=m.id AND r.admin_email=? WHERE (m.reply_text IS NULL OR (m.reply_text NOT LIKE ? AND m.reply_text NOT LIKE ?)) ORDER BY m.created_at DESC LIMIT 300").bind(who,'{"inbound":true%','{"outbound":true%').all()).results || []);
  }
  // Upload reply attachment → returns url (call before reply POST)
  if (p === "/api/admin/messages/attach" && method === "POST") {
    if (!env.MEDIA) return json({ error: "R2 not configured." }, 503);
    const file = await req.arrayBuffer();
    const type = req.headers.get("content-type") || "application/octet-stream";
    const name = decodeURIComponent(
      req.headers.get("x-file-name") || "attach.bin"
    ).replace(/[^a-zA-Z0-9._-]/g, "_");
    if (file.byteLength > 2 * 1024 * 1024)
      return json({ error: "Attachment max 2 MB after compression." }, 413);
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
    const absUrl = (rawUrl) => { const v = String(rawUrl || ""); return v.startsWith("/") ? u.origin + v : v; };
    const attHtml = attachments
      .map((a) => {
        const href = escapeHtml(absUrl(a.url || ""));
        const n = escapeHtml(a.name || "file");
        const isImg =
          /\.(png|jpe?g|gif|webp)$/i.test(a.name || "") ||
          (a.content_type || "").startsWith("image/");
        if (isImg)
          return `<p><a href="${href}"><img src="${href}" alt="${n}" style="max-width:240px;border-radius:8px"></a></p>`;
        return `<p>Attachment: <a href="${href}">${n}</a></p>`;
      })
      .join("");
    const contactFooter = "थप सहयोग वा जानकारी आवश्यक परे हामीलाई info@gopalkoirala.com.np मा सिधै इमेल गर्नुहोला।";
    const finalReply = reply + "\n\n" + contactFooter;
    const storedReply = attachments.length > 0 ? finalReply + "\n\n<!--ATTACH:" + JSON.stringify(attachments) + "-->" : finalReply;
    const delivery = await sendEmail(env, {
      from: "noreply@gopalkoirala.com.np",
      replyTo: "info@gopalkoirala.com.np",
      to: msg.email,
      subject: `Re: ${msg.subject || "Your message to Granshi"}`,
      html: "<p>Hello " + escapeHtml(msg.name) + ",</p><p>" + escapeHtml(reply).replace(/\n/g, "<br>") + "</p>" + attHtml + "<p style='margin-top:22px;padding-top:14px;border-top:1px solid #ddd'>" + escapeHtml(contactFooter) + "</p><hr><p>Original: " + escapeHtml(msg.body || "") + "</p>",
      attachments,
    });
    if (!delivery.sent) return json({ error: "Reply could not be sent.", detail: delivery.error || "Email service unavailable." }, 502);
    await env.DB.prepare("UPDATE messages SET reply_text=?,replied_at=?,status=? WHERE id=?").bind(storedReply, new Date().toISOString(), "replied", id).run();
    return json({ ok: true });
  }
  if (p.startsWith("/api/admin/messages/") && method === "POST") {
    const x = await body(req);
    if (["new", "replied", "archived"].includes(x.status))
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
      "UPDATE admins SET salt=?,password_hash=?,session_version=session_version+1,failed_login_attempts=0 WHERE email=?"
    ).bind(h.salt, h.hash, who).run();
    return json({ ok: true }, 200, { "set-cookie": clearCookie });
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

function commentsWidgetHtml(slug, lang = "en") {
  const s = escapeHtml(slug);
  const ne = lang === "ne";
  return ` <section id="granshi-comments" class="g-comments" data-slug="${s}"> <h2 class="g-c-title">${ne ? "प्रतिक्रिया तथा टिप्पणी" : "Comments & Feedback"}</h2> <div id="g-c-list" class="g-c-list"><p class="g-c-muted">${ne ? "लोड हुँदैछ…" : "Loading…"}</p></div> <button type="button" id="g-c-open" class="g-c-open" aria-expanded="false" aria-controls="g-c-form">${ne ? "टिप्पणी लेख्नुहोस्" : "Leave a comment"}</button> <form id="g-c-form" class="g-c-form" hidden> <p class="g-c-muted">${ne ? "आफ्नो विचार साझा गर्नुहोस्। स्वीकृतिपछि टिप्पणी यहाँ देखिनेछ।" : "Share your thoughts. Comments appear here after approval."}</p> <label>${ne ? "नाम *" : "Name *"}</label> <input name="name" required maxlength="80" autocomplete="name"> <label>${ne ? "इमेल (वैकल्पिक)" : "Email (optional)"}</label> <input name="email" type="email" maxlength="180" autocomplete="email"> <label style="position:absolute;left:-9999px">Website</label> <input name="website" tabindex="-1" autocomplete="off" style="position:absolute;left:-9999px"> <label>${ne ? "टिप्पणी *" : "Comment *"}</label> <textarea name="body" required maxlength="2000" rows="4"></textarea> <button type="submit">${ne ? "पठाउनुहोस्" : "Submit feedback"}</button> <p id="g-c-msg" class="g-c-msg"></p> </form> </section> <style> .g-comments{max-width:800px;margin:32px auto 48px;padding:28px 4%;border-top:1px solid #e5e7eb;font-family:"Plus Jakarta Sans","Noto Sans Devanagari",system-ui,sans-serif;color:#111827} .g-c-title{font-family:"Fraunces","Noto Sans Devanagari",Georgia,serif;font-size:1.35rem;margin:0 0 16px} .g-c-list{margin-bottom:18px} .g-c-item{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:14px 16px;margin:10px 0} .g-c-item b{font-size:14px}.g-c-item time{font-size:12px;color:#525d70;margin-left:8px;font-variant-numeric:tabular-nums} .g-c-item p{margin:8px 0 0;line-height:1.6;white-space:pre-wrap;font-size:14.5px;color:#27303f} .g-c-muted{color:#525d70;font-size:13.5px} .g-c-open{display:inline-flex;align-items:center;padding:10px 16px;border:1px solid #d1d5db;border-radius:8px;background:#fff;color:#111827;font:600 13.5px "Plus Jakarta Sans","Noto Sans Devanagari",system-ui,sans-serif;cursor:pointer} .g-c-open:hover{border-color:#111827} .g-c-form[hidden]{display:none!important} .g-c-form{margin-top:18px;padding:18px;background:#fff;border:1px solid #e5e7eb;border-radius:12px} .g-c-form label{display:block;font-size:12.5px;font-weight:600;margin:10px 0 4px} .g-c-form input,.g-c-form textarea{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font:inherit;box-sizing:border-box;background:#faf9f6} .g-c-form button[type=submit]{margin-top:12px;padding:10px 18px;border:0;border-radius:8px;background:#0f172a;color:#fff;font-weight:600;cursor:pointer} .g-c-msg{font-size:13px;margin-top:8px}.g-c-msg.ok{color:#166534}.g-c-msg.err{color:#b91c1c} </style> <script> (function(){ var root=document.getElementById('granshi-comments'); if(!root)return; var slug=root.getAttribute('data-slug'); var list=document.getElementById('g-c-list'); var form=document.getElementById('g-c-form'); var openBtn=document.getElementById('g-c-open'); var msg=document.getElementById('g-c-msg'); openBtn.addEventListener('click',function(){form.hidden=false;openBtn.setAttribute('aria-expanded','true');openBtn.hidden=true;var first=form.querySelector('input[name="name"]');if(first)first.focus()}); function esc(t){return String(t||'').replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})} function load(){ fetch('/api/comments?slug='+encodeURIComponent(slug)).then(function(r){return r.json()}).then(function(d){ var rows=d.comments||[]; if(!rows.length){list.innerHTML='<p class="g-c-muted">${ne ? "अहिलेसम्म कुनै टिप्पणी छैन।" : "No comments yet."}</p>';return} list.innerHTML=rows.map(function(c){ var t=(c.created_at||'').replace('T',' ').slice(0,16); return '<div class="g-c-item"><b>'+esc(c.name)+'</b><time>'+esc(t)+'</time><p>'+esc(c.body)+'</p></div>'; }).join(''); }).catch(function(){list.innerHTML='<p class="g-c-muted">${ne ? "टिप्पणी लोड गर्न सकिएन।" : "Could not load comments."}</p>'}); } form.addEventListener('submit',function(e){ e.preventDefault(); msg.className='g-c-msg';msg.textContent='${ne ? "पठाइँदैछ…" : "Sending…"}'; var fd=new FormData(form); fetch('/api/comments',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ page_slug:slug,name:fd.get('name'),email:fd.get('email'),body:fd.get('body'),website:fd.get('website') })}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d}})}).then(function(x){ if(!x.ok)throw new Error(x.d.error||'Failed'); msg.className='g-c-msg ok';msg.textContent=x.d.message||'Thank you!'; form.reset(); }).catch(function(err){msg.className='g-c-msg err';msg.textContent=err.message||'Error'}); }); load(); })(); </script>`;
}

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runScheduledDiagnosis(env,controller.scheduledTime).catch(e=>console.error("Nightly diagnosis failed",e)));
  },
  async fetch(req, env, ctx) {
    const u = new URL(req.url);
    // Public SEO routes: generate from currently published database content.
    if (u.pathname === "/sitemap.xml") {
      const origin = u.origin;
      const xmlEscape = (value) => String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
      const urls = new Map();
      const addUrl = (path, updatedAt = "") => {
        const loc = origin + path;
        const entry = { loc, updatedAt: String(updatedAt || "") };
        const previous = urls.get(loc);
        if (!previous || entry.updatedAt > previous.updatedAt) urls.set(loc, entry);
      };
      addUrl("/");
      const pages = await safeAll(env, "SELECT slug,updated_at FROM pages WHERE published=1 AND slug IS NOT NULL AND slug<>'' ORDER BY updated_at DESC LIMIT 5000");
      for (const page of pages) addUrl("/" + encodeURIComponent(String(page.slug).split("/").pop()), page.updated_at);
      const departments = await safeAll(env, "SELECT slug FROM departments WHERE visible=1 AND slug IS NOT NULL AND slug<>'' ORDER BY sort_order LIMIT 500");
      for (const dept of departments) addUrl("/dept/" + encodeURIComponent(dept.slug));
      for (const slug of ["about","contact","privacy","terms","disclaimer","cookies","copyright"]) addUrl("/legal/" + slug);
      const entries = [...urls.values()].sort((a,b) => a.loc.localeCompare(b.loc)).map(item =>
        "<url><loc>" + xmlEscape(item.loc) + "</loc>" +
        (item.updatedAt && !Number.isNaN(Date.parse(item.updatedAt)) ? "<lastmod>" + new Date(item.updatedAt).toISOString() + "</lastmod>" : "") +
        "</url>"
      ).join("");
      return new Response('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + entries + "</urlset>", {
        headers: { "content-type": "application/xml; charset=utf-8", "cache-control": "public, max-age=300" }
      });
    }
    if (u.pathname === "/robots.txt") {
      return new Response("User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\nDisallow: /_preview/\nSitemap: " + u.origin + "/sitemap.xml\n", {
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=300" }
      });
    }
    if (u.pathname === "/sitemap") {
      const settings = await getSettings(env);
      const lang = u.searchParams.get("lang") === "ne" ? "ne" : "en";
      const depts = await safeAll(env, "SELECT id,slug,name_en,name_ne FROM departments WHERE visible=1 ORDER BY sort_order LIMIT 200");
      const pgs = await safeAll(env, "SELECT slug,title_en,title_ne,updated_at FROM pages WHERE published=1 ORDER BY updated_at DESC LIMIT 500");
      const title = lang === "ne" ? "वेबसाइट निर्देशिका (Sitemap)" : "Site Directory";
      const deptLinks = depts.map(d => `<li><a href="/dept/${escapeHtml(d.slug||d.id)}?lang=${lang}">${escapeHtml(lang==="ne"&&d.name_ne?d.name_ne:d.name_en)}</a></li>`).join("");
      const pageLinks = pgs.map(p => `<li><a href="/${escapeHtml(p.slug)}?lang=${lang}">${escapeHtml(lang==="ne"&&p.title_ne?p.title_ne:p.title_en)}</a> <small style="color:#64748b">${escapeHtml(String(p.updated_at||"").slice(0,10))}</small></li>`).join("");
      const legalLinks = ["about","contact","privacy","terms","disclaimer","cookies","copyright"].map(s => `<li><a href="/legal/${s}?lang=${lang}">${escapeHtml(s[0].toUpperCase()+s.slice(1))}</a></li>`).join("");
      const bodyHtml = `<section class="page-hero"><div class="wrap"><h1>${escapeHtml(title)}</h1><p>${lang==="ne"?"वेबसाइटमा प्रकाशित विभाग, लेख, उपकरण तथा नीति पृष्ठहरूको पूर्ण सूची। (Search Engine का लागि XML संस्करण /sitemap.xml मा उपलब्ध छ।)":"Complete directory of published departments, articles, tools, and policy pages. (Machine-readable XML for search engines lives at /sitemap.xml.)"}</p></div></section><article class="wrap"><div class="blk-cols"><div><h2 class="blk-h" style="margin-top:0">${lang==="ne"?"विभागहरू":"Departments"}</h2><ul style="line-height:2">${deptLinks||"<li>—</li>"}</ul><h2 class="blk-h">${lang==="ne"?"जानकारी तथा नीतिहरू":"Information & Policies"}</h2><ul style="line-height:2">${legalLinks}</ul></div><div><h2 class="blk-h" style="margin-top:0">${lang==="ne"?"प्रकाशित पेज तथा उपकरणहरू":"Published Pages & Tools"}</h2><ul style="line-height:2">${pageLinks||"<li>—</li>"}</ul></div></div></article>`;
      return new Response(pageChrome(title, "Site directory and published links", bodyHtml, settings, lang), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=120" } });
    }
    if (u.pathname.startsWith("/api/")) {
      try {
        return await api(req, env, ctx);
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
    // Editable public information and policy pages.

    if (u.pathname.startsWith('/legal/')) {
      const slug = u.pathname.slice(7).replace(/\/$/, '');
      const settings = await getSettings(env);
      const contactEmail = (settings.contact_email && settings.contact_email !== "hello@gopalkoirala.com.np")
        ? settings.contact_email
        : "info@gopalkoirala.com.np";
      const defs = {
        about: [
          "About Granshi",
          "ग्रान्शीको बारेमा",
          `Granshi is an independently operated personal website created to share practical knowledge, learning guides, useful tools, creative work and personal projects.\n\nThis site is not a government portal, public authority, school or formal institution. It is maintained as an independent digital notebook and public showcase.\n\nEvery article and tool is published in good faith with clarity in mind. Thoughtful feedback, corrections and suggestions are always welcome—when an error is pointed out, we review and update it promptly.\n\nWe never intentionally publish material to mislead, target or harm anyone. If something unintentionally causes concern, please reach out via ${contactEmail} with the page link so we can review and address it.\n\nThank you for visiting and exploring.`,
          `Granshi व्यक्तिगत प्रयासमा सञ्चालन गरिएको स्वतन्त्र डिजिटल वेबसाइट हो। यसको उद्देश्य व्यावहारिक ज्ञान, सिकाइ सामग्री, उपयोगी डिजिटल उपकरण, सिर्जनात्मक काम र व्यक्तिगत परियोजनाहरू साझा गर्नु हो।\n\nयो कुनै सरकारी वेबसाइट, सार्वजनिक निकाय, विद्यालय वा औपचारिक संस्थाको पोर्टल होइन। यो एक स्वतन्त्र व्यक्तिगत डिजिटल संग्रह र प्रकाशन मञ्च हो।\n\nयहाँका लेख र उपकरणहरू सरल, स्पष्ट र उपयोगी बनाउने प्रयास गरिएको छ। तपाईंका सुझाव, प्रश्न र सुधारका प्रतिक्रिया सधैँ स्वागत छन्—कुनै त्रुटि औँल्याइएमा हामी समीक्षा गरी सुधार गर्नेछौँ।\n\nकसैलाई हानि, भ्रम वा अपमान गर्ने उद्देश्यले कुनै सामग्री प्रकाशन गरिँदैन। यदि कुनै सामग्रीले अनपेक्षित रूपमा असुविधा पारेमा कृपया सम्बन्धित पेजको लिंकसहित ${contactEmail} मा जानकारी दिनुहोस्।\n\nभ्रमण र साथका लागि धन्यवाद।`
        ],
        contact: [
          "Contact",
          "सम्पर्क",
          `Questions, suggestions, corrections and collaboration inquiries are welcome.\n\nDirect email: ${contactEmail}\n\nYou can also send a message using the Contact form on the homepage. When reporting an issue on a specific page, please include the page URL and clear details.\n\nPlease do not send passwords, banking credentials or other sensitive personal information via email or public forms.`,
          `प्रश्न, सुझाव, सुधारका कुरा तथा सहकार्यका प्रस्तावहरू स्वागत छन्।\n\nसीधा इमेल: ${contactEmail}\n\nतपाईंले वेबसाइटको गृहपृष्ठमा रहेको सम्पर्क फारमबाट पनि सन्देश पठाउन सक्नुहुन्छ। कुनै पेजमा त्रुटि वा सुधार औँल्याउँदा सम्बन्धित पेजको लिंक र स्पष्ट विवरण राखिदिनुहोला।\n\nकृपया इमेल वा सामान्य फारममार्फत पासवर्ड, बैंक विवरण वा अन्य संवेदनशील व्यक्तिगत जानकारी नपठाउनुहोस्।`
        ],
        privacy: [
          "Privacy Policy",
          "गोपनीयता नीति",
          `Granshi is a personal website designed to respect visitor privacy and collect only the information reasonably needed to operate the site and respond to inquiries.\n\nWhen you submit the contact form, send an email or leave feedback, details such as your name, email address and message are processed solely to respond, moderate comments and maintain site security. Basic technical logs may be processed by our hosting and security infrastructure to protect and deliver the service.\n\nWe do not sell or rent visitor information to third parties. Please avoid sharing sensitive personal or financial information in public comments or contact forms.\n\nIf optional analytics or advertising services are introduced in the future, this policy will be updated accordingly along with clear consent choices where required.\n\nFor privacy inquiries or requests regarding messages you have submitted, contact ${contactEmail}.`,
          `Granshi आगन्तुकको गोपनीयताको सम्मान गर्ने व्यक्तिगत वेबसाइट हो। वेबसाइट सञ्चालन गर्न र तपाईंको सन्देशको जवाफ दिन आवश्यक न्यूनतम जानकारी मात्र प्रयोग गरिन्छ।\n\nतपाईंले सम्पर्क फारम भर्दा, इमेल पठाउँदा वा टिप्पणी लेख्दा प्राप्त नाम, इमेल ठेगाना र सन्देश जवाफ दिन, टिप्पणी व्यवस्थापन गर्न र वेबसाइट सुरक्षित राख्न मात्र प्रयोग गरिन्छ। होस्टिङ तथा सुरक्षा प्रदायकले सेवा सञ्चालनका लागि सामान्य प्राविधिक अभिलेख राख्न सक्छन्।\n\nहामी आगन्तुकका व्यक्तिगत विवरण कसैलाई बिक्री वा भाडामा दिँदैनौँ। सार्वजनिक टिप्पणी वा सामान्य फारममा संवेदनशील व्यक्तिगत वा वित्तीय विवरण नराख्नुहोला।\n\nभविष्यमा वैकल्पिक Analytics वा विज्ञापन सेवा थपिएमा आवश्यक सहमति र विवरणसहित यो नीति अद्यावधिक गरिनेछ।\n\nगोपनीयतासम्बन्धी कुनै प्रश्न वा अनुरोध भए ${contactEmail} मा सम्पर्क गर्नुहोस्।`
        ],
        terms: [
          "Terms & Conditions",
          "प्रयोगका सर्तहरू",
          "By using Granshi, you agree to browse and interact respectfully and lawfully.\n\nContent and tools on this website are provided for general information, learning and creative exploration. Please do not attempt to disrupt site services, bypass security, impersonate others or submit abusive, unlawful or infringing content.\n\nYou remain responsible for any messages or comments you submit. Content may be updated, corrected or removed at any time as the site evolves.\n\nLinks to external websites are provided for convenience; Granshi is not responsible for the content or practices of third-party sites.\n\nGranshi is a personal website, not a formal educational institution or government service. Please review the Disclaimer page for scope limitations.",
          "Granshi प्रयोग गर्दा तपाईं वेबसाइटलाई सम्मानजनक र कानुनसम्मत तरिकाले प्रयोग गर्न सहमत भएको मानिन्छ।\n\nयहाँका सामग्री र उपकरणहरू सामान्य जानकारी, सिकाइ र सिर्जनात्मक अध्ययनका लागि उपलब्ध गराइएका हुन्। वेबसाइटको सेवा अवरुद्ध गर्ने, सुरक्षा छल्ने, अरूको पहिचान नक्कल गर्ने वा अपमानजनक तथा गैरकानुनी सामग्री पठाउने कार्य नगर्नुहोस्।\n\nतपाईंले पठाउने सन्देश र टिप्पणीको जिम्मेवारी तपाईं स्वयंको हुनेछ। आवश्यकताअनुसार वेबसाइटका सामग्री अद्यावधिक, सुधार वा हटाउन सकिनेछ।\n\nबाह्य वेबसाइटका लिंकहरू सुविधाका लागि मात्र राखिएका हुन्; तिनको सामग्री वा नीतिमाथि Granshi को नियन्त्रण हुँदैन।\n\nयो स्वतन्त्र व्यक्तिगत वेबसाइट हो, औपचारिक शैक्षिक संस्था वा सरकारी सेवा होइन। थप विवरणका लागि अस्वीकरण (Disclaimer) पृष्ठ पढ्नुहोस्।"
        ],
        disclaimer: [
          "Disclaimer",
          "अस्वीकरण",
          "All articles, notes and tools on Granshi are shared in good faith for general knowledge, learning and creative purposes. Nothing published here should be taken as professional medical, legal, financial or engineering advice.\n\nWhile reasonable care is taken to ensure clarity and accuracy, content may occasionally be incomplete or outdated. Always verify important matters with qualified professionals or authoritative sources.\n\nInteractive tools, calculators and demonstrations are provided for educational convenience; outputs may be approximate.\n\nIf you spot an error or have concerns about any page, please let us know so we can review and update it.",
          "Granshi मा प्रकाशित लेख, नोट र उपकरणहरू सामान्य ज्ञान, सिकाइ र सिर्जनात्मक प्रयोजनका लागि सद्भावपूर्वक साझा गरिएका हुन्। यहाँको कुनै पनि सामग्रीलाई चिकित्सकीय, कानुनी, आर्थिक वा व्यावसायिक विशेषज्ञ सल्लाहको विकल्पका रूपमा लिनु हुँदैन।\n\nजानकारी स्पष्ट र उपयोगी बनाउने प्रयास गरिन्छ, तर कतिपय सामग्री समयसँगै पुरानो वा अपूर्ण हुन सक्छन्। महत्त्वपूर्ण निर्णय गर्नुअघि आधिकारिक स्रोत वा विज्ञबाट पुष्टि गर्नुहोस्।\n\nइन्टर्‍याक्टिभ उपकरण, क्यालकुलेटर र उदाहरणहरू सामान्य सिकाइ र प्रयोगका लागि हुन्; तिनको नतिजा अनुमानित हुन सक्छ।\n\nकुनै गल्ती वा सुधार आवश्यक देखिएमा कृपया सम्पर्क गरी जानकारी दिनुहोला।"
        ],
        cookies: [
          "Cookie Policy",
          "कुकी नीति",
          "Cookies and browser storage are small files saved in your browser to remember preferences or support core website features.\n\nGranshi currently uses essential browser storage only where needed—for example, remembering your EN/Nepali language preference and maintaining secure admin sessions.\n\nIf optional analytics or advertising cookies are introduced in the future, they will remain disabled until you are given clear information and choice where required. You can clear or manage cookies anytime through your browser settings.",
          "Cookies र Browser Storage तपाईंको ब्राउजरमा भाषा छनोट वा आधारभूत सुविधा सम्झन प्रयोग हुने साना डेटा फाइल हुन्।\n\nGranshi ले हाल आवश्यक आधारभूत कामका लागि मात्र ब्राउजर स्टोरेज प्रयोग गर्छ—जस्तै तपाईंले रोज्नुभएको अंग्रेजी/नेपाली भाषा सम्झन र सुरक्षित Admin सत्र कायम राख्न।\n\nभविष्यमा वैकल्पिक Analytics वा विज्ञापनसम्बन्धी कुकी थपिएमा आवश्यक सहमति नलिई सक्रिय गरिने छैन र यो नीति अद्यावधिक गरिनेछ। तपाईंले जुनसुकै बेला आफ्नो ब्राउजर सेटिङबाट कुकी हटाउन सक्नुहुन्छ।"
        ],
        copyright: [
          "Copyright Policy",
          "प्रतिलिपि अधिकार नीति",
          `Original writing, designs and custom tools on Granshi are the work of their creator unless otherwise noted. We respect the intellectual property of authors, photographers and developers.\n\nPlease do not copy, scrape or republish substantial parts of this website without permission or proper attribution.\n\nIf you believe any material here infringes your copyright or lacks proper credit, please email ${contactEmail} with the page URL and details so we can review, credit or remove it promptly.`,
          `अन्यथा उल्लेख गरिएको बाहेक Granshi मा प्रकाशित मौलिक लेख, डिजाइन र उपकरणहरू स्रष्टाकै सिर्जना हुन्। हामी अन्य लेखक, फोटोग्राफर र विकासकर्ताको बौद्धिक सम्पत्तिको सम्मान गर्छौँ।\n\nअनुमति वा उचित स्रोत उल्लेखबिना यस वेबसाइटका सामग्री हुबहु प्रतिलिपि वा पुनःप्रकाशन नगर्नुहोला।\n\nयदि यहाँ प्रकाशित कुनै सामग्रीले तपाईंको प्रतिलिपि अधिकार उल्लङ्घन गरेको वा श्रेय छुटेको लागेमा सम्बन्धित पेजको लिंकसहित ${contactEmail} मा इमेल गर्नुहोस्, हामी तुरुन्तै समीक्षा गरी आवश्यक सुधार वा हटाउने कदम चाल्नेछौँ।`
        ]
      };
      if (Object.prototype.hasOwnProperty.call(defs, slug)) {
        const lang = u.searchParams.get('lang') === 'ne' ? 'ne' : 'en';
        const item = defs[slug];
        const title = item[lang === 'ne' ? 1 : 0];
        const content = settings['legal_' + slug + '_' + lang] || item[lang === 'ne' ? 3 : 2];
        const kicker = lang === 'ne' ? 'जानकारी तथा नीति' : 'Information &amp; Policy';
        const contactFormHtml = slug === 'contact' ? `<div style="margin-top:28px;background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:22px"><h2 style="margin:0 0 6px;font-family:Fraunces,Georgia,serif;font-size:1.35rem">${lang==='ne'?'सीधा सन्देश पठाउनुहोस्':'Send a Direct Message'}</h2><p style="margin:0 0 16px;color:#525d70;font-size:14px">${lang==='ne'?'प्रश्न, सुझाव वा सहकार्यको लागि तलको फारम भर्नुहोस्।':'Fill out the form below for inquiries, feedback, or corrections.'}</p><form id="legalContactForm"><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px"><div><label style="display:block;font-size:12.5px;font-weight:600;margin:8px 0 4px">${lang==='ne'?'तपाईंको नाम *':'Your name *'}</label><input name="name" required maxlength="120" style="width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font:inherit"></div><div><label style="display:block;font-size:12.5px;font-weight:600;margin:8px 0 4px">${lang==='ne'?'इमेल *':'Your email *'}</label><input name="email" type="email" required maxlength="180" style="width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font:inherit"></div></div><div><label style="display:block;font-size:12.5px;font-weight:600;margin:8px 0 4px">${lang==='ne'?'विषय':'Subject'}</label><input name="subject" maxlength="200" style="width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font:inherit"></div><div><label style="display:block;font-size:12.5px;font-weight:600;margin:8px 0 4px">${lang==='ne'?'सन्देश *':'Message *'}</label><textarea name="body" required maxlength="5000" rows="4" style="width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font:inherit"></textarea></div><div style="display:flex;align-items:center;gap:12px;margin-top:14px;flex-wrap:wrap"><button type="submit" class="btn">${lang==='ne'?'सन्देश पठाउनुहोस्':'Send Message'}</button><span id="lcStatus" style="font-size:13px;font-weight:600"></span></div></form></div><script>(function(){var f=document.getElementById('legalContactForm'),st=document.getElementById('lcStatus');if(!f)return;f.addEventListener('submit',function(e){e.preventDefault();var fd=new FormData(f),btn=f.querySelector('button[type=submit]');btn.disabled=true;st.style.color='#525d70';st.textContent='${lang==='ne'?'पठाइँदैछ…':'Sending…'}';fetch('/api/contact',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:fd.get('name'),email:fd.get('email'),subject:fd.get('subject'),body:fd.get('body')})}).then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d}})}).then(function(x){if(!x.ok)throw new Error(x.d.error||'Failed');st.style.color='#166534';st.textContent='${lang==='ne'?'सन्देश पठाइयो। धन्यवाद!':'Message sent. Thank you!'}';f.reset()}).catch(function(err){st.style.color='#b91c1c';st.textContent=err.message||'Error'}).finally(function(){btn.disabled=false})})})();</script>` : '';
        const bodyHtml = '<section class="page-hero"><div class="wrap"><span style="display:block;font-size:12px;font-weight:600;letter-spacing:.06em;color:var(--gold);margin-bottom:8px">' + kicker + '</span><h1>' + escapeHtml(title) + '</h1></div></section><article class="wrap">' + content.split(/\n+/).map(x => '<p class="blk-p">' + escapeHtml(x) + '</p>').join('') + contactFormHtml + '</article>';
        return new Response(pageChrome(title, content.slice(0, 155), bodyHtml, settings, lang), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=60' } });
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
            "SELECT slug,title_en,title_ne,description_en,description_ne,thumbnail_image,thumbnail_title_en,thumbnail_title_ne,thumbnail_summary_en,thumbnail_summary_ne,thumbnail_alt,thumbnail_focal_x,thumbnail_focal_y,updated_at,content FROM pages WHERE department_id=? AND published=1 ORDER BY sort_order,updated_at DESC"
          )
            .bind(dept.id)
            .all();
          const lang = u.searchParams.get("lang") === "ne" ? "ne" : "en";
          const title =
            lang === "ne" && dept.name_ne ? dept.name_ne : dept.name_en;
          const deptLabel = lang === "ne" && dept.name_ne ? dept.name_ne : dept.name_en;
          const list = (pages.results || []).map((pg) => {
            const cardTitle = lang==="ne" && pg.thumbnail_title_ne ? pg.thumbnail_title_ne : (pg.thumbnail_title_en || (lang==="ne"&&pg.title_ne?pg.title_ne:pg.title_en));
            const image = pg.thumbnail_image
              ? `<div class="dept-card-media"><img src="${escapeHtml(pg.thumbnail_image)}" alt="${escapeHtml(pg.thumbnail_alt||cardTitle)}" loading="lazy" referrerpolicy="no-referrer" style="object-position:${Number(pg.thumbnail_focal_x??50)}% ${Number(pg.thumbnail_focal_y??50)}%"></div>`
              : `<div class="dept-card-media"><div class="dept-art"><span>${escapeHtml((cardTitle||"G").slice(0,1).toUpperCase())}</span></div></div>`;
            const summary = lang==="ne" ? (pg.thumbnail_summary_ne||pg.description_ne||pageExcerpt(searchablePageText(pg.content),"")) : (pg.thumbnail_summary_en||pg.description_en||pageExcerpt(searchablePageText(pg.content),""));
            const dateStr = pg.updated_at ? String(pg.updated_at).slice(0,10) : "";
            return `<a class="dept-page" href="/${escapeHtml(pg.slug)}${lang==="ne"?"?lang=ne":""}">${image}<div class="dept-card-copy"><div class="dept-card-meta">${escapeHtml(deptLabel)}${dateStr ? ` <span aria-hidden="true">·</span> ${escapeHtml(dateStr)}` : ""}</div><h3>${escapeHtml(cardTitle)}</h3>${summary?`<p>${escapeHtml(summary.slice(0,145))}${summary.length>145?"…":""}</p>`:""}<span class="dept-card-more">${lang==="ne"?"पूरा पढ्नुहोस् →":"Read article →"}</span></div></a>`;
          }).join("");
          const countVal = (pages.results||[]).length;
          const body = `<section class="page-hero"><div class="wrap"><span class="dept-kicker">${lang==="ne"?"विभाग":"Department"}</span><h1>${escapeHtml(title)}</h1><p>${escapeHtml(lang==="ne"&&dept.description_ne?dept.description_ne:dept.description_en||"")}</p><span class="dept-count">${countVal} ${lang==="ne"?"प्रकाशित सामग्री":"published items"}</span></div></section><section class="wrap" style="padding:32px 0 56px"><div class="dept-list">${list||`<div class="dept-empty"><h3>${lang==="ne"?"यस विभागमा सामग्री तयार हुँदैछ":"No publications in this department yet"}</h3><p>${lang==="ne"?"गृहपृष्ठमा फर्किएर अन्य विभागहरू हेर्नुहोस्।":"Return to the homepage to explore other sections or get in touch."}</p><a class="btn" href="/${lang==="ne"?"?lang=ne":""}">${lang==="ne"?"गृहपृष्ठमा जानुहोस्":"Back to Home"}</a></div>`}</div><style>.dept-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}.dept-page{overflow:hidden;background:#fff;border:1px solid #e5e7eb;border-radius:14px;display:grid;grid-template-columns:116px 1fr;align-items:stretch;transition:transform .18s cubic-bezier(.16,1,.3,1),border-color .18s}.dept-page:hover{transform:translateY(-2px);border-color:#d1d5db}.dept-card-media{height:100%;min-height:104px;padding:7px;overflow:hidden;background:linear-gradient(145deg,#0f172a,#1e3354 70%,#4a3816);border-right:1px solid #e5e7eb;display:flex;align-items:center;justify-content:center}.dept-card-media img{width:100%;height:100%;border-radius:8px;object-fit:cover}.dept-art{width:100%;height:100%;min-height:88px;border-radius:8px;display:grid;place-items:center;background:radial-gradient(circle at 80% 20%,rgba(216,180,106,.28),transparent 55%),linear-gradient(145deg,#182438,#0f172a);color:#f5e4ba;font-family:"Fraunces",Georgia,serif;font-size:26px}.dept-card-copy{padding:12px 14px;display:flex;flex-direction:column;justify-content:center;gap:5px;min-width:0}.dept-card-meta{font-size:11.5px;color:#525d70;font-variant-numeric:tabular-nums}.dept-kicker{display:block;font-size:12px;letter-spacing:.06em;font-weight:600;color:var(--gold);margin-bottom:8px}.dept-card-copy h3{margin:0;font-size:15.5px;line-height:1.3;color:#111827}.dept-card-copy p{margin:0;color:#525d70;font-size:13px;line-height:1.45;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}.dept-card-more{font-size:12.5px;font-weight:600;color:var(--navy)}.dept-count{display:inline-block;margin-top:12px;font-size:13px;color:#525d70;font-variant-numeric:tabular-nums}.dept-empty{grid-column:1/-1;background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:30px 24px;text-align:center}.dept-empty h3{margin:0 0 8px}.dept-empty p{margin:0 0 18px;color:#525d70;font-size:14px}@media(max-width:600px){.dept-list{grid-template-columns:1fr}.dept-page{grid-template-columns:86px 1fr}.dept-card-media{min-height:88px;padding:5px}}</style></section>`;
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
    const assetRes = await env.ASSETS.fetch(req);
    if (assetRes.status === 404 && !u.pathname.split("/").pop()?.includes(".")) {
      const settings = await getSettings(env);
      const lang = u.searchParams.get("lang") === "ne" ? "ne" : "en";
      const title = lang === "ne" ? "पेज भेटिएन (404)" : "Page Not Found (404)";
      const body404 = `<section class="page-hero"><div class="wrap"><h1>404</h1><p>${lang === "ne" ? "माफ गर्नुहोला, तपाईंले खोज्नुभएको पृष्ठ भेटिएन वा प्रकाशित गरिएको छैन।" : "Sorry, the page you requested could not be found or is not published."}</p><p style="margin-top:18px"><a class="btn" href="/${lang === "ne" ? "?lang=ne" : ""}">${lang === "ne" ? "गृहपृष्ठमा फर्कनुहोस्" : "Back to Home"}</a></p></div></section>`;
      return new Response(pageChrome(title, "", body404, settings, lang), {
        status: 404,
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    return assetRes;
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
  const widget = commentsOn ? commentsWidgetHtml(page.slug, lang) : "";
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
    // ZIP page HTML is preserved exactly; do not inject, replace, or remove its header/body until a safe shared-header adapter is tested.
    const contentNotice = '<footer id="granshi-content-note" style="margin:36px auto 0;padding:22px 20px;background:#101b35;color:#d4dbea;font:13px/1.7 system-ui,sans-serif"><div style="max-width:1050px;margin:auto"><p><strong>सामग्रीसम्बन्धी सूचना:</strong> यस पेजमा प्रस्तुत जानकारी सार्वजनिक रूपमा उपलब्ध अनलाइन स्रोत तथा सन्दर्भहरूको अध्ययन र संकलनमा आधारित हुन सक्छ। प्रकाशित सबै कुरा स्वतन्त्र रूपमा शतप्रतिशत प्रमाणित वा त्रुटिरहित छन् भन्ने ग्यारेन्टी छैन। महत्त्वपूर्ण निर्णय गर्नुअघि आधिकारिक तथा विश्वसनीय मूल स्रोतबाट पुष्टि गर्नुहोस्। कुनै सुझाव, सुधार वा त्रुटि भेटिएमा <a href="/legal/contact" style="color:#edbd62">Contact Us</a> मार्फत जानकारी दिनुहोस्।</p><p><strong>Content note:</strong> Information on this page may be compiled from publicly available online sources and references. We cannot guarantee that every statement has been independently verified or is error-free. Please verify important information with authoritative original sources. Suggestions and corrections are welcome via <a href="/legal/contact" style="color:#edbd62">Contact Us</a>.</p></div></footer>';
    if (!html.includes('id="granshi-content-note"')) {
      if (/<\/body>/i.test(html)) html = html.replace(/<\/body>/i, contentNotice + "\n</body>");
      else html += contentNotice;
    }
    return new Response(html, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "public, max-age=30",
      },
    });
  }
  const isLink = String(page.template || "").startsWith("link:");
  if (isLink) {
    const targetUrl = String(page.template).slice(5).trim();
    const safeThumb = page.thumbnail_image
      ? `<div style="margin:0 0 24px;border-radius:14px;overflow:hidden;border:1px solid var(--line)"><img src="${escapeHtml(page.thumbnail_image)}" alt="${escapeHtml(page.thumbnail_alt || title)}" style="width:100%;max-height:380px;object-fit:cover;display:block"></div>`
      : "";
    const launchLabel = lang === "ne" ? "एप / लिंक खोल्नुहोस् ↗" : "Launch App / Open Link ↗";
    const domainLabel = (() => { try { return new URL(targetUrl).hostname; } catch { return targetUrl; } })();
    const body = `<section class="page-hero"><div class="wrap"><span style="display:block;font-size:12px;font-weight:600;letter-spacing:.06em;color:var(--gold);margin-bottom:8px">${lang === "ne" ? "बाह्य एप तथा लिंक" : "App &amp; Curated Link"} · ${escapeHtml(domainLabel)}</span><h1>${escapeHtml(title)}</h1>${desc ? `<p>${escapeHtml(desc)}</p>` : ""}<p style="margin-top:20px"><a class="btn" href="${escapeHtml(targetUrl)}" target="_blank" rel="noopener noreferrer">${launchLabel}</a></p></div></section><article class="wrap">${safeThumb}${page.thumbnail_summary_en || page.thumbnail_summary_ne ? `<p class="blk-p">${escapeHtml(lang === "ne" ? (page.thumbnail_summary_ne || page.thumbnail_summary_en) : (page.thumbnail_summary_en || desc))}</p>` : ""}<p><a class="btn" href="${escapeHtml(targetUrl)}" target="_blank" rel="noopener noreferrer">${launchLabel}</a></p></article>${widget}`;
    return new Response(pageChrome(title, desc, body, settings, lang), {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "public, max-age=60",
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
