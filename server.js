import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import express from "express";
import worker from "./src/worker.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

const LOCAL_DIR = path.join(__dirname, ".local");
const DB_PATH = path.join(LOCAL_DIR, "granshi.sqlite");
const MEDIA_DIR = path.join(LOCAL_DIR, "media");
const MEDIA_INDEX_PATH = path.join(LOCAL_DIR, "media-index.json");
const SECRET_PATH = path.join(LOCAL_DIR, "session-secret.txt");
const PUBLIC_DIR = path.join(__dirname, "public");
const MIGRATIONS_DIR = path.join(__dirname, "database");

fs.mkdirSync(MEDIA_DIR, { recursive: true });

function loadOrCreateSessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  try {
    if (fs.existsSync(SECRET_PATH)) {
      const existing = fs.readFileSync(SECRET_PATH, "utf8").trim();
      if (existing) return existing;
    }
  } catch {}
  const generated = crypto.randomBytes(32).toString("hex");
  try {
    fs.writeFileSync(SECRET_PATH, generated, "utf8");
  } catch {}
  return generated;
}

function initDatabase() {
  const sqlite = new DatabaseSync(DB_PATH);
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS _migrations (
      name TEXT PRIMARY KEY,
      applied_at TEXT NOT NULL
    );
  `);

  const appliedStmt = sqlite.prepare("SELECT name FROM _migrations");
  const applied = new Set(appliedStmt.all().map((row) => row.name));

  const migrationFiles = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((file) => file.endsWith(".sql"))
    .sort();

  const insertMigration = sqlite.prepare(
    "INSERT INTO _migrations(name, applied_at) VALUES(?, ?)"
  );

  for (const file of migrationFiles) {
    if (applied.has(file)) continue;
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), "utf8").trim();
    if (sql) {
      sqlite.exec(sql);
    }
    insertMigration.run(file, new Date().toISOString());
  }

  return sqlite;
}

function createD1Adapter(sqlite) {
  const normalizeArg = (value) => {
    if (value === undefined) return null;
    if (typeof value === "boolean") return value ? 1 : 0;
    return value;
  };

  function wrapStatement(sql, boundArgs = []) {
    return {
      bind(...args) {
        return wrapStatement(sql, args.map(normalizeArg));
      },
      async first(columnName) {
        const stmt = sqlite.prepare(sql);
        const row = stmt.get(...boundArgs);
        if (row === undefined) return null;
        if (columnName !== undefined) return row[columnName] ?? null;
        return row;
      },
      async all() {
        const stmt = sqlite.prepare(sql);
        const results = stmt.all(...boundArgs);
        return { results, success: true, meta: {} };
      },
      async run() {
        const stmt = sqlite.prepare(sql);
        const info = stmt.run(...boundArgs);
        return {
          success: true,
          meta: {
            changes: Number(info.changes ?? 0),
            last_row_id: Number(info.lastInsertRowid ?? 0),
          },
        };
      },
    };
  }

  return {
    prepare(sql) {
      return wrapStatement(sql);
    },
    async exec(sql) {
      sqlite.exec(sql);
      return { count: 1, duration: 0 };
    },
  };
}

function createR2Adapter() {
  let index = {};
  try {
    if (fs.existsSync(MEDIA_INDEX_PATH)) {
      index = JSON.parse(fs.readFileSync(MEDIA_INDEX_PATH, "utf8")) || {};
    }
  } catch {
    index = {};
  }

  function saveIndex() {
    fs.writeFileSync(MEDIA_INDEX_PATH, JSON.stringify(index, null, 2), "utf8");
  }

  function filePathForKey(key) {
    const hash = crypto.createHash("sha256").update(key).digest("hex");
    return path.join(MEDIA_DIR, hash);
  }

  async function toBuffer(value) {
    if (Buffer.isBuffer(value)) return value;
    if (typeof value === "string") return Buffer.from(value, "utf8");
    if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
    if (ArrayBuffer.isView(value)) {
      return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    if (value && typeof value.getReader === "function") {
      const reader = value.getReader();
      const chunks = [];
      while (true) {
        const { done, value: chunk } = await reader.read();
        if (done) break;
        chunks.push(Buffer.from(chunk));
      }
      return Buffer.concat(chunks);
    }
    return Buffer.from(String(value ?? ""), "utf8");
  }

  return {
    async get(key) {
      const meta = index[key];
      if (!meta) return null;
      const diskPath = filePathForKey(key);
      if (!fs.existsSync(diskPath)) return null;
      const buf = fs.readFileSync(diskPath);
      return {
        key,
        size: buf.byteLength,
        httpEtag: meta.etag,
        httpMetadata: { contentType: meta.contentType },
        writeHttpMetadata(headers) {
          if (meta.contentType) {
            headers.set("content-type", meta.contentType);
          }
        },
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(buf));
            controller.close();
          },
        }),
        async arrayBuffer() {
          return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
        },
        async text() {
          return buf.toString("utf8");
        },
      };
    },
    async put(key, value, options = {}) {
      const buf = await toBuffer(value);
      const etag = `"${crypto.createHash("md5").update(buf).digest("hex")}"`;
      const contentType =
        options?.httpMetadata?.contentType || "application/octet-stream";
      fs.writeFileSync(filePathForKey(key), buf);
      index[key] = {
        size: buf.byteLength,
        etag,
        contentType,
        uploaded: new Date().toISOString(),
      };
      saveIndex();
      return { key, size: buf.byteLength, httpEtag: etag };
    },
    async delete(key) {
      const diskPath = filePathForKey(key);
      if (fs.existsSync(diskPath)) fs.unlinkSync(diskPath);
      delete index[key];
      saveIndex();
    },
    async list(options = {}) {
      const prefix = String(options.prefix || "");
      const limit = Math.max(1, Math.min(1000, Number(options.limit || 1000)));
      const cursor = options.cursor ? Number(options.cursor) : 0;
      const keys = Object.keys(index)
        .filter((k) => !prefix || k.startsWith(prefix))
        .sort();
      const slice = keys.slice(cursor, cursor + limit);
      const nextCursor = cursor + slice.length;
      const truncated = nextCursor < keys.length;
      return {
        objects: slice.map((key) => ({
          key,
          size: index[key].size,
          httpEtag: index[key].etag,
          httpMetadata: { contentType: index[key].contentType },
        })),
        truncated,
        cursor: truncated ? String(nextCursor) : undefined,
      };
    },
  };
}

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".pdf": "application/pdf",
};

function createAssetsAdapter() {
  return {
    async fetch(webReq) {
      const url = new URL(webReq.url);
      let reqPath = decodeURIComponent(url.pathname || "/");
      if (reqPath === "/" || reqPath === "") {
        reqPath = "/index.html";
      } else if (reqPath === "/admin" || reqPath === "/admin/") {
        reqPath = "/admin/index.html";
      }

      const resolvedBase = path.resolve(PUBLIC_DIR);
      let target = path.resolve(PUBLIC_DIR, "." + reqPath);
      if (!target.startsWith(resolvedBase)) {
        return new Response("Forbidden", { status: 403 });
      }

      if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
        target = path.join(target, "index.html");
      }

      if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
        return new Response("Not found", { status: 404 });
      }

      const ext = path.extname(target).toLowerCase();
      const contentType = MIME_TYPES[ext] || "application/octet-stream";
      const data = fs.readFileSync(target);
      return new Response(data, {
        status: 200,
        headers: { "content-type": contentType },
      });
    },
  };
}

const sqliteDb = initDatabase();
const env = {
  DB: createD1Adapter(sqliteDb),
  MEDIA: createR2Adapter(),
  ASSETS: createAssetsAdapter(),
  ENVIRONMENT: process.env.ENVIRONMENT || "production",
  SESSION_SECRET: loadOrCreateSessionSecret(),
  SETUP_TOKEN: process.env.SETUP_TOKEN || "granshi-setup-token",
  RESEND_API_KEY: process.env.RESEND_API_KEY || "",
  RESEND_WEBHOOK_SECRET: process.env.RESEND_WEBHOOK_SECRET || "",
};

const app = express();
app.disable("x-powered-by");
app.use(express.raw({ type: "*/*", limit: "30mb" }));

app.all(/.*/, async (req, res) => {
  try {
    const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "http")
      .split(",")[0]
      .trim();
    const host = req.headers.host || `localhost:${PORT}`;
    const fullUrl = `${proto}://${host}${req.originalUrl}`;

    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined) continue;
      if (Array.isArray(v)) {
        for (const item of v) headers.append(k, item);
      } else {
        headers.set(k, String(v));
      }
    }

    const hasBody =
      req.method !== "GET" &&
      req.method !== "HEAD" &&
      Buffer.isBuffer(req.body) &&
      req.body.length > 0;

    const webReq = new Request(fullUrl, {
      method: req.method,
      headers,
      body: hasBody ? req.body : undefined,
    });

    const webRes = await worker.fetch(webReq, env);

    res.status(webRes.status);

    const setCookies =
      typeof webRes.headers.getSetCookie === "function"
        ? webRes.headers.getSetCookie()
        : [];

    webRes.headers.forEach((value, key) => {
      if (key.toLowerCase() === "set-cookie") return;
      res.setHeader(key, value);
    });

    if (setCookies.length > 0) {
      const normalizedCookies =
        proto === "https"
          ? setCookies
          : setCookies.map((c) => c.replace(/;\s*Secure/gi, ""));
      res.setHeader("set-cookie", normalizedCookies);
    }

    const arrayBuf = await webRes.arrayBuffer();
    res.send(Buffer.from(arrayBuf));
  } catch (err) {
    console.error("Worker adapter error:", err);
    res.status(500).json({ error: "Server error", detail: String(err) });
  }
});

app.listen(PORT, HOST, () => {
  console.log(`Granshi CMS listening on http://${HOST}:${PORT}`);
});
