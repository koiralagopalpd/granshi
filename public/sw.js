const CACHE_NAME = "granshi-shell-v2";
const SHELL_ASSETS = [
  "/",
  "/manifest.webmanifest",
  "/admin-manifest.webmanifest",
  "/icon.svg",
  "/pwa-192x192.png",
  "/pwa-512x512.png",
  "/apple-touch-icon.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS).catch(() => {}))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/admin") || url.pathname.startsWith("/_preview/")) {
    return;
  }

  // Static icons & manifest: stale-while-revalidate
  if (/\.(png|jpg|jpeg|webp|svg|ico|webmanifest)$/i.test(url.pathname)) {
    event.respondWith(
      caches.match(req).then((cached) => {
        const net = fetch(req).then((res) => {
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
          }
          return res;
        }).catch(() => cached);
        return cached || net;
      })
    );
    return;
  }

  // HTML navigation: network first with offline cache fallback
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      }).catch(() => caches.match(req).then((c) => c || caches.match("/")))
    );
  }
});

async function checkAdminInboxAndNotify() {
  try {
    const res = await fetch("/api/admin/notifications", { credentials: "include" });
    if (!res.ok) return;
    const data = await res.json();
    const total = Number(data.total_unread || 0);
    if (self.registration && "setAppBadge" in navigator) {
      if (total > 0) navigator.setAppBadge(total).catch(() => {});
      else navigator.clearAppBadge().catch(() => {});
    }
    const items = Array.isArray(data.latest_items) ? data.latest_items : [];
    if (total > 0 && items.length) {
      const top = items[0];
      const tag = "granshi-inbox-" + top.id;
      const existing = await self.registration.getNotifications({ tag });
      if (!existing.length) {
        await self.registration.showNotification(
          total === 1 ? "New message on Granshi" : `${total} unread messages on Granshi`,
          {
            body: `${top.sender || "Visitor"}: ${top.subject || top.preview || "Open Admin Inbox"}`,
            icon: "/pwa-192x192.png",
            badge: "/pwa-192x192.png",
            tag,
            data: { url: "/admin#messages" }
          }
        );
      }
    }
  } catch (_) {}
}

self.addEventListener("periodicsync", (event) => {
  if (event.tag === "granshi-admin-inbox") {
    event.waitUntil(checkAdminInboxAndNotify());
  }
});

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SHOW_ADMIN_NOTIFICATION") {
    const p = event.data.payload || {};
    event.waitUntil(
      self.registration.showNotification(p.title || "New message on Granshi", {
        body: p.body || "Tap to open Granshi Admin Inbox",
        icon: "/pwa-192x192.png",
        badge: "/pwa-192x192.png",
        tag: p.tag || ("granshi-admin-" + Date.now()),
        data: { url: "/admin#messages" }
      })
    );
  }
  if (event.data && event.data.type === "CHECK_ADMIN_INBOX") {
    event.waitUntil(checkAdminInboxAndNotify());
  }
});

self.addEventListener("push", (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch (_) {}
  event.waitUntil(
    self.registration.showNotification(payload.title || "Granshi Admin Alert", {
      body: payload.body || "New incoming message or email.",
      icon: "/pwa-192x192.png",
      badge: "/pwa-192x192.png",
      tag: payload.tag || "granshi-push",
      data: { url: payload.url || "/admin#messages" }
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || "/admin";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const client of list) {
        if (client.url.includes("/admin") && "focus" in client) {
          client.postMessage({ type: "OPEN_INBOX" });
          return client.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow(targetUrl);
    })
  );
});
