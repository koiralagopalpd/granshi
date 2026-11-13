# GRANSHI CMS v3 — Full Free-Tier Power

**Cloudflare Workers + D1 + R2**  
Domain target: `gopalkoirala.com.np`  
Brand: Granshi — Our Digital World

Completely free-tier friendly. No paid services required (optional Resend for real email).

---

## What’s included

### Public site
- Bilingual homepage (EN / नेपाली)
- Dynamic menus, hero, colors, footer from Settings
- Department cards + search
- Contact form with department selector
- Published CMS pages at `/slug`
- Product pages ready (`/product-slug`) when marketplace is on

### Admin panel (full control)
- **Drag & drop page builder** (SortableJS)
  - Blocks: Heading, Paragraph, Image, Button, Quote, Hero, Columns, Cards, Video, Spacer, Divider, Custom HTML
  - Reorder by dragging
- Departments (with per-department email)
- Messages inbox
- Menus
- Media library (R2, 25 MB/file)
- **Marketplace ready**
  - Products (price, stock, images, status)
  - Categories
  - Orders list (for future checkout)
- Site settings (colors, texts, marketplace toggle)
- Single-admin security (PBKDF2 + signed cookie)

---

## Deploy (free)

```bash
npm install
npx wrangler login

# 1. Create D1
npx wrangler d1 create granshi-db
# → put database_id into wrangler.toml

# 2. Migrate
npx wrangler d1 migrations apply granshi-db --remote

# 3. R2 bucket
npx wrangler r2 bucket create granshi-media

# 4. Secrets
npx wrangler secret put SESSION_SECRET
npx wrangler secret put SETUP_TOKEN
# optional email:
# npx wrangler secret put RESEND_API_KEY

# 5. Deploy
npx wrangler deploy
```

Connect domain in Cloudflare Dashboard → Workers → granshi → Domains.

First visit: `https://yoursite.com/admin`  
Create admin with SETUP_TOKEN.

---

## How to use the page builder

1. Admin → **Pages (Builder)** → New page  
2. Fill title + slug  
3. Click blocks on the right (Heading, Cards, Hero…)  
4. **Drag ⠿ handle** to reorder  
5. Check **Published** → Save  
6. Open `https://yoursite.com/your-slug`

---

## Marketplace (future-ready)

1. Admin → **Categories** → add categories  
2. Admin → **Products** → add products, set status = Published  
3. Admin → **Settings** → enable **Marketplace enabled**  
4. Products appear on homepage and at `/product-slug`

Checkout / payment is not built yet (you can add eSewa / Khalti / Stripe later). Schema and admin UI are ready.

---

## Resend inbound email and attachments

After deploying the worker, configure a Resend webhook:
- Endpoint: `https://gopalkoirala.com.np/api/webhooks/resend`
- Event: `email.received`
- Save the webhook signing secret as the Cloudflare Worker secret `RESEND_WEBHOOK_SECRET`.
- Keep the existing `RESEND_API_KEY` as a Worker secret. Never put either secret in this repository.
- Apply the new D1 migration: `npx wrangler d1 migrations apply granshi-db --remote`.

The endpoint verifies Svix signatures and timestamp freshness, fetches the full received message from Resend, stores the message in the Admin Inbox, and copies received attachments into the configured R2 bucket. Repeated webhook deliveries are deduplicated by Resend email ID. Test with a real message after deploying; repository checks cannot verify Cloudflare secrets, Resend webhook delivery, DNS routing, or live R2/D1 permissions.

Admin replies use the configured Resend sender and set `info@gopalkoirala.com.np` as Reply-To. Uploaded files are attached to the outgoing email as base64 content. Image attachments are converted/compressed without cropping while preserving aspect ratio; the 100 KB target is best-effort, not guaranteed for every image.

## Department email

- Edit department → set **Contact email**  
- Visitor chooses department on contact form  
- Message always saved in **Messages**  
- If `RESEND_API_KEY` is set → email is also sent to that department (or global contact email)

---

## Free-tier limits (Cloudflare)

| Resource | Free allowance (approx.) |
|----------|--------------------------|
| Workers requests | 100,000 / day |
| D1 reads | 5 million / day |
| D1 writes | 100,000 / day |
| R2 storage | 10 GB |
| R2 Class A ops | 1 million / month |

Enough for a growing personal / brand site.

---

## Security

- One admin only  
- PBKDF2 180k iterations  
- HttpOnly + Secure session cookie  
- Never commit secrets  

---

## Not included (by design / free constraint)

- Visual WYSIWYG like WordPress Gutenberg (this is structured blocks + drag reorder)
- Multi-admin roles  
- Built-in payment gateway  
- Cloudflare Turnstile (you can add later for spam)  
- Image auto-resize (use external or Cloudflare Images later)

This is a complete, deployable foundation you control 100% from the admin panel, with marketplace structure already in place for the next stage.
