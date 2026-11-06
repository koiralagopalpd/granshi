Granshi CMS v3 D1 migrations

Apply:
  npx wrangler d1 migrations apply granshi-db --remote

Local test:
  npx wrangler d1 migrations apply granshi-db --local

Includes: pages, departments, menus, media, messages,
and marketplace-ready tables (categories, products, orders).
