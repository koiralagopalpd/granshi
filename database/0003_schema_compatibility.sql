-- Bring the original starter schema in line with the columns used by the CMS Worker.
-- All changes are additive; existing rows and data are retained.

ALTER TABLE departments ADD COLUMN slug TEXT;
UPDATE departments SET slug = 'department-' || id WHERE slug IS NULL OR slug = '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_departments_slug ON departments(slug);

ALTER TABLE pages ADD COLUMN department_id INTEGER;
ALTER TABLE pages ADD COLUMN category_id INTEGER;
ALTER TABLE pages ADD COLUMN is_popular INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_pages_department ON pages(department_id, published, sort_order);

ALTER TABLE categories ADD COLUMN department_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_categories_department ON categories(department_id, sort_order);

ALTER TABLE media ADD COLUMN department_id INTEGER;
ALTER TABLE media ADD COLUMN page_slug TEXT;
CREATE INDEX IF NOT EXISTS idx_media_department ON media(department_id, created_at);
CREATE INDEX IF NOT EXISTS idx_media_page ON media(page_slug, created_at);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page_slug TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comments_page_status ON comments(page_slug, status, created_at);
