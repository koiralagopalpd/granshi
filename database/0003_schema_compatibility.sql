-- Compatibility tables and indexes for the current CMS.
-- The columns below are already present in the live D1 database. They are
-- included in 0001_initial.sql for fresh installations, so this migration
-- must not ALTER TABLE and duplicate existing columns.
CREATE UNIQUE INDEX IF NOT EXISTS idx_departments_slug ON departments(slug);
CREATE INDEX IF NOT EXISTS idx_pages_department ON pages(department_id, published, sort_order);
CREATE INDEX IF NOT EXISTS idx_categories_department ON categories(department_id, sort_order);
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
