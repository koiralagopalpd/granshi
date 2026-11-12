-- Granshi discovery, thumbnail and website-grounded search.
-- Additive migration: existing page content and URLs are preserved.
ALTER TABLE pages ADD COLUMN thumbnail_image TEXT NOT NULL DEFAULT '';
ALTER TABLE pages ADD COLUMN thumbnail_title_en TEXT NOT NULL DEFAULT '';
ALTER TABLE pages ADD COLUMN thumbnail_title_ne TEXT NOT NULL DEFAULT '';
ALTER TABLE pages ADD COLUMN thumbnail_summary_en TEXT NOT NULL DEFAULT '';
ALTER TABLE pages ADD COLUMN thumbnail_summary_ne TEXT NOT NULL DEFAULT '';
ALTER TABLE pages ADD COLUMN thumbnail_alt TEXT NOT NULL DEFAULT '';
ALTER TABLE pages ADD COLUMN thumbnail_focal_x INTEGER NOT NULL DEFAULT 50;
ALTER TABLE pages ADD COLUMN thumbnail_focal_y INTEGER NOT NULL DEFAULT 50;

CREATE TABLE IF NOT EXISTS page_search_index (
  page_slug TEXT PRIMARY KEY,
  title TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  body_text TEXT NOT NULL DEFAULT '',
  department_id INTEGER,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_page_search_department ON page_search_index(department_id);
