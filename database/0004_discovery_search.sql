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

-- Replace compatibility placeholder slugs with stable, readable department URLs.
UPDATE departments SET slug='knowledge' WHERE name_en='Knowledge' AND (slug IS NULL OR slug LIKE 'department-%');
UPDATE departments SET slug='learning' WHERE name_en='Learning' AND (slug IS NULL OR slug LIKE 'department-%');
UPDATE departments SET slug='smart-tools' WHERE name_en='Smart Tools' AND (slug IS NULL OR slug LIKE 'department-%');
UPDATE departments SET slug='games' WHERE name_en='Games' AND (slug IS NULL OR slug LIKE 'department-%');
UPDATE departments SET slug='creative-studio' WHERE name_en='Creative Studio' AND (slug IS NULL OR slug LIKE 'department-%');
UPDATE departments SET slug='world' WHERE name_en='World' AND (slug IS NULL OR slug LIKE 'department-%');
UPDATE departments SET slug='community' WHERE name_en='Community' AND (slug IS NULL OR slug LIKE 'department-%');
UPDATE departments SET slug='advanced-services' WHERE name_en='Advanced Services' AND (slug IS NULL OR slug LIKE 'department-%');

-- Seed the search table for pages that were already published before this migration.
INSERT OR REPLACE INTO page_search_index(page_slug,title,description,body_text,department_id,updated_at)
SELECT slug,COALESCE(title_en,'')||' '||COALESCE(title_ne,''),COALESCE(description_en,'')||' '||COALESCE(description_ne,''),content,department_id,updated_at
FROM pages WHERE published=1;
