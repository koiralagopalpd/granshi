-- GRANSHI CMS UPGRADE
-- Safe additive migration
-- Existing data and Marketplace categories are preserved.

-- 1. Add Department and ZIP support to Pages

ALTER TABLE pages ADD COLUMN department_id INTEGER;
ALTER TABLE pages ADD COLUMN category_id INTEGER;
ALTER TABLE pages ADD COLUMN page_type TEXT NOT NULL DEFAULT 'blocks';
ALTER TABLE pages ADD COLUMN zip_key TEXT;
ALTER TABLE pages ADD COLUMN zip_entry TEXT DEFAULT 'index.html';
ALTER TABLE pages ADD COLUMN version_number INTEGER NOT NULL DEFAULT 1;


-- 2. Separate Department Categories
-- Do NOT modify Marketplace categories table.

CREATE TABLE IF NOT EXISTS department_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    department_id INTEGER NOT NULL,
    name_en TEXT NOT NULL,
    name_ne TEXT,
    slug TEXT NOT NULL,
    description_en TEXT,
    description_ne TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    published INTEGER NOT NULL DEFAULT 1,
    created_at TEXT,
    updated_at TEXT,
    UNIQUE(department_id, slug)
);


-- 3. ZIP Page Version History

CREATE TABLE IF NOT EXISTS page_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_slug TEXT NOT NULL,
    version_number INTEGER NOT NULL,
    zip_key TEXT NOT NULL,
    entry_file TEXT NOT NULL DEFAULT 'index.html',
    title_en TEXT,
    title_ne TEXT,
    description_en TEXT,
    description_ne TEXT,
    department_id INTEGER,
    category_id INTEGER,
    published INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    created_by TEXT,
    UNIQUE(page_slug, version_number)
);


-- 4. Message Reply History

CREATE TABLE IF NOT EXISTS message_replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    sender TEXT NOT NULL DEFAULT 'admin',
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    email_sent INTEGER NOT NULL DEFAULT 0
);


-- 5. Message Attachments

CREATE TABLE IF NOT EXISTS message_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    reply_id INTEGER,
    file_key TEXT NOT NULL,
    file_name TEXT NOT NULL,
    content_type TEXT,
    file_size INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);


-- 6. Media Usage References

CREATE TABLE IF NOT EXISTS media_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    media_key TEXT NOT NULL,
    page_slug TEXT,
    department_id INTEGER,
    created_at TEXT NOT NULL
);


-- 7. ZIP Page Assets

CREATE TABLE IF NOT EXISTS page_zip_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_slug TEXT NOT NULL,
    version_number INTEGER NOT NULL,
    asset_path TEXT NOT NULL,
    r2_key TEXT NOT NULL,
    content_type TEXT,
    file_size INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(page_slug, version_number, asset_path)
);


-- 8. Indexes

CREATE INDEX IF NOT EXISTS idx_pages_department
ON pages(department_id);

CREATE INDEX IF NOT EXISTS idx_pages_category
ON pages(category_id);

CREATE INDEX IF NOT EXISTS idx_department_categories_department
ON department_categories(department_id);

CREATE INDEX IF NOT EXISTS idx_page_versions_slug
ON page_versions(page_slug, version_number);

CREATE INDEX IF NOT EXISTS idx_message_replies_message
ON message_replies(message_id);

CREATE INDEX IF NOT EXISTS idx_message_attachments_message
ON message_attachments(message_id);

CREATE INDEX IF NOT EXISTS idx_media_usage_key
ON media_usage(media_key);

CREATE INDEX IF NOT EXISTS idx_page_zip_assets_page
ON page_zip_assets(page_slug, version_number);
