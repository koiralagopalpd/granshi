-- Granshi CMS v3 — full schema (free tier + marketplace-ready)

CREATE TABLE IF NOT EXISTS admins (
  email TEXT PRIMARY KEY,
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pages (
  slug TEXT PRIMARY KEY,
  title_en TEXT NOT NULL,
  title_ne TEXT,
  description_en TEXT,
  description_ne TEXT,
  content TEXT NOT NULL DEFAULT '[]',
  template TEXT NOT NULL DEFAULT 'default',
  published INTEGER NOT NULL DEFAULT 0,
  sort_order INTEGER NOT NULL DEFAULT 0,
  department_id INTEGER,
  category_id INTEGER,
  is_popular INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS departments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name_en TEXT NOT NULL,
  name_ne TEXT,
  description_en TEXT,
  description_ne TEXT,
  url TEXT NOT NULL DEFAULT '#',
  icon TEXT DEFAULT '✦',
  email TEXT DEFAULT '',
  image TEXT DEFAULT '',
  visible INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  slug TEXT
);

CREATE TABLE IF NOT EXISTS menus (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label_en TEXT NOT NULL,
  label_ne TEXT,
  url TEXT NOT NULL,
  parent_id INTEGER DEFAULT NULL,
  visible INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS media (
  key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  content_type TEXT,
  size INTEGER,
  created_at TEXT NOT NULL,
  department_id INTEGER,
  page_slug TEXT
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  department_id INTEGER,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  subject TEXT,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  created_at TEXT NOT NULL,
  reply_text TEXT,
  replied_at TEXT
);

-- Marketplace-ready (empty until you enable)
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name_en TEXT NOT NULL,
  name_ne TEXT,
  slug TEXT UNIQUE NOT NULL,
  description_en TEXT,
  description_ne TEXT,
  image TEXT DEFAULT '',
  parent_id INTEGER DEFAULT NULL,
  visible INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  department_id INTEGER
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name_en TEXT NOT NULL,
  name_ne TEXT,
  slug TEXT UNIQUE NOT NULL,
  description_en TEXT,
  description_ne TEXT,
  price REAL NOT NULL DEFAULT 0,
  compare_price REAL,
  currency TEXT NOT NULL DEFAULT 'NPR',
  image TEXT DEFAULT '',
  images TEXT DEFAULT '[]',
  category_id INTEGER,
  stock INTEGER DEFAULT 0,
  sku TEXT,
  status TEXT NOT NULL DEFAULT 'draft',
  featured INTEGER NOT NULL DEFAULT 0,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT UNIQUE NOT NULL,
  customer_name TEXT NOT NULL,
  customer_email TEXT NOT NULL,
  customer_phone TEXT,
  shipping_address TEXT,
  items TEXT NOT NULL DEFAULT '[]',
  subtotal REAL NOT NULL DEFAULT 0,
  total REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'NPR',
  status TEXT NOT NULL DEFAULT 'pending',
  notes TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status);
CREATE INDEX IF NOT EXISTS idx_pages_published ON pages(published);
CREATE INDEX IF NOT EXISTS idx_products_status ON products(status);
CREATE INDEX IF NOT EXISTS idx_products_slug ON products(slug);
CREATE INDEX IF NOT EXISTS idx_categories_slug ON categories(slug);

-- Defaults
INSERT OR IGNORE INTO settings(key, value) VALUES
  ('brand_name', 'Granshi — My Digital World'),
  ('tagline', 'One World. Endless Possibilities.'),
  ('hero_title_en', 'Explore Your Digital World.'),
  ('hero_title_ne', 'आफ्नो डिजिटल संसार अन्वेषण गर्नुहोस्।'),
  ('hero_desc_en', 'Knowledge, learning, creativity and technology — connected in one place. Welcome to Granshi.'),
  ('hero_desc_ne', 'ज्ञान, सिकाइ, सिर्जनशीलता र प्रविधि — सबै एउटै ठाउँमा। Granshi मा स्वागत छ।'),
  ('hero_image', '/assets-brand.png'),
  ('contact_email', 'hello@gopalkoirala.com.np'),
  ('language_default', 'en'),
  ('footer_text', '© Granshi — My Digital World. One World. Endless Possibilities.'),
  ('primary_color', '#101a2c'),
  ('accent_color', '#e5c77e'),
  ('marketplace_enabled', '0'),
  ('currency', 'NPR');

INSERT OR IGNORE INTO departments(name_en, name_ne, description_en, description_ne, url, icon, email, visible, sort_order) VALUES
  ('Knowledge', 'ज्ञान', 'Discover facts, science, history and useful information.', 'तथ्य, विज्ञान, इतिहास र उपयोगी जानकारी।', '#', '✦', '', 1, 1),
  ('Learning', 'सिकाइ', 'Languages, skills, lessons and tutorials.', 'भाषा, सीप, पाठ र ट्युटोरियल।', '#', '◎', '', 1, 2),
  ('Smart Tools', 'स्मार्ट टुल्स', 'Useful digital tools and productivity helpers.', 'उपयोगी डिजिटल टुल्स र काम सजिलो बनाउने साधन।', '#', '⌘', '', 1, 3),
  ('Games', 'खेल', 'Games and interactive experiences.', 'खेल तथा अन्तरक्रियात्मक अनुभव।', '#', '♟', '', 1, 4),
  ('Creative Studio', 'क्रिएटिभ स्टुडियो', 'Photography, video, design and creative work.', 'फोटोग्राफी, भिडियो, डिजाइन र सिर्जनात्मक काम।', '#', '✧', '', 1, 5),
  ('World', 'विश्व', 'Countries, cultures, places and stories.', 'देश, संस्कृति, स्थान र कथाहरू।', '#', '◎', '', 1, 6),
  ('Community', 'समुदाय', 'Connect and share ideas.', 'जोडिनुहोस् र विचार साझा गर्नुहोस्।', '#', '♧', '', 1, 7),
  ('Advanced Services', 'विशेष सेवाहरू', 'Future digital services and projects.', 'भविष्यका डिजिटल सेवा र परियोजनाहरू।', '#', '◇', '', 1, 8);

INSERT OR IGNORE INTO menus(label_en, label_ne, url, visible, sort_order) VALUES
  ('Home', 'गृहपृष्ठ', '/', 1, 1),
  ('Explore', 'अन्वेषण', '#departments', 1, 2),
  ('About', 'हाम्रोबारे', '#about', 1, 3),
  ('Contact', 'सम्पर्क', '#contact', 1, 4);
