-- Persistent diagnosis checkpoint/latest report and admin pending-work tracker.
CREATE TABLE IF NOT EXISTS diagnostics_state (
  id INTEGER PRIMARY KEY CHECK (id=1),
  status TEXT NOT NULL DEFAULT 'idle',
  trigger_type TEXT NOT NULL DEFAULT 'manual',
  run_id TEXT,
  started_at TEXT,
  updated_at TEXT,
  completed_at TEXT,
  current_index INTEGER NOT NULL DEFAULT 0,
  checks_json TEXT NOT NULL DEFAULT '[]',
  latest_report_json TEXT
);

CREATE TABLE IF NOT EXISTS pending_work_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','success')),
  created_at TEXT NOT NULL,
  completed_at TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0
);

INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Draft Email लाई सबै डिभाइसमा उपलब्ध गराउने','pending',datetime('now'),1
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Draft Email लाई सबै डिभाइसमा उपलब्ध गराउने');
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Database तथा R2 Backup / Restore','pending',datetime('now'),2
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Database तथा R2 Backup / Restore');
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Login History र Failed Login Record','pending',datetime('now'),3
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Login History र Failed Login Record');
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Admin Activity Log','pending',datetime('now'),4
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Admin Activity Log');
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Email Delivery / Bounce Status','pending',datetime('now'),5
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Email Delivery / Bounce Status');
