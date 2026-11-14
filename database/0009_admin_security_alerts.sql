-- Audit every failed Admin login without storing credentials or session tokens.
CREATE TABLE IF NOT EXISTS admin_security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  attempt_count INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  email_alert_status TEXT NOT NULL DEFAULT 'not_due' CHECK(email_alert_status IN ('not_due','sent','failed')),
  email_alert_error TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_security_events_created ON admin_security_events(created_at DESC);

-- Tasks requiring the site owner's action after code review.
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Resend API Key लाई Cloudflare Worker Secret मा RESEND_API_KEY नामले राख्ने','pending',datetime('now'),20
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Resend API Key लाई Cloudflare Worker Secret मा RESEND_API_KEY नामले राख्ने');
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Resend मा gopalkoirala.com.np domain verify गरी info@gopalkoirala.com.np sender प्रमाणित गर्ने','pending',datetime('now'),21
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Resend मा gopalkoirala.com.np domain verify गरी info@gopalkoirala.com.np sender प्रमाणित गर्ने');
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Admin Security Migration 0008 र 0009 उत्पादन D1 मा लागू गर्ने','pending',datetime('now'),22
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Admin Security Migration 0008 र 0009 उत्पादन D1 मा लागू गर्ने');
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'PR #4 परीक्षण सफल भएपछि main मा Merge गर्ने र Worker Deploy गर्ने','pending',datetime('now'),23
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='PR #4 परीक्षण सफल भएपछि main मा Merge गर्ने र Worker Deploy गर्ने');
INSERT INTO pending_work_items(title,status,created_at,sort_order)
SELECT 'Admin Login Security Alert को वास्तविक Email Delivery परीक्षण गर्ने','pending',datetime('now'),24
WHERE NOT EXISTS (SELECT 1 FROM pending_work_items WHERE title='Admin Login Security Alert को वास्तविक Email Delivery परीक्षण गर्ने');
