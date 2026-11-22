-- Cross-device synced email drafts for Admin composer.
CREATE TABLE IF NOT EXISTS email_drafts (
  id TEXT PRIMARY KEY,
  recipient TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_drafts_updated ON email_drafts(updated_at DESC);
