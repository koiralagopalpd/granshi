-- Add idempotent inbound email storage.
-- reply_text and replied_at are part of the baseline schema; live D1 already has them.

CREATE TABLE IF NOT EXISTS inbound_email_events (
  id TEXT PRIMARY KEY,
  resend_email_id TEXT NOT NULL UNIQUE,
  message_id INTEGER,
  sender TEXT NOT NULL,
  recipients TEXT NOT NULL DEFAULT '[]',
  subject TEXT,
  body_text TEXT,
  body_html TEXT,
  headers_json TEXT,
  attachments_json TEXT NOT NULL DEFAULT '[]',
  received_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_inbound_email_events_message
  ON inbound_email_events(message_id);
CREATE INDEX IF NOT EXISTS idx_inbound_email_events_received
  ON inbound_email_events(received_at);
