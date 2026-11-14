-- Persistent per-admin read state for Contact Us messages and inbound mailbox emails.
CREATE TABLE IF NOT EXISTS admin_message_reads (
  admin_email TEXT NOT NULL,
  message_id INTEGER NOT NULL,
  read_at TEXT NOT NULL,
  PRIMARY KEY (admin_email, message_id)
);
CREATE INDEX IF NOT EXISTS idx_admin_message_reads_message
  ON admin_message_reads(message_id);
