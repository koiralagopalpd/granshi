-- Persistent Admin lockout, recovery gate and global session revocation.
ALTER TABLE admins ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN locked_at TEXT;
ALTER TABLE admins ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN recovery_authorized INTEGER NOT NULL DEFAULT 0;
