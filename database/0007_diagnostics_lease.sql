-- Prevent concurrent Admin and Cron workers from advancing the same scan checkpoint.
ALTER TABLE diagnostics_state ADD COLUMN lease_until TEXT;
