-- Batch package creation: group id + pricing confirmation timestamp.
-- Status values now: Draft (unconfirmed) | Scheduled (confirmed, awaiting
-- activation window) | Active | Inactive.
ALTER TABLE packages
  ADD COLUMN IF NOT EXISTS batch_id uuid,
  ADD COLUMN IF NOT EXISTS pricing_confirmed_at timestamptz;

CREATE INDEX IF NOT EXISTS packages_batch_id_idx ON packages (batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS packages_scheduled_idx ON packages (available_from) WHERE status = 'Scheduled';

-- If packages.status has a CHECK constraint, allow 'Scheduled' too, e.g.:
-- ALTER TABLE packages DROP CONSTRAINT IF EXISTS packages_status_check;
-- ALTER TABLE packages ADD CONSTRAINT packages_status_check
--   CHECK (status IN ('Draft','Scheduled','Active','Inactive'));
