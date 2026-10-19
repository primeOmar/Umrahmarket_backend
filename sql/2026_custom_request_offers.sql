-- Structured offers on custom package requests.
-- An agent can now edit the client's request into a full offer (route, nights,
-- hotels, inclusions, per-passenger prices, optional linked package) and the
-- client can accept or decline it.

ALTER TABLE custom_request_recipients
  ADD COLUMN IF NOT EXISTS offer           jsonb,
  ADD COLUMN IF NOT EXISTS client_decision text CHECK (client_decision IN ('accepted', 'declined')),
  ADD COLUMN IF NOT EXISTS decided_at      timestamptz;

ALTER TABLE custom_package_requests
  DROP CONSTRAINT IF EXISTS custom_package_requests_status_check;
ALTER TABLE custom_package_requests
  ADD CONSTRAINT custom_package_requests_status_check CHECK (status IN ('open', 'closed', 'accepted'));
