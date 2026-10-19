-- Custom package requests: a client describes a trip that no listed package
-- covers; it fans out to selected (or all) approved agents' dashboards.
-- Agents never receive the client's name/phone/email — only the request
-- details and an opaque reference code.

CREATE TABLE IF NOT EXISTS custom_package_requests (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id   uuid NOT NULL,
  audience    text NOT NULL CHECK (audience IN ('all', 'selected')),
  details     jsonb NOT NULL DEFAULT '{}'::jsonb,
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS custom_requests_client_idx ON custom_package_requests (client_id, created_at DESC);

CREATE TABLE IF NOT EXISTS custom_request_recipients (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id    uuid NOT NULL REFERENCES custom_package_requests(id) ON DELETE CASCADE,
  agent_id      uuid NOT NULL,
  status        text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'viewed', 'responded', 'declined')),
  message       text,
  price         numeric,
  package_id    uuid,
  viewed_at     timestamptz,
  responded_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (request_id, agent_id)
);
CREATE INDEX IF NOT EXISTS custom_recipients_agent_idx ON custom_request_recipients (agent_id, status, created_at DESC);

-- Accessed only through the backend (service role).
ALTER TABLE custom_package_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_request_recipients ENABLE ROW LEVEL SECURITY;
