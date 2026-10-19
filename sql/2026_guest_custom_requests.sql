-- Guest (unauthenticated) custom package requests: a visitor can ask for a
-- customized package without creating an account, as long as they verify a
-- WhatsApp number (Twilio Verify OTP) and provide an email. Replies from
-- agents are pushed out to them via WhatsApp + email since they have no
-- dashboard to check.

ALTER TABLE custom_package_requests
  ALTER COLUMN client_id DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS guest_whatsapp text,
  ADD COLUMN IF NOT EXISTS guest_email text,
  ADD COLUMN IF NOT EXISTS guest_verified_at timestamptz;

-- Either an authenticated client or a verified guest must own the request.
ALTER TABLE custom_package_requests
  DROP CONSTRAINT IF EXISTS custom_requests_owner_check;
ALTER TABLE custom_package_requests
  ADD CONSTRAINT custom_requests_owner_check CHECK (
    client_id IS NOT NULL
    OR (guest_whatsapp IS NOT NULL AND guest_email IS NOT NULL AND guest_verified_at IS NOT NULL)
  );

CREATE INDEX IF NOT EXISTS custom_requests_guest_idx ON custom_package_requests (guest_whatsapp, created_at DESC);

-- Lightweight throttle log for guest OTP sends (independent of whatever
-- retry/cooldown Twilio Verify itself enforces) — caps abuse per number
-- and per IP without needing a Redis dependency.
CREATE TABLE IF NOT EXISTS guest_otp_throttle (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  phone       text NOT NULL,
  ip          text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS guest_otp_throttle_phone_idx ON guest_otp_throttle (phone, created_at DESC);
CREATE INDEX IF NOT EXISTS guest_otp_throttle_ip_idx ON guest_otp_throttle (ip, created_at DESC);

ALTER TABLE guest_otp_throttle ENABLE ROW LEVEL SECURITY; -- service role only
