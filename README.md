# Secure Auth Backend — Passport Verification

This small service provides a production-ready endpoint to verify client passports before booking/payment.

Features:
- Multipart upload (passport image) with strict validation
- OCR via Google Cloud Vision (MRZ-aware heuristics)
- Uploads images to Cloudflare R2 (S3-compatible)
- Stores verification records in Supabase
- Rate limiting, helmet hardening and input validation

Quick start:
1. Copy `.env.example` to `.env` and fill in credentials.
2. `npm install`
3. `npm start`

Endpoint:
- POST `/api/bookings/passport/verify` (multipart form, fields: `packageId`, `passportNumber`, `passportCountry`, `passportExpiry`, `travelDate` optionally, file field `passportPhoto`)

Security notes:
- Provide `SUPABASE_SERVICE_ROLE_KEY` to allow server-side inserts.
- Protect the service behind a firewall or API gateway in production.
- Use Google Vision service account for OCR.
