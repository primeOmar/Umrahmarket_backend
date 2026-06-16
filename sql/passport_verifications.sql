-- =====================================================================
-- Passport verification — schema migration (Postgres / Supabase)
-- Idempotent: safe to re-run. Extends the original passport_verifications
-- table created in create_tables.sql with OCR / MRZ fields, retry tracking,
-- a per (user, package) uniqueness constraint, RLS, and an updated_at trigger.
-- =====================================================================

-- Base table (kept for fresh databases; no-op if it already exists)
create table if not exists passport_verifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  package_id uuid not null,
  booking_id uuid,
  passport_number text not null,
  passport_country text not null,
  passport_expiry date not null,
  travel_date date,
  passport_image_url text not null,
  verified boolean not null default false,
  verification_status text not null default 'pending',
  created_at timestamptz not null default now(),
  verified_at timestamptz
);

-- ── New columns (OCR/MRZ extraction, identity, audit) ────────────────
alter table passport_verifications add column if not exists surname           text;
alter table passport_verifications add column if not exists given_names       text;
alter table passport_verifications add column if not exists full_name         text;
alter table passport_verifications add column if not exists date_of_birth     date;
alter table passport_verifications add column if not exists sex               text;
alter table passport_verifications add column if not exists nationality       text;          -- ISO-3166 alpha-3 from MRZ
alter table passport_verifications add column if not exists image_key         text;          -- private R2 object key
alter table passport_verifications add column if not exists mrz_raw           text;          -- raw machine-readable zone (audit only)
alter table passport_verifications add column if not exists ocr_confidence    numeric(5,2);  -- 0..100
alter table passport_verifications add column if not exists match_score       numeric(5,2);  -- 0..100 (input vs OCR)
alter table passport_verifications add column if not exists match_details     jsonb;         -- per-field comparison
alter table passport_verifications add column if not exists attempts          integer not null default 0;
alter table passport_verifications add column if not exists last_attempt_at   timestamptz;
alter table passport_verifications add column if not exists reviewed_by       uuid;          -- admin/agent who manually cleared
alter table passport_verifications add column if not exists review_note       text;
alter table passport_verifications add column if not exists updated_at        timestamptz not null default now();

-- ── Status domain ────────────────────────────────────────────────────
--   pending          : row created, not yet decided
--   verified         : OCR confirmed the typed details (auto)
--   manual_review    : retries exhausted — needs human verification
--   rejected         : passport invalid (expiry rule failed) or denied by admin
--   expired_passport : passport expires < 6 months from travel date
do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'passport_verifications_status_chk'
  ) then
    alter table passport_verifications
      add constraint passport_verifications_status_chk
      check (verification_status in
        ('pending','verified','manual_review','rejected','expired_passport'));
  end if;
end$$;

-- ── One active verification per (user, package) — enables upsert ─────
create unique index if not exists uq_passport_verifications_user_package
  on passport_verifications(user_id, package_id);

create index if not exists idx_passport_verifications_user    on passport_verifications(user_id);
create index if not exists idx_passport_verifications_package on passport_verifications(package_id);
create index if not exists idx_passport_verifications_status  on passport_verifications(verification_status);

-- ── updated_at trigger ───────────────────────────────────────────────
create or replace function set_passport_verifications_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists trg_passport_verifications_updated_at on passport_verifications;
create trigger trg_passport_verifications_updated_at
  before update on passport_verifications
  for each row execute function set_passport_verifications_updated_at();

-- ── Row Level Security ───────────────────────────────────────────────
-- The backend writes exclusively via the service-role key (bypasses RLS).
-- Clients only ever read their own row. No client INSERT/UPDATE policy is
-- defined on purpose — all writes must go through the verified backend flow.
alter table passport_verifications enable row level security;

drop policy if exists "passport_select_own" on passport_verifications;
create policy "passport_select_own"
  on passport_verifications
  for select
  using (auth.uid() = user_id);

-- Foreign keys (added only if the referenced tables exist; ignore failures)
do $$
begin
  if exists (select 1 from information_schema.tables where table_name = 'packages') then
    begin
      alter table passport_verifications
        add constraint fk_passport_package
        foreign key (package_id) references packages(id) on delete cascade;
    exception when duplicate_object then null; when others then null;
    end;
  end if;
end$$;
