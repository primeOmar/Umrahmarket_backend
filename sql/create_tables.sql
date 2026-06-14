-- SQL migration for passport verifications (Postgres / Supabase)

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

create index if not exists idx_passport_verifications_user on passport_verifications(user_id);
create index if not exists idx_passport_verifications_package on passport_verifications(package_id);
