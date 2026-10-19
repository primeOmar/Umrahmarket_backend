-- WhatsApp messaging: logs, broadcasts and opt-in. Safe to re-run.
alter table profiles add column if not exists whatsapp_opt_in boolean default true;

create table if not exists whatsapp_broadcasts (
  id uuid primary key default gen_random_uuid(),
  created_by uuid,
  template_sid text not null,
  template_name text,
  variables_map jsonb default '{}'::jsonb,
  audience text,
  recipient_count int default 0,
  sent_count int default 0,
  failed_count int default 0,
  created_at timestamptz not null default now()
);

create table if not exists whatsapp_messages (
  id uuid primary key default gen_random_uuid(),
  twilio_sid text,
  category text,
  to_number text,
  template_sid text,
  template_name text,
  variables jsonb,
  status text,
  error_code text,
  error_message text,
  recipient_profile_id uuid,
  booking_id uuid,
  broadcast_id uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz
);

alter table whatsapp_messages add column if not exists created_at timestamptz not null default now();
alter table whatsapp_messages add column if not exists updated_at timestamptz;
alter table whatsapp_messages add column if not exists recipient_profile_id uuid;
alter table whatsapp_messages add column if not exists broadcast_id uuid;
alter table whatsapp_messages add column if not exists booking_id uuid;

create index if not exists whatsapp_messages_twilio_sid_idx on whatsapp_messages (twilio_sid);
create index if not exists whatsapp_messages_reminder_idx on whatsapp_messages (category, recipient_profile_id, created_at);
