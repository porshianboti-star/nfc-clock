-- NFC attendance clock — schema `clock` in the shared CompanyCard/MeetingBrand Supabase project.
-- Idempotent. Applied 2026-10-22 through the Management API (database/query).
-- Access model: NO grants to anon/authenticated; only the Edge Function (service_role) touches
-- these tables. RLS is enabled with no policies as a second fence.

create extension if not exists pgcrypto;
create schema if not exists clock;

-- 256-bit secret keys (admin link, personal install link, device token) — base64url, 43 chars
create or replace function clock.gen_key() returns text
language sql volatile set search_path = clock, pg_temp as
$$ select translate(encode(extensions.gen_random_bytes(32), 'base64'), '+/=', '-_') $$;

-- short readable tag code for the sticker URL (8 chars, no 0/O/1/I)
create or replace function clock.gen_code() returns text
language plpgsql volatile set search_path = clock, pg_temp as $$
declare a text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; r text := ''; i int;
        b bytea := extensions.gen_random_bytes(8);
begin
  for i in 0..7 loop r := r || substr(a, (get_byte(b, i) % 32) + 1, 1); end loop;
  return r;
end $$;

create table if not exists clock.orgs (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  admin_key  text not null unique default clock.gen_key(),
  tz         text not null default 'Asia/Jerusalem',
  created_at timestamptz not null default now()
);

create table if not exists clock.workers (
  id                uuid primary key default gen_random_uuid(),
  org_id            uuid not null references clock.orgs(id) on delete cascade,
  name              text not null,
  phone             text,
  install_key       text not null unique default clock.gen_key(),
  device_token_hash text,
  bound_at          timestamptz,
  link_opened_at    timestamptz,
  active            boolean not null default true,
  created_at        timestamptz not null default now()
);
create index if not exists workers_org_idx on clock.workers (org_id);
create index if not exists workers_token_idx on clock.workers (device_token_hash);

create table if not exists clock.tags (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references clock.orgs(id) on delete cascade,
  code       text not null unique default clock.gen_code(),
  location   text not null,
  lat        double precision,
  lng        double precision,
  radius_m   integer not null default 150,
  created_at timestamptz not null default now()
);
create index if not exists tags_org_idx on clock.tags (org_id);

create table if not exists clock.events (
  id          bigint generated always as identity primary key,
  org_id      uuid not null references clock.orgs(id) on delete cascade,
  worker_id   uuid not null references clock.workers(id) on delete cascade,
  tag_id      uuid references clock.tags(id) on delete set null,
  kind        text not null check (kind in ('in', 'out')),
  ts          timestamptz not null default now(),
  lat         double precision,
  lng         double precision,
  accuracy_m  integer,
  distance_m  integer,
  flags       text[] not null default '{}',
  source      text not null default 'tap',
  note        text,
  created_at  timestamptz not null default now()
);
create index if not exists events_org_ts_idx on clock.events (org_id, ts desc);
create index if not exists events_worker_ts_idx on clock.events (worker_id, ts desc);

alter table clock.orgs    enable row level security;
alter table clock.workers enable row level security;
alter table clock.tags    enable row level security;
alter table clock.events  enable row level security;

revoke all on schema clock from public, anon, authenticated;
grant usage on schema clock to service_role;
grant all on all tables in schema clock to service_role;
grant all on all sequences in schema clock to service_role;
grant execute on all functions in schema clock to service_role;
alter default privileges in schema clock grant all on tables to service_role;
alter default privileges in schema clock grant all on sequences to service_role;
