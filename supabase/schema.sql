-- ============================================================
-- عين اليقين — قاعدة بيانات عباداتي
-- Run once in Supabase → SQL Editor. Safe to re-run.
--
-- Design:
--  * All tables have RLS on and NO policies, so the public key
--    cannot read or write them directly.
--  * The website talks to the database only through the
--    functions below (SECURITY DEFINER).
--  * Members sign in with email only (owner's decision); each
--    device keeps a random session token.
--  * Sign-up data (phone, birth date, nationality...) is never
--    returned to the website — only admins can read it.
--  * Admins cannot read anyone's ibadat: no function returns them
--    to admins.
-- ============================================================

create extension if not exists pgcrypto;

create table if not exists public.members (
  id           uuid primary key default gen_random_uuid(),
  email        text not null unique check (email = lower(trim(email)) and length(email) between 5 and 254),
  name         text not null check (length(name) between 2 and 120),
  phone        text check (length(phone) <= 30),
  dob          date,
  gender       text check (gender in ('male','female')),
  nationality  text check (length(nationality) <= 60),
  governorate  text check (length(governorate) <= 60),
  with_ay      text check (with_ay in ('yes','no','')),
  relation     text check (length(relation) <= 30),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table if not exists public.sessions (
  token       uuid primary key default gen_random_uuid(),
  member_id   uuid not null references public.members(id) on delete cascade,
  created_at  timestamptz not null default now(),
  last_seen   timestamptz not null default now()
);
create index if not exists sessions_member_idx on public.sessions(member_id);

create table if not exists public.profiles (
  member_id   uuid primary key references public.members(id) on delete cascade,
  data        jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now()
);

create table if not exists public.days (
  member_id   uuid not null references public.members(id) on delete cascade,
  key         text not null check (length(key) <= 64),
  data        jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now(),
  primary key (member_id, key)
);

create table if not exists public.admins (
  email text primary key check (email = lower(trim(email)))
);

alter table public.members  enable row level security;
alter table public.sessions enable row level security;
alter table public.profiles enable row level security;
alter table public.days     enable row level security;
alter table public.admins   enable row level security;

revoke all on public.members, public.sessions, public.profiles, public.days, public.admins from anon, authenticated;

-- ---------- helpers ----------
create or replace function public._member_of(p_token uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare m uuid;
begin
  update sessions set last_seen = now() where token = p_token returning member_id into m;
  if m is null then raise exception 'invalid_session' using errcode = '28000'; end if;
  return m;
end $$;
revoke all on function public._member_of(uuid) from public, anon, authenticated;

-- ---------- sign up ----------
create or replace function public.ay_register(p jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare e text := lower(trim(p->>'email')); m uuid; t uuid;
begin
  if e !~ '^[^\s@]+@[^\s@]+\.[^\s@]{2,}$' then raise exception 'bad_email'; end if;
  if exists (select 1 from members where email = e) then raise exception 'exists'; end if;
  insert into members(email, name, phone, dob, gender, nationality, governorate, with_ay, relation)
  values (e, trim(p->>'name'), p->>'phone', nullif(p->>'dob','')::date, nullif(p->>'gender',''),
          p->>'nationality', nullif(p->>'governorate',''), coalesce(p->>'withAY',''), nullif(p->>'relation',''))
  returning id into m;
  insert into profiles(member_id) values (m);
  insert into sessions(member_id) values (m) returning token into t;
  return jsonb_build_object('token', t, 'email', e, 'name', trim(p->>'name'));
end $$;

-- ---------- sign in (email only) ----------
create or replace function public.ay_sign_in(p_email text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare e text := lower(trim(p_email)); m uuid; n text; t uuid;
begin
  select id, name into m, n from members where email = e;
  if m is null then return null; end if;
  insert into sessions(member_id) values (m) returning token into t;
  return jsonb_build_object('token', t, 'email', e, 'name', n);
end $$;

create or replace function public.ay_sign_out(p_token uuid)
returns void language sql security definer set search_path = public as $$
  delete from sessions where token = p_token;
$$;

-- ---------- load / save own ibadat ----------
create or replace function public.ay_load(p_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare m uuid := _member_of(p_token); r jsonb;
begin
  select jsonb_build_object(
    'email', mb.email, 'name', mb.name,
    'prof', coalesce((select data from profiles where member_id = m), '{}'::jsonb),
    'days', coalesce((select jsonb_object_agg(key, data) from days where member_id = m), '{}'::jsonb))
  into r from members mb where mb.id = m;
  return r;
end $$;

create or replace function public.ay_save_prof(p_token uuid, p_data jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare m uuid := _member_of(p_token);
begin
  if pg_column_size(p_data) > 200000 then raise exception 'too_large'; end if;
  insert into profiles(member_id, data, updated_at) values (m, p_data, now())
  on conflict (member_id) do update set data = excluded.data, updated_at = now();
end $$;

create or replace function public.ay_save_day(p_token uuid, p_key text, p_data jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare m uuid := _member_of(p_token);
begin
  if pg_column_size(p_data) > 50000 then raise exception 'too_large'; end if;
  if (select count(*) from days where member_id = m) > 2000 then raise exception 'too_many'; end if;
  insert into days(member_id, key, data, updated_at) values (m, p_key, p_data, now())
  on conflict (member_id, key) do update set data = excluded.data, updated_at = now();
end $$;

-- ---------- admin: sign-up data only ----------
create or replace function public.ay_admin_members()
returns setof jsonb language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from admins where email = lower(coalesce(auth.jwt()->>'email',''))) then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  return query
    select jsonb_build_object(
      'email', mb.email, 'name', mb.name, 'phone', mb.phone, 'dob', mb.dob,
      'gender', mb.gender, 'nationality', mb.nationality, 'governorate', mb.governorate,
      'with_ay', mb.with_ay, 'relation', mb.relation, 'created_at', mb.created_at,
      'last_seen', (select max(last_seen) from sessions s where s.member_id = mb.id))
    from members mb order by mb.created_at desc;
end $$;

revoke all on function public.ay_register(jsonb), public.ay_sign_in(text), public.ay_sign_out(uuid),
  public.ay_load(uuid), public.ay_save_prof(uuid, jsonb), public.ay_save_day(uuid, text, jsonb),
  public.ay_admin_members() from public;
grant execute on function public.ay_register(jsonb), public.ay_sign_in(text), public.ay_sign_out(uuid),
  public.ay_load(uuid), public.ay_save_prof(uuid, jsonb), public.ay_save_day(uuid, text, jsonb)
  to anon, authenticated;
grant execute on function public.ay_admin_members() to authenticated;

-- ---------- is this email an admin? (used to show the password box) ----------
create or replace function public.ay_is_admin(p_email text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from admins where email = lower(trim(p_email)));
$$;
revoke all on function public.ay_is_admin(text) from public;
grant execute on function public.ay_is_admin(text) to anon, authenticated;
