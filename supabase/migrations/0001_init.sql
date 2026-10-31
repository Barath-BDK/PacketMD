-- PacketMD backend. Packets never reach this database: only schema-checked findings do.

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  role text not null default 'analyst' check (role in ('analyst', 'admin')),
  created_at timestamptz not null default now()
);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  owner uuid references auth.users on delete cascade, -- null only for guest shares, readable through the Edge Function alone
  created_at timestamptz not null default now(),
  file_sha256 text not null check (file_sha256 ~ '^[0-9a-f]{64}$'),
  summary jsonb not null check (pg_column_size(summary) < 8192),
  findings jsonb not null check (jsonb_typeof(findings) = 'array' and pg_column_size(findings) < 262144),
  pseudonymised boolean not null default true
);
create index reports_owner_idx on public.reports (owner);

create table public.baselines (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users on delete cascade,
  name text not null check (length(name) between 1 and 80),
  identity jsonb not null check (pg_column_size(identity) < 65536),
  created_at timestamptz not null default now()
);
create index baselines_owner_idx on public.baselines (owner);

create table public.shares (
  token text primary key check (token ~ '^[0-9a-f]{32}$'),
  report_id uuid not null references public.reports on delete cascade,
  expires_at timestamptz not null
);
create index shares_report_idx on public.shares (report_id);

create table public.feedback (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users on delete cascade,
  finding_type text not null check (length(finding_type) < 64),
  verdict text not null check (verdict in ('correct', 'false-positive', 'false-negative')),
  note text check (length(note) < 500),
  created_at timestamptz not null default now()
);
create index feedback_owner_idx on public.feedback (owner);

create table public.share_limits (
  key text not null,
  window_start timestamptz not null,
  hits int not null default 0,
  primary key (key, window_start)
);

-- Role lookups must not re-enter RLS on profiles.
create function public.is_admin() returns boolean
language sql stable security definer set search_path = ''
as $$ select exists (select 1 from public.profiles where id = (select auth.uid()) and role = 'admin') $$;

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = ''
as $$ begin insert into public.profiles (id) values (new.id); return new; end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

create function public.bump_share_rate(k text, max_hits int) returns boolean
language plpgsql security definer set search_path = ''
as $$
declare w timestamptz := date_trunc('hour', now()); n int;
begin
  delete from public.share_limits where window_start < now() - interval '1 day';
  insert into public.share_limits (key, window_start, hits) values (k, w, 1)
  on conflict (key, window_start) do update set hits = public.share_limits.hits + 1 returning hits into n;
  return n <= max_hits;
end $$;

revoke all on function public.handle_new_user() from public, anon, authenticated;
revoke all on function public.bump_share_rate(text, int) from public, anon, authenticated;
grant execute on function public.bump_share_rate(text, int) to service_role;
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

alter table public.profiles enable row level security;
alter table public.reports enable row level security;
alter table public.baselines enable row level security;
alter table public.shares enable row level security;
alter table public.feedback enable row level security;
alter table public.share_limits enable row level security;

-- Guests get nothing directly. Their only door is the share-report function.
revoke all on all tables in schema public from anon;
revoke all on all tables in schema public from authenticated;
grant select on public.profiles to authenticated;
grant select, insert, delete on public.reports to authenticated;
grant select, insert, delete on public.baselines to authenticated;
grant select, insert on public.feedback to authenticated;

-- No update policy on profiles: nobody can raise their own role from the client.
create policy "read own profile or admin" on public.profiles for select to authenticated using (id = (select auth.uid()) or (select public.is_admin()));
create policy "read own reports or admin" on public.reports for select to authenticated using (owner = (select auth.uid()) or (select public.is_admin()));
create policy "insert own reports" on public.reports for insert to authenticated with check (owner = (select auth.uid()));
create policy "delete own reports" on public.reports for delete to authenticated using (owner = (select auth.uid()));
create policy "read own baselines" on public.baselines for select to authenticated using (owner = (select auth.uid()));
create policy "insert own baselines" on public.baselines for insert to authenticated with check (owner = (select auth.uid()));
create policy "delete own baselines" on public.baselines for delete to authenticated using (owner = (select auth.uid()));
create policy "read own feedback or admin" on public.feedback for select to authenticated using (owner = (select auth.uid()) or (select public.is_admin()));
create policy "insert own feedback" on public.feedback for insert to authenticated with check (owner = (select auth.uid()));
