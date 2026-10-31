-- is_admin stays callable from policies but leaves the schema exposed over the REST API.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create function private.is_admin() returns boolean
language sql stable security definer set search_path = ''
as $$ select exists (select 1 from public.profiles where id = (select auth.uid()) and role = 'admin') $$;
revoke all on function private.is_admin() from public, anon;
grant execute on function private.is_admin() to authenticated;

drop policy "read own profile or admin" on public.profiles;
drop policy "read own reports or admin" on public.reports;
drop policy "read own feedback or admin" on public.feedback;
create policy "read own profile or admin" on public.profiles for select to authenticated using (id = (select auth.uid()) or (select private.is_admin()));
create policy "read own reports or admin" on public.reports for select to authenticated using (owner = (select auth.uid()) or (select private.is_admin()));
create policy "read own feedback or admin" on public.feedback for select to authenticated using (owner = (select auth.uid()) or (select private.is_admin()));
drop function public.is_admin();

-- Reached only by the service role inside the Edge Function. Stated outright rather than left implicit.
create policy "no direct access" on public.shares for all to anon, authenticated using (false) with check (false);
create policy "no direct access" on public.share_limits for all to anon, authenticated using (false) with check (false);
