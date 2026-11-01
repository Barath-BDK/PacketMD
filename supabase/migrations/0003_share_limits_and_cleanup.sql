-- Each rate check also clears expired guest shares, so guest data cannot pile up forever.
create or replace function public.bump_share_rate(k text, max_hits int) returns boolean
language plpgsql security definer set search_path = ''
as $$
declare w timestamptz := date_trunc('hour', now()); n int;
begin
  delete from public.share_limits where window_start < now() - interval '1 day';
  delete from public.reports r using public.shares s where s.report_id = r.id and r.owner is null and s.expires_at < now();
  insert into public.share_limits (key, window_start, hits) values (k, w, 1)
  on conflict (key, window_start) do update set hits = public.share_limits.hits + 1 returning hits into n;
  return n <= max_hits;
end $$;
revoke all on function public.bump_share_rate(text, int) from public, anon, authenticated;
grant execute on function public.bump_share_rate(text, int) to service_role;
