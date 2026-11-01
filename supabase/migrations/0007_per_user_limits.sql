-- Direct inserts skip the share function's limits, so one account must not be able to fill the shared database.
create or replace function private.cap_rows() returns trigger
language plpgsql security definer set search_path = ''
as $$
declare n bigint; bytes bigint := 0; recent bigint := 0;
begin
  if new.owner is null then return new; end if;
  perform pg_advisory_xact_lock(hashtext(new.owner::text));
  if tg_table_name = 'reports' then
    select count(*), coalesce(sum(pg_column_size(full_report) + pg_column_size(findings)), 0), count(*) filter (where created_at > now() - interval '1 hour')
      into n, bytes, recent from public.reports where owner = new.owner;
    if recent >= 30 or bytes + pg_column_size(new.full_report) > 50 * 1024 * 1024 then raise exception 'saved report limit reached'; end if;
  else
    execute format('select count(*) from public.%I where owner = $1', tg_table_name) into n using new.owner;
  end if;
  if n >= tg_argv[0]::int then raise exception 'row limit reached'; end if;
  return new;
end $$;
revoke all on function private.cap_rows() from public, anon, authenticated;

create trigger cap_reports before insert on public.reports for each row execute function private.cap_rows('100');
create trigger cap_baselines before insert on public.baselines for each row execute function private.cap_rows('50');
create trigger cap_feedback before insert on public.feedback for each row execute function private.cap_rows('1000');
