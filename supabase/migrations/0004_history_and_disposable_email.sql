-- Investigation history needs the file name. Keep the list in step with packages/core/src/disposable.ts.
alter table public.reports add column file_name text check (length(file_name) <= 200);

create or replace function private.reject_disposable_email() returns trigger
language plpgsql security definer set search_path = ''
as $$
declare d text := lower(split_part(new.email, '@', 2));
begin
  if d ~ 'tempmail|temp-mail|tmpmail|10minute|minutemail|mailinator|guerrillamail|yopmail|trashmail|throwaway|fakeinbox|fakemail|disposable|discardmail|burnermail|1secmail'
     or d ~ '(^|\.)(sharklasers\.com|grr\.la|spam4\.me|pokemail\.net|tempail\.com|getnada\.com|nada\.email|dropmail\.me|maildrop\.cc|mailnesia\.com|mintemail\.com|mohmal\.com|emailondeck\.com|moakt\.com|mytemp\.email|tmpeml\.com|inboxkitten\.com|mail\.tm|mail\.gw|tempr\.email|discard\.email|spamgourmet\.com|mailcatch\.com|mailsac\.com|harakirimail\.com|33mail\.com|dispostable\.com|owlymail\.com|esiix\.com|wwjmp\.com|xojxe\.com|yoggm\.com|vjuum\.com|rteet\.com|dpptd\.com|kzccv\.com|qiott\.com|laafd\.com|txcct\.com|emltmp\.com|tmail\.ws|tmails\.net)$'
  then
    raise exception 'temporary email addresses are not accepted';
  end if;
  return new;
end $$;
revoke all on function private.reject_disposable_email() from public, anon, authenticated;

-- In the database, so calling the sign-up API directly cannot get around the browser check.
create trigger reject_disposable_email before insert or update of email on auth.users
  for each row execute function private.reject_disposable_email();
