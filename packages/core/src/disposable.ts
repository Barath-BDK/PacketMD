// Keep in step with supabase/migrations/0004_history_and_disposable_email.sql, which enforces the same list.
// A list cannot catch every throwaway service, so this raises the bar rather than guaranteeing it.
const KEYWORDS = /tempmail|temp-mail|tmpmail|10minute|minutemail|mailinator|guerrillamail|yopmail|trashmail|throwaway|fakeinbox|fakemail|disposable|discardmail|burnermail|1secmail/;
const DOMAINS = /(^|\.)(sharklasers\.com|grr\.la|spam4\.me|pokemail\.net|tempail\.com|getnada\.com|nada\.email|dropmail\.me|maildrop\.cc|mailnesia\.com|mintemail\.com|mohmal\.com|emailondeck\.com|moakt\.com|mytemp\.email|tmpeml\.com|inboxkitten\.com|mail\.tm|mail\.gw|tempr\.email|discard\.email|spamgourmet\.com|mailcatch\.com|mailsac\.com|harakirimail\.com|33mail\.com|dispostable\.com|owlymail\.com|esiix\.com|wwjmp\.com|xojxe\.com|yoggm\.com|vjuum\.com|rteet\.com|dpptd\.com|kzccv\.com|qiott\.com|laafd\.com|txcct\.com|emltmp\.com|tmail\.ws|tmails\.net)$/;

export function isDisposableEmail(email: string) {
  const domain = (email.trim().toLowerCase().split('@')[1] ?? '').replace(/\.+$/, '');
  return KEYWORDS.test(domain) || DOMAINS.test(domain);
}
