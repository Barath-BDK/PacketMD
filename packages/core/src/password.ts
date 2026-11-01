export interface PasswordRule { id: string; label: string; ok: boolean }

export const PASSWORD_MIN = 12;
// bcrypt, which Supabase Auth uses, ignores everything past 72 bytes.
export const PASSWORD_MAX = 72;

// Passwords and roots that top breach lists. Matched after undoing common swaps such as @ for a.
const COMMON = ['password', 'passwd', 'qwerty', 'letmein', 'welcome', 'admin', 'administrator', 'iloveyou', 'dragon', 'monkey', 'football', 'baseball', 'master', 'sunshine', 'princess', 'shadow', 'superman', 'batman', 'trustno', 'starwars', 'whatever', 'freedom', 'changeme', 'default', 'secret', 'login', 'abc123', 'packetmd'];
const KEYBOARD = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx3edc', '1q2w3e4r5t'];
const LEET: Record<string, string> = { '@': 'a', '4': 'a', '0': 'o', '1': 'i', '!': 'i', '3': 'e', '$': 's', '5': 's', '7': 't' };

function hasRun(s: string) {
  for (let i = 0; i + 3 < s.length; i++) {
    const c = [0, 1, 2, 3].map((n) => s.charCodeAt(i + n));
    const step = c[1]! - c[0]!;
    if (Math.abs(step) <= 1 && c[2]! - c[1]! === step && c[3]! - c[2]! === step) return true; // 1234, dcba, aaaa
  }
  return KEYBOARD.some((row) => {
    const both = row + [...row].reverse().join('');
    for (let i = 0; i + 4 <= both.length; i++) if (s.includes(both.slice(i, i + 4))) return true;
    return false;
  });
}

/** Every rule is shown live while typing and all must pass before an account can be created. */
export function checkPassword(pw: string, email = ''): PasswordRule[] {
  const low = pw.toLowerCase();
  const plain = low.replace(/[@4013!$57]/g, (c) => LEET[c]!);
  const name = email.split('@')[0]?.toLowerCase() ?? '';
  const bytes = new TextEncoder().encode(pw).length;
  return [
    { id: 'length', label: `At least ${PASSWORD_MIN} characters`, ok: pw.length >= PASSWORD_MIN && bytes <= PASSWORD_MAX },
    { id: 'upper', label: 'An uppercase letter (A to Z)', ok: /[A-Z]/.test(pw) },
    { id: 'lower', label: 'A lowercase letter (a to z)', ok: /[a-z]/.test(pw) },
    { id: 'digit', label: 'A number (0 to 9)', ok: /\d/.test(pw) },
    { id: 'symbol', label: 'A symbol, such as ! ? # or %', ok: /[^A-Za-z0-9\s]/.test(pw) },
    { id: 'pattern', label: 'No runs like 1234, abcd, aaaa or qwer', ok: pw.length > 0 && !hasRun(low) },
    { id: 'common', label: 'No common words like password or admin', ok: pw.length > 0 && !COMMON.some((w) => low.includes(w) || plain.includes(w)) },
    { id: 'email', label: 'Does not contain your email name', ok: pw.length > 0 && (name.length < 3 || !low.includes(name)) },
  ];
}

export const passwordOk = (pw: string, email = '') => checkPassword(pw, email).every((r) => r.ok);
