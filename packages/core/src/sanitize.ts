import { BUDGET } from './thresholds';

// Control chars, bidi overrides and zero-width chars: nothing from a capture may steer the display.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;

/** Every packet-derived string passes through here before it leaves the parser. */
export function safeText(s: string, max: number = BUDGET.maxString): string {
  const clean = s.replace(UNSAFE, '�');
  return clean.length > max ? clean.slice(0, max) + '...' : clean;
}

/** Cell and line prefixes that spreadsheets and Markdown treat as live content. */
export function neutralize(s: string): string {
  const t = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return t.replace(/[\\|`<>[\]]/g, (c) => '\\' + c);
}

/** Filenames arrive from the OS and are as untrusted as packets. */
export function safeName(name: string): string {
  const base = name.split(/[\\/]/).pop() || 'capture';
  return safeText(base, 120);
}

export function shellArg(s: string): string | null {
  // Fix commands only ever carry IPs, MACs, ports or DNS names. Anything else is dropped.
  // A leading dash would be read as an option by the command, so it never starts a value.
  return /^[A-Za-z0-9.:_][A-Za-z0-9.:_-]{0,252}$/.test(s) ? s : null;
}
