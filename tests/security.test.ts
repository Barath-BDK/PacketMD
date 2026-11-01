import { fullPayload, payload, pseudonymize } from '../apps/web/src/lib/payload';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze, BUDGET, HYPOTHESES, TEMPLATES, mapped, techniqueOf, toMarkdown, checkPassword, isDisposableEmail, decode, gate, neutralize, parseFilter, passwordOk, Rejected, safeText, Sha256, md5, type ByteSource, type RawPacket, type Report } from '@packetmd/core';
import { createHash } from 'node:crypto';
import { fileSource } from '../packages/cli/src/source';

const mem = (b: Uint8Array): ByteSource => ({ size: b.length, read: async (o, l) => b.subarray(o, o + l) });
const manifest = JSON.parse(readFileSync('labgen/hostile/manifest.json', 'utf8')) as { file: string; uploadName: string; expect: string; attack: string }[];
const hostile = (f: string) => new Uint8Array(readFileSync(`labgen/hostile/${f}`));

describe('intake gate', () => {
  const pcap = new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, ...new Array(20).fill(0)]);
  it('keeps a valid capture with a very long name', () => expect(gate(`${'a'.repeat(300)}.pcap`, 100, pcap).ok).toBe(true));
  it('needs extension and magic to agree', () => {
    expect(gate('a.pcap', 100, pcap).ok).toBe(true);
    expect(gate('a.pcapng', 100, pcap).ok).toBe(false);
    expect(gate('a.exe', 100, pcap).ok).toBe(false);
    expect(gate('a.pcap.zip', 100, pcap).ok).toBe(false);
  });
  it('accepts all five magics', () => {
    for (const m of [[0xa1, 0xb2, 0xc3, 0xd4], [0xd4, 0xc3, 0xb2, 0xa1], [0xa1, 0xb2, 0x3c, 0x4d], [0x4d, 0x3c, 0xb2, 0xa1]]) expect(gate('a.pcap', 100, new Uint8Array(m)).ok).toBe(true);
    expect(gate('a.pcapng', 100, new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a])).ok).toBe(true);
  });
  it('refuses a file over the size budget', () => expect(gate('a.pcap', BUDGET.maxFileBytes + 1, pcap).ok).toBe(false));
  it('names what a disguised file really is', () => expect(gate('a.pcap', 100, new Uint8Array([0x4d, 0x5a, 0, 0])).reason).toContain('Windows program'));
});

describe('hostile corpus', () => {
  for (const h of manifest) it(`${h.file}: ${h.attack}`, async () => {
    let r: Report | null = null, rejected = false;
    try { r = await analyze(mem(hostile(h.file)), h.uploadName); }
    catch (e) { if (e instanceof Rejected) rejected = true; else throw e; }
    if (h.expect === 'rejected') expect(rejected).toBe(true);
    else expect(r).not.toBeNull();
    if (h.expect === 'evasion') expect(r!.findings.some((f) => f.hypothesis === 'parser-evasion')).toBe(true);
    if (r) {
      expect(r.defense.fileName).not.toContain('/');
      expect(JSON.stringify(r)).not.toMatch(/[‮\u0000]/);
    }
  });
  it('never hands the UI a raw eicar payload', async () => {
    const r = await analyze(mem(hostile('eicar-payload.pcap')), 'e.pcap');
    expect(JSON.stringify(r)).not.toContain('EICAR');
  });
  it('keeps the HTML hostname inert text', async () => {
    const r = await analyze(mem(hostile('hostile-hostnames.pcap')), 'h.pcap');
    const row = r.rows[0]!;
    expect(row.info).toContain('<img');
    expect(/[‮\u0000]/.test(JSON.stringify(r.rows))).toBe(false);
  });
  it('reports unsupported link types plainly', async () => {
    const r = await analyze(mem(hostile('wifi-linktype.pcap')), 'w.pcap');
    expect(r.defense.unsupportedLink).toBe(true);
  });
});

describe('sanitising', () => {
  it('strips controls and bidi', () => expect(safeText('a‮b\0c')).toBe('a�b�c'));
  it('truncates', () => expect(safeText('x'.repeat(999)).length).toBeLessThan(300));
  it('neutralises spreadsheet formulas', () => { for (const c of ['=', '+', '-', '@']) expect(neutralize(`${c}cmd`).startsWith("'")).toBe(true); });
});

describe('offsets', () => {
  it('reproduce the exact packet bytes', async () => {
    const file = 'samples/mixed-incident.pcap', bytes = readFileSync(file);
    const src = fileSource(file), r = await analyze(src, file);
    src.close();
    for (const f of r.findings) for (const e of f.evidence) {
      const data = new Uint8Array(bytes.subarray(e.dataOffset, e.dataOffset + e.capLen));
      const raw: RawPacket = { no: e.no, ts: e.ts, capLen: e.capLen, origLen: e.capLen, linkType: 1, recordOffset: e.recordOffset, dataOffset: e.dataOffset, data };
      expect(decode(raw).info).toBe(e.info);
      expect(bytes.readUInt32LE(e.recordOffset + 8)).toBe(e.capLen);
    }
  });
});

describe('own hashes', () => {
  it('sha256 matches node crypto across chunk boundaries', () => {
    const b = new Uint8Array(1000).map((_, i) => i & 255), h = new Sha256();
    h.update(b.subarray(0, 63)); h.update(b.subarray(63, 500)); h.update(b.subarray(500));
    expect(h.digest()).toBe(createHash('sha256').update(b).digest('hex'));
  });
  it('md5 matches node crypto', () => expect(md5('771,4865-4866,0-23,29-23,0')).toBe(createHash('md5').update('771,4865-4866,0-23,29-23,0').digest('hex')));
});

describe('temporary email block', () => {
  it('refuses throwaway services, including subdomains and new variants', () => {
    for (const e of ['a@mailinator.com', 'A@MAILINATOR.COM', 'a@sub.mailinator.com', 'a@yopmail.fr', 'a@guerrillamail.net', 'a@10minutemail.co', 'a@temp-mail.org', 'a@sharklasers.com', 'a@mail.tm']) expect(isDisposableEmail(e), e).toBe(true);
  });
  it('allows normal addresses', () => {
    for (const e of ['cs23i1005@iiitdm.ac.in', 'a@gmail.com', 'a@outlook.com', 'a@protonmail.com', 'a@hotmail.tm.example', '']) expect(isDisposableEmail(e), e).toBe(false);
  });
});

describe('password rules', () => {
  it('refuses weak passwords', () => {
    for (const p of ['1234567890', '12345678901234', 'password', 'P@ssw0rd12345!', 'Qwertyuiop12!', 'Aaaaaaaaaaa1!', 'Abcdefgh1234!', 'short1!A']) expect(passwordOk(p), p).toBe(false);
  });
  it('accepts a strong one', () => expect(passwordOk('Tiger-Plum9!river', 'sam@example.com')).toBe(true));
  it('refuses a password holding the email name', () => expect(passwordOk('Barath-Plum9!river', 'barath@example.com')).toBe(false));
  it('refuses more than bcrypt can use', () => expect(passwordOk('Tiger-Plum9!' + 'kx'.repeat(40))).toBe(false));
  it('shows every rule unmet for an empty box', () => expect(checkPassword('').filter((r) => r.ok).length).toBeLessThanOrEqual(1));
});

describe('filter language', () => {
  const env = { findings: [] };
  const row = { no: 5, ts: 0, src: '10.0.0.1', dst: '10.0.0.2', proto: 'TCP', len: 60, info: '', capLen: 60, recordOffset: 0, dataOffset: 0, sport: 443, dport: 5000, linkType: 1 };
  it('combines with and/or/not', () => {
    expect(parseFilter('ip.src == 10.0.0.1 and not proto == udp', env)(row)).toBe(true);
    expect(parseFilter('(ip.src == 1.1.1.1 or tcp.port == 443) && frame.number in 1-9', env)(row)).toBe(true);
  });
  it('explains errors in plain words', () => expect(() => parseFilter('nonsense == 1', env)).toThrow(/does not know/));
  it('treats code as a harmless unknown field', () => expect(() => parseFilter('process.exit(1)', env)).toThrow());
  it('only ever raises its own plain error, whatever is typed', () => {
    const hostile = ['constructor == 1', '__proto__ == x', 'toString == 1', 'hasOwnProperty == a', '<script>alert(1)</script>', '<img src=x onerror=alert(1)> == 1', "' OR 1=1 --", '"', '""', '((((', '))))', 'not', '!', 'and', 'or or', '==', '== ==',
      'ip.addr ==', 'tcp.port == abc', 'tcp.port == 99999', 'tcp.port == -1', 'tcp.port == 1e3', 'tcp.port == 0x50', 'frame.number == 1.5', 'frame.number in 1-', 'frame.number in 1-99999999999', 'flag:', 'flag:__proto__', 'finding:', 'finding:__proto__',
      'domain contains', 'dns.qry.name contains ""', '('.repeat(5000), 'not '.repeat(5000), '!'.repeat(50000), 'a'.repeat(100000), 'ip.src == 1 or '.repeat(200) + 'ip.src == 1'];
    for (const q of hostile) {
      try { parseFilter(q, env)(row); expect.unreachable(`accepted ${q.slice(0, 30)}`); } catch (e) {
        expect((e as Error).constructor.name, q.slice(0, 30)).toBe('FilterError');
        expect((e as Error).message.length, q.slice(0, 30)).toBeLessThan(120);
      }
    }
  });
  it('does not repeat control or direction characters in an error', () => {
    try { parseFilter('\u202egnp\u0007 == 1', env); expect.unreachable(); } catch (e) { expect((e as Error).message).not.toMatch(/[\u0000-\u001f\u202e]/); }
  });
  it('still allows long honest filters and a blank box', () => {
    expect(parseFilter('   ', env)(row)).toBe(true);
    expect(parseFilter(Array.from({ length: 12 }, (_, i) => `tcp.port == ${i + 440}`).join(' or '), env)(row)).toBe(true);
    expect(parseFilter('flag:rst', env)(row)).toBe(false);
  });
});

describe('claim-to-packet binding and stories', () => {
  const all = readdirSync('samples').filter((f) => f.endsWith('.pcap') && !f.startsWith('large'));
  it('every finding has evidence and every story cites only real packets and hosts', async () => {
    for (const name of all) {
      const src = fileSource(`samples/${name}`), r = await analyze(src, name);
      src.close();
      const hosts = new Set(r.rows.flatMap((x) => [x.src, x.dst]));
      for (const f of r.findings) {
        expect(f.evidence.length).toBeGreaterThan(0);
        for (const st of f.story) {
          for (const p of st.packets) expect(p).toBeLessThanOrEqual(r.rows.length);
          for (const e of st.edges) { expect(hosts.has(e.from)).toBe(true); expect(hosts.has(e.to)).toBe(true); }
        }
      }
    }
  });
});

describe('saved report', () => {
  it('keeps the investigation but no packets or real addresses', async () => {
    const s = fileSource('samples/mixed-incident.pcap'), r = await analyze(s, 'mixed-incident.pcap');
    s.close();
    const full = fullPayload(r), text = JSON.stringify(full);
    expect(full.rows).toEqual([]);
    expect(full.findings.length).toBe(r.findings.length);
    expect(full.findings[0]!.story.length).toBeGreaterThan(0);
    expect(full.findings[0]!.hypotheses.length).toBeGreaterThan(0);
    expect(full.timeline.length).toBeGreaterThan(0);
    expect(text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
    expect(text).not.toMatch(/([0-9a-f]{2}:){5}/i);
    expect(text.length).toBeLessThan(2_500_000);
    expect(payload(r).findings.map((f) => f.plain)).toEqual(full.findings.map((f) => f.plain));
  });
});

describe('share payload', () => {
  it('replaces IPv4, IPv6 and MAC addresses but not times', () => {
    const out = JSON.stringify(pseudonymize({ a: '192.168.1.10 and 00:1a:2b:00:00:10', b: '2001:db8::1 and fe80::1:2', c: 'at 10:30:15' }));
    expect(out).not.toMatch(/192\.168|00:1a|2001:db8|fe80/);
    expect(out).toContain('10:30:15');
  });
});

describe('audit fixes', () => {
  const cmds = (id: string, f: Record<string, unknown>) => JSON.stringify(TEMPLATES[id]!.fix(f as never));
  it('drops any fix command built from a hostile DNS name', () => {
    for (const bad of ['a,;echo INJECTED;', 'a,$(id).x', 'a b', 'a"b', '-fdummy.txt', 'a,-x']) {
      expect(cmds('dns-failure', { server: '10.0.0.53', sample: bad }), bad).not.toContain('dig @');
      expect(cmds('dns-tunnel', { domain: bad }), bad).not.toContain('local-zone');
      expect(cmds('dns-hijack', { qname: bad, forged: bad }), bad).not.toContain('iptables');
    }
  });
  it('still writes the command for a normal name', () => {
    expect(cmds('dns-failure', { server: '10.0.0.53', sample: 'www.example.com' })).toContain('dig @10.0.0.53 www.example.com');
  });
  it('a backslash cannot undo Markdown escaping', () => {
    expect(neutralize('\\[click\\](https://x.invalid)')).toBe('\\\\\\[click\\\\\\](https://x.invalid)');
    expect(neutralize('\\<img>')).toBe('\\\\\\<img\\>');
  });
  it('masks every address form the engine writes', () => {
    const out = JSON.stringify(pseudonymize({ a: 'findstr 00-1a-2b-00-00-10', b: '00:1a:2b:00:00:10', c: '::ffff:a00:1', d: '2001:db8:aa:bb:cc:dd:ee:ff', e: '::1', t: 'at 10:30:05', ip: 'edge-10.0.0.5.pcap' })) as string;
    for (const raw of ['00-1a-2b', '00:1a:2b', 'ffff:a00', '2001:db8', '::1', '10.0.0.5']) expect(out, raw).not.toContain(raw);
    expect(out).toContain('10:30:05');
    const j = JSON.parse(out) as { a: string; b: string };
    expect(j.a).toBe(`findstr ${j.b}`);
  });
  it('cannot be hung by a crafted name', () => {
    const t = performance.now();
    pseudonymize({ d: Array.from({ length: 300 }, () => `a:b:${'a'.repeat(240)}g`) });
    expect(performance.now() - t).toBeLessThan(500);
  });
});

describe('MITRE ATT&CK labels', () => {
  it('every attack has a decision, and every id is well formed', () => {
    for (const [id, h] of Object.entries(HYPOTHESES)) {
      if (h.family !== 'attack') { expect(techniqueOf(id), id).toBeNull(); continue; }
      expect(mapped(id), id).toBe(true);
      const t = techniqueOf(id);
      if (t) { expect(t.id, id).toMatch(/^T\d{4}(\.\d{3})?$/); expect(t.url).toBe(`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`); }
    }
  });
  it('appears in the Markdown export', async () => {
    const s = fileSource('samples/arp-spoof.pcap'), r = await analyze(s, 'arp-spoof.pcap');
    s.close();
    expect(toMarkdown(r)).toContain('MITRE ATT&CK: T1557.002 ARP Cache Poisoning');
  });
});
