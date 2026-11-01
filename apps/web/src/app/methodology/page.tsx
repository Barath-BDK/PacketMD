import { BUDGET, HYPOTHESES, T, TEMPLATES } from '@packetmd/core';
import accuracy from '@/generated/accuracy.json';

const LIBS: [string, string, string][] = [
  ['Next.js', 'Web framework', 'MIT'], ['React', 'Interface', 'MIT'], ['Tailwind CSS', 'Styling', 'MIT'], ['Lenis', 'Smooth scrolling', 'MIT'],
  ['@supabase/supabase-js', 'Optional accounts and share links', 'MIT'], ['Scapy', 'Generates lab captures only, in labgen/', 'GPL-2.0'], ['Vitest', 'Tests', 'MIT'], ['esbuild', 'Bundles the Worker', 'MIT'],
];

const PAIRS = [
  { symptom: 'A second DHCP server appears', sides: [
    { file: 'rogue-dhcp-benign-router', label: 'Fault', why: 'A home router left plugged in. It offers itself as gateway and leaves DNS answers alone.' },
    { file: 'rogue-dhcp-malicious', label: 'Attack', why: 'It points clients at a foreign DNS server, and the answers that follow are wrong.' },
  ] },
  { symptom: 'A server stops answering', sides: [
    { file: 'server-outage', label: 'Fault', why: 'Known clients retry with doubling waits, and connections worked earlier. The server has gone down.' },
    { file: 'syn-flood', label: 'Attack', why: 'Hundreds of sources send requests at machine speed and never finish the handshake.' },
  ] },
  { symptom: 'Two devices claim one address', sides: [
    { file: 'duplicate-ip', label: 'Fault', why: 'Both only answer when asked, and DHCP handed out an address already in use.' },
    { file: 'arp-spoof', label: 'Attack', why: 'One device sends replies nobody asked for while also holding its own address.' },
  ] },
  { symptom: 'The gateway changes hardware address', sides: [
    { file: 'failover-gratuitous-arp', label: 'Harmless', why: 'The old device goes silent as the new one announces itself: a backup taking over.' },
    { file: 'arp-spoof', label: 'Attack', why: 'The real gateway stays active while another device keeps claiming to be it.' },
  ] },
  { symptom: 'One host probes many ports', sides: [
    { file: 'port-scan-benign-scanner', label: 'Harmless', why: 'It identifies itself as a vulnerability scanner and completes real connections.' },
    { file: 'port-scan-vertical', label: 'Attack', why: 'It tries ports rapidly and almost never finishes a handshake.' },
  ] },
];

const ok = (file: string) => accuracy.rows.find((r) => r.file === file)?.ok ?? false;

export default function Methodology() {
  const fam = (f: string) => Object.entries(HYPOTHESES).filter(([, h]) => h.family === f);
  return (
    <div className="pad">
      <h1 className="disp h2 rise d1" style={{ maxWidth: '18ch' }}>How a verdict <span className="ac">gets made.</span></h1>
      <p className="muted rise d2" style={{ maxWidth: '64ch', fontSize: 17, lineHeight: 1.5 }}>Detectors never decide. Each one only reports signals. Competing explanations collect weight from those signals, and the verdict goes to the winner if it wins clearly. A close race stays Inconclusive, and an attack label is blocked if an innocent explanation matched.</p>
      <section className="veil rise d3" style={{ padding: 24, marginTop: 24 }}>
        <h2 className="disp h3">Same symptoms, different causes</h2>
        <p style={{ lineHeight: 1.5, maxWidth: '68ch' }}>Telling a fault from an attack is the hard part, because they often look identical at first. Each row below is a pair of lab captures with the same symptom and a different cause, and the result comes from the latest test run.</p>
        {PAIRS.map((p) => (
          <div key={p.symptom} className="pair">
            <h3>{p.symptom}</h3>
            <div className="grid-2" style={{ gap: 16 }}>
              {p.sides.map((x) => <div key={x.file}><span className="sm">{x.label}</span><p style={{ margin: '4px 0 0', lineHeight: 1.5 }}>{x.why}</p><p className={ok(x.file) ? 'sm' : 'sm ac'} style={{ margin: '4px 0 0' }}>{ok(x.file) ? 'Told apart correctly' : 'Got this one wrong'}</p></div>)}
            </div>
          </div>
        ))}
        <div className="pair">
          <h3>When the evidence does not settle it</h3>
          <p style={{ lineHeight: 1.5, margin: 0, maxWidth: '68ch' }}>In one lab capture a device claims the gateway, but DHCP also really leased it that address, so both a spoof and a mistake fit. PacketMD refuses to guess, shows the case for each side, and says what to capture next.</p>
        </div>
        <h3 className="disp h3" style={{ marginTop: 24 }}>How far to trust this</h3>
        <p style={{ lineHeight: 1.5, maxWidth: '68ch' }}>All {accuracy.samples} lab captures gave the expected result, including {accuracy.hardNegatives} that are clean or only look suspicious. We generated these captures and tuned the thresholds on them, so that score alone proves little.</p>
        <p style={{ lineHeight: 1.5, maxWidth: '68ch' }}>So we attacked our own detectors. The first round of 26 captures, each built to evade a specific check, caught only 8. After fixing those we wrote two more rounds of attacks the detectors had never seen. Run untuned, <strong>they caught 5 of 11, then 2 of 12</strong>, and the second round also set off 4 false alarms on normal traffic. About 30% is the most honest figure we have for an attack nobody planned for. Those cases are now fixed and all 49 attacks are permanent tests, but a new technique would start from a similar place.</p>
        <p style={{ lineHeight: 1.5, maxWidth: '68ch', marginBottom: 0 }}>A capture also has hard limits. PacketMD cannot see inside encrypted traffic, cannot judge whether a large upload is a backup or a theft, and does not read application payloads for attacks such as SQL injection. An app calling an unnamed host on a fixed timer can still be reported as beaconing. Treat a clean report as "nothing we know how to see", never as proof that a network is safe.</p>
      </section>
      <div className="grid-2" style={{ marginTop: 24 }}>
        <section className="veil" style={{ padding: 24 }}><h2 className="disp h3">Faults we look for</h2><ul style={{ paddingLeft: 18, lineHeight: 1.7 }}>{fam('fault').map(([id, h]) => <li key={id}>{h.title}</li>)}</ul></section>
        <section className="veil" style={{ padding: 24 }}><h2 className="disp h3">Attacks we look for</h2><ul style={{ paddingLeft: 18, lineHeight: 1.7 }}>{fam('attack').map(([id, h]) => <li key={id}>{h.title}. <span className="muted">{TEMPLATES[id]?.analogy}</span></li>)}</ul></section>
      </div>
      <section className="veil" style={{ padding: 24, marginTop: 24 }}>
        <h2 className="disp h3">What a capture cannot tell us</h2>
        <p style={{ lineHeight: 1.5, maxWidth: '64ch' }}>A pcap holds no process names or user accounts. PacketMD never claims either. It says "looks like a browser", shows the basis, and if a name is hidden by encrypted client hello or encrypted DNS, it says the name is hidden and does not guess.</p>
      </section>
      <section className="veil" style={{ padding: 24, marginTop: 24 }}>
        <h2 className="disp h3">Budgets and thresholds</h2>
        <div className="grid-2">
          <table className="t"><tbody>{Object.entries(BUDGET).map(([k, v]) => <tr key={k}><td className="dat">{k}</td><td className="dat">{v}</td></tr>)}</tbody></table>
          <table className="t"><tbody>{Object.entries(T).map(([k, v]) => <tr key={k}><td className="dat">{k}</td><td className="dat">{v}</td></tr>)}</tbody></table>
        </div>
      </section>
      <section className="veil" style={{ padding: 24, marginTop: 24 }}>
        <h2 className="disp h3">Libraries</h2>
        <table className="t"><tbody>{LIBS.map(([n, w, l]) => <tr key={n}><td>{n}</td><td>{w}</td><td className="dat">{l}</td></tr>)}</tbody></table>
        <p className="muted" style={{ lineHeight: 1.5 }}>Parsing, decoding, detection and diagnosis are our own code. Wireshark, tshark, Zeek and Suricata are not used or wrapped.</p>
      </section>
    </div>
  );
}
