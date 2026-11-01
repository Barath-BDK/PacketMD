export interface Technique { id: string; name: string; url: string }

const make = (id: string, name: string): Technique => ({ id, name, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` });

// Checked page by page against ATT&CK v20 on attack.mitre.org. Names are MITRE's own page titles.
// A label appears only where MITRE describes the behaviour. Null means no technique does, so none is claimed.
const MAP: Record<string, Technique | null> = {
  'arp-spoof': make('T1557.002', 'Adversary-in-the-Middle: ARP Cache Poisoning'),
  'rogue-dhcp-attack': make('T1557.003', 'Adversary-in-the-Middle: DHCP Spoofing'),
  'dhcp-starvation': make('T1557.003', 'Adversary-in-the-Middle: DHCP Spoofing'), // this page describes DHCP exhaustion
  'dns-hijack': make('T1557', 'Adversary-in-the-Middle'),
  'llmnr-poison': make('T1557.001', 'Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay'),
  'icmp-redirect': make('T1557', 'Adversary-in-the-Middle'),
  'rogue-ra': make('T1557', 'Adversary-in-the-Middle'),
  'port-scan': make('T1046', 'Network Service Discovery'),
  'syn-flood': make('T1499.001', 'Endpoint Denial of Service: OS Exhaustion Flood'),
  'udp-flood': make('T1498.001', 'Network Denial of Service: Direct Network Flood'),
  reflection: make('T1498.002', 'Network Denial of Service: Reflection Amplification'),
  slowloris: make('T1499', 'Endpoint Denial of Service'), // no sub-technique covers holding connections open at low volume
  'dns-tunnel': make('T1071.004', 'Application Layer Protocol: DNS'),
  'icmp-tunnel': make('T1095', 'Non-Application Layer Protocol'),
  'brute-force': make('T1110.001', 'Brute Force: Password Guessing'),
  beaconing: make('T1071', 'Application Layer Protocol'),
  'dga-domain': make('T1568.002', 'Dynamic Resolution: Domain Generation Algorithms'),
  'data-exfil': make('T1048', 'Exfiltration Over Alternative Protocol'),
  'parser-evasion': null, // T1499.004 needs a real software flaw being exploited, which a capture cannot show
  'rst-injection': null, // T1565.002 is about altering data in transit, not ending a connection
  'mac-flood': null,
  'vlan-hopping': null, // T1599 needs a compromised network device, which double tagging does not
};

/** Worked out from the hypothesis, so reports saved before this existed get labels too. */
export const techniqueOf = (hypothesis: string): Technique | null => MAP[hypothesis] ?? null;
export const mapped = (hypothesis: string) => hypothesis in MAP;
