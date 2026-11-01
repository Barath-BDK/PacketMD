export interface Technique { id: string; name: string; url: string }

const make = (id: string, name: string): Technique => ({ id, name, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` });

// The closest MITRE ATT&CK Enterprise technique for each attack. Null means no technique fits honestly.
const MAP: Record<string, Technique | null> = {
  'arp-spoof': make('T1557.002', 'ARP Cache Poisoning'),
  'rogue-dhcp-attack': make('T1557.003', 'DHCP Spoofing'),
  'dns-hijack': make('T1557', 'Adversary-in-the-Middle'),
  'port-scan': make('T1046', 'Network Service Discovery'),
  'syn-flood': make('T1498.001', 'Direct Network Flood'),
  'dns-tunnel': make('T1071.004', 'Application Layer Protocol: DNS'),
  'llmnr-poison': make('T1557.001', 'LLMNR/NBT-NS Poisoning and SMB Relay'),
  'parser-evasion': null,
  'dhcp-starvation': make('T1499', 'Endpoint Denial of Service'),
  'rst-injection': make('T1565.002', 'Transmitted Data Manipulation'),
  'icmp-redirect': make('T1557', 'Adversary-in-the-Middle'),
  'brute-force': make('T1110', 'Brute Force'),
  'mac-flood': make('T1557', 'Adversary-in-the-Middle'),
  'icmp-tunnel': make('T1095', 'Non-Application Layer Protocol'),
  'data-exfil': make('T1048', 'Exfiltration Over Alternative Protocol'),
  'udp-flood': make('T1498.001', 'Direct Network Flood'),
  reflection: make('T1498.002', 'Reflection Amplification'),
  slowloris: make('T1499.002', 'Service Exhaustion Flood'),
  'rogue-ra': make('T1557', 'Adversary-in-the-Middle'),
  'vlan-hopping': make('T1599', 'Network Boundary Bridging'),
  beaconing: make('T1071', 'Application Layer Protocol'),
  'dga-domain': make('T1568.002', 'Domain Generation Algorithms'),
};

/** Worked out from the hypothesis, so reports saved before this existed get labels too. */
export const techniqueOf = (hypothesis: string): Technique | null => MAP[hypothesis] ?? null;
export const mapped = (hypothesis: string) => hypothesis in MAP;
