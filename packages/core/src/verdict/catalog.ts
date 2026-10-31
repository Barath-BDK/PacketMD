export type Family = 'fault' | 'attack' | 'benign';

// prior is a log-odds head start: attacks start behind, so they have to earn the label.
export const HYPOTHESES: Record<string, { family: Family; title: string; prior: number }> = {
  benign: { family: 'benign', title: 'Normal behaviour', prior: 0.4 },
  'tcp-loss': { family: 'fault', title: 'Packet loss causing TCP retransmissions', prior: 0 },
  'tcp-reset': { family: 'fault', title: 'Connections being reset', prior: 0 },
  'syn-unanswered': { family: 'fault', title: 'Connection attempts getting no answer', prior: 0 },
  'zero-window': { family: 'fault', title: 'A receiver too busy to accept data', prior: 0 },
  'dns-failure': { family: 'fault', title: 'DNS lookups failing', prior: 0 },
  'duplicate-ip': { family: 'fault', title: 'Two devices using one IP address', prior: 0 },
  'mtu-blackhole': { family: 'fault', title: 'Large packets vanishing (MTU mismatch)', prior: 0 },
  'high-latency': { family: 'fault', title: 'Unusual delay', prior: 0 },
  'dhcp-failure': { family: 'fault', title: 'Devices cannot get an address', prior: 0 },
  'server-outage': { family: 'fault', title: 'A server stopped answering', prior: 0 },
  'rogue-dhcp-misconfig': { family: 'fault', title: 'A second DHCP server plugged in by mistake', prior: 0 },
  'arp-spoof': { family: 'attack', title: 'ARP spoofing', prior: -0.5 },
  'rogue-dhcp-attack': { family: 'attack', title: 'Rogue DHCP server attack', prior: -0.5 },
  'dns-hijack': { family: 'attack', title: 'DNS hijacking', prior: -0.5 },
  'port-scan': { family: 'attack', title: 'Port scan', prior: -0.5 },
  'syn-flood': { family: 'attack', title: 'SYN flood', prior: -0.5 },
  'dns-tunnel': { family: 'attack', title: 'DNS tunnelling', prior: -0.5 },
  'llmnr-poison': { family: 'attack', title: 'LLMNR / NBT-NS poisoning', prior: -0.5 },
  'parser-evasion': { family: 'attack', title: 'Crafted packets aimed at parsers', prior: -0.5 },
  beaconing: { family: 'attack', title: 'Machine-timed beaconing', prior: -0.5 },
  'dga-domain': { family: 'attack', title: 'Algorithm-generated domain lookups', prior: -0.5 },
};
