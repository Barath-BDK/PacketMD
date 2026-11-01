// The contract between engine, Worker and UI. Bump on any shape change: the UI refuses a mismatched Worker.
export const ENGINE_SCHEMA = 1;

export type Lane = 'FAULT' | 'ATTACK' | 'BENIGN' | 'INCONCLUSIVE';
export type Level = 'beginner' | 'technical' | 'analyst';

export interface ByteSource {
  size: number;
  read(offset: number, length: number): Promise<Uint8Array>;
}

export interface RawPacket {
  no: number;           // 1-based
  ts: number;           // seconds since epoch
  capLen: number;
  origLen: number;
  linkType: number;
  recordOffset: number; // file offset of the pcap record or pcapng block
  dataOffset: number;   // file offset of packet byte 0
  blockType?: string;   // pcapng only
  data: Uint8Array;
}

export interface Arp { op: number; sha: string; spa: string; tha: string; tpa: string }
export interface Icmp { type: number; code: number; nextMtu?: number; innerSrc?: string; innerDst?: string; innerProto?: number; tail?: string }
export interface Tcp {
  sport: number; dport: number; seq: number; ack: number; flags: number;
  win: number; mss?: number; payload: number; dataStart: number;
}
export interface Udp { sport: number; dport: number; len: number; dataStart: number }
export interface DnsAnswer { name: string; type: number; ttl: number; data: string }
export interface Dns {
  id: number; qr: boolean; rcode: number; qname: string; qtype: number; aa: boolean;
  answers: DnsAnswer[]; kind: 'dns' | 'mdns' | 'llmnr' | 'nbns';
}
export interface Dhcp {
  op: number; xid: number; msgType: number; chaddr: string; yiaddr: string; giaddr: string;
  server?: string; router?: string; dns: string[]; hostname?: string; mask?: string; lease?: number; requested?: string;
}
export interface Tls { sni?: string; ja3?: string; ech?: boolean; version: number }
export interface Http { method: string; path: string; host?: string; ua?: string }

export interface Pkt {
  no: number; ts: number; len: number; capLen: number; recordOffset: number; dataOffset: number; blockType?: string;
  srcMac?: string; dstMac?: string; vlan?: number; vlanDepth?: number; icmp6?: number;
  arp?: Arp;
  ipv?: 4 | 6; src?: string; dst?: string; ttl?: number; ipProto?: number; df?: boolean; mf?: boolean; fragOff?: number; ipId?: number; ipLen?: number;
  icmp?: Icmp; tcp?: Tcp; udp?: Udp; dns?: Dns; dhcp?: Dhcp; tls?: Tls; http?: Http;
  ntp?: boolean;
  proto: string;
  info: string;
  anomalies?: string[];
  flags?: string[]; // expert flags: retransmit, dupack, rst, zerowin
}

export interface TreeNode { label: string; start?: number; len?: number; children?: TreeNode[] }

export interface Signal {
  id: string;
  label: string;                   // plain sentence
  weights: Record<string, number>; // hypothesis id to log-likelihood-ratio weight
  packets: number[];
}

export interface BenignCheck { id: string; label: string; matched: boolean; packets: number[] }

export interface Candidate {
  detector: string;
  topic: string;     // only candidates about the same question compete in one case
  hypotheses: string[];
  hosts: string[];
  t0: number; t1: number;
  evidence: number[];
  signals: Signal[];
  benign?: BenignCheck[];
  facts: Record<string, string | number | string[]>;
}

export interface Hypothesis { id: string; family: 'fault' | 'attack' | 'benign'; title: string; prob: number; score: number }

export interface Evidence {
  no: number; ts: number; proto: string; info: string; recordOffset: number; dataOffset: number; capLen: number; blockType?: string;
}

export interface FixStep { title: string; why: string; windows?: string; linux?: string; router?: string }
export interface StoryStep { key: string; title: string; caption: string; technical: string; analyst: string; packets: number[]; t?: number; edges: { from: string; to: string; label: string; bad?: boolean }[] }

export interface LevelText { what: string; why: string; rule: string; sure: string; fields?: string }

export interface Finding {
  id: string;           // F1, F2... stable within a report
  fingerprint: string;  // stable across captures, used by Verify Fix
  lane: Lane;
  hypothesis: string;
  title: string;
  confidence: 'low' | 'medium' | 'high';
  margin: number;
  hypotheses: Hypothesis[];
  signals: Signal[];
  benign: BenignCheck[];
  hosts: string[];
  blast: string[];
  t0: number; t1: number;
  plain: string; technical: string; analyst: string;
  levels: Record<Level, LevelText>;
  cause: string; whyNotTheOther: string; analogy: string;
  wireshark: string; bpf: string;
  fixSteps: FixStep[]; verifyBy: string;
  nextCapture?: string;
  evidence: Evidence[];
  story: StoryStep[];
  causedBy?: string[]; // finding ids
  priority: number;
}

export interface HostRow { ip: string; macs: string[]; names: string[]; pkts: number; bytesOut: number; bytesIn: number; role: string; firstSeen: number; lastSeen: number }
export interface ConvRow { id: string; proto: string; a: string; b: string; aPort: number; bPort: number; pkts: number; bytes: number; t0: number; t1: number; state: string; domain?: string; domainSource?: string; domainPacket?: number }
export interface ActivityRow {
  domain: string; source: string; sourcePacket: number; klass: string; basis: string[];
  bytesIn: number; bytesOut: number; first: number; last: number; requests: number; protocol: string;
  health: number; rating: 'Clean-looking' | 'Unknown' | 'Suspicious' | 'Likely malicious'; reasons: string[]; conv: string[];
}
export interface DefenseReport {
  fileName: string; size: number; sha256: string; format: string; linkTypes: number[];
  packets: number; skipped: number; anomalies: Record<string, number>; truncated: boolean; unsupportedLink: boolean;
  parseMs: number; checks: { label: string; ok: boolean; detail: string }[];
}
export interface Baseline { gateways: Record<string, string>; dhcpServers: string[]; resolvers: string[]; ipMac: Record<string, string> }

export interface Report {
  schema: number;
  defense: DefenseReport;
  headline: string;
  findings: Finding[];
  hosts: HostRow[];
  conversations: ConvRow[];
  activity: ActivityRow[];
  protocols: { name: string; pkts: number; bytes: number }[];
  timeline: { t: number; pkts: number; bytes: number; bad: number }[];
  t0: number; t1: number;
  baseline: Baseline;
  rows: PacketRow[];
}

// Flat row for the packet list, sent to the UI in place of raw bytes.
export interface PacketRow {
  no: number; ts: number; src: string; dst: string; proto: string; len: number; info: string; capLen: number;
  recordOffset: number; dataOffset: number; blockType?: string; flags?: string[]; sport?: number; dport?: number;
  srcMac?: string; dstMac?: string; linkType: number; domain?: string; qname?: string;
}
