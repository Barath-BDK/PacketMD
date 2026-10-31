import { shellArg } from '../sanitize';
import type { FixStep } from '../types';
import type { Case } from '../verdict/engine';

type F = Record<string, string | number | string[]>;
const s = (v: unknown) => (Array.isArray(v) ? v.join(', ') : v === undefined || v === null ? '' : String(v));

export interface Tpl {
  plain(f: F): string; technical(f: F): string; analyst(f: F): string;
  cause(f: F): string; whyNot(f: F): string; analogy: string;
  filter(f: F): string; bpf(f: F): string;
  fix(f: F): FixStep[]; verify(f: F): string;
}

/** A step survives only if every value it needs came from the capture and is safe in a shell line. */
function step(need: unknown[], make: () => FixStep): FixStep[] {
  return need.every((v) => { const x = s(v); return x !== '' && x !== '0' && shellArg(x.replace(/, /g, ',').split(',')[0]!) !== null; }) ? [make()] : [];
}

const arpWatch = (f: F): FixStep[] => step([f.ip, f.macA], () => ({
  title: `Pin the real address of ${f.ip}`, why: 'A static entry stops forged replies from changing where traffic goes while you investigate.',
  windows: `netsh interface ipv4 add neighbors "Ethernet" ${f.ip} ${s(f.macA).replace(/:/g, '-')}`, linux: `sudo ip neigh replace ${f.ip} lladdr ${f.macA} nud permanent dev eth0`,
  router: `arp ${f.ip} ${f.macA} ARPA`,
}));

export const TEMPLATES: Record<string, Tpl> = {
  'arp-spoof': {
    plain: (f) => `A device is pretending to be ${f.ip}${f.isGateway ? ', your internet gateway' : ''}. Traffic meant for it may now pass through that impostor, who can read or change it.`,
    technical: (f) => `MAC ${f.macB}${f.attackerIp ? ` (also ${f.attackerIp})` : ''} is claiming ${f.ip}, which belongs to ${f.macA}, with ${f.unsolicited} unsolicited ARP replies and ${f.flips} binding flips.`,
    analyst: (f) => `ip=${f.ip} legit_mac=${f.macA} claimant_mac=${f.macB} claimant_ip=${f.attackerIp} unsolicited=${f.unsolicited} flips=${f.flips}`,
    cause: (f) => `The device at ${f.macB} is sending forged ARP replies, most likely a spoofing tool such as a man-in-the-middle kit.`,
    whyNot: (f) => `A duplicate IP is an accident: two devices share an address and answer when asked. Here ${f.macB} sent replies nobody requested${f.attackerIp ? ` while holding its own address ${f.attackerIp}` : ''}, which an accident does not do.`,
    analogy: 'Someone swapped the name tags on the mailboxes, so your post is delivered to their box first.',
    filter: (f) => `arp and arp.src.proto_ipv4 == ${f.ip}`, bpf: (f) => `arp and ether src ${f.macB}`,
    fix: (f) => [
      ...step([f.macB], () => ({ title: `Find and isolate ${f.macB}`, why: 'The switch knows which port this MAC is on. Shut that port and you remove the attacker.', windows: `arp -a | findstr ${s(f.macB).replace(/:/g, '-')}`, linux: `ip neigh | grep -i ${f.macB}`, router: `show mac address-table address ${f.macB}\ninterface <port-from-above>\n shutdown` })),
      ...arpWatch(f),
      ...step([f.ip], () => ({ title: 'Turn on Dynamic ARP Inspection', why: 'The switch then drops ARP replies that do not match its DHCP records.', router: `ip arp inspection vlan 1\nip dhcp snooping vlan 1\nip dhcp snooping` })),
    ],
    verify: (f) => `Capture again for two minutes. ${f.ip} should appear with only ${f.macA}.`,
  },
  'duplicate-ip': {
    plain: (f) => `Two devices are using the same address, ${f.ip}. They take turns losing their connection, which feels like random drops.`,
    technical: (f) => `${f.ip} is claimed by ${f.macA} and ${f.macB}, with ${f.flips} binding flips and no forged replies.`,
    analyst: (f) => `ip=${f.ip} mac_a=${f.macA} mac_b=${f.macB} flips=${f.flips}`,
    cause: () => 'One device likely has a fixed address inside the range the DHCP server hands out.',
    whyNot: (f) => `ARP spoofing would show a burst of unsolicited replies and a device that also owns another address. ${f.macB} shows neither.`,
    analogy: 'Two houses on one street were given the same number, so deliveries bounce between them.',
    filter: (f) => `arp.src.proto_ipv4 == ${f.ip}`, bpf: (f) => `arp host ${f.ip}`,
    fix: (f) => [
      ...step([f.ip, f.macB], () => ({ title: `Find which device has the fixed address`, why: 'One of the two must move.', windows: `arp -a ${f.ip}`, linux: `sudo arping -c 3 -D ${f.ip}`, router: `show ip arp ${f.ip}\nshow mac address-table address ${f.macB}` })),
      ...step([f.ip], () => ({ title: `Reserve or exclude ${f.ip} in DHCP`, why: 'The server then stops handing it to a second device.', router: `ip dhcp excluded-address ${f.ip}` })),
    ],
    verify: (f) => `Capture again. ${f.ip} should map to one MAC only.`,
  },
  'rogue-dhcp-attack': {
    plain: (f) => `A device at ${f.server} is posing as your network's address server. It tells computers to use ${f.dns || 'its own settings'}, which can send them to fake sites.`,
    technical: (f) => `DHCP server ${f.server} competes with ${f.legit}, offering router ${f.router} and DNS ${f.dns}. Its answers lead to altered DNS.`,
    analyst: (f) => `rogue_server=${f.server} rogue_mac=${f.serverMac} legit=${f.legit} router=${f.router} dns=${f.dns} clients=${s(f.clients)}`,
    cause: () => 'An attacker added a DHCP server to redirect the network to infrastructure they control.',
    whyNot: (f) => `A forgotten home router offers itself as gateway and leaves DNS alone. This one points clients at ${f.dns} and the answers afterwards are altered.`,
    analogy: 'An impostor at the front desk is handing out wrong directions to every visitor.',
    filter: (f) => `dhcp.option.dhcp_server_id == ${f.server}`, bpf: () => 'udp port 67 or udp port 68',
    fix: (f) => [
      ...step([f.serverMac], () => ({ title: `Disconnect ${f.server}`, why: 'Clients keep getting bad settings until it is off the network.', router: `show mac address-table address ${f.serverMac}\ninterface <port-from-above>\n shutdown`, linux: `ip neigh | grep -i ${f.serverMac}`, windows: `arp -a | findstr ${s(f.serverMac).replace(/:/g, '-')}` })),
      ...step([f.legit], () => ({ title: 'Allow DHCP only from the real server port', why: 'DHCP snooping drops offers from any other port.', router: `ip dhcp snooping\nip dhcp snooping vlan 1\ninterface <uplink-to-${f.legit}>\n ip dhcp snooping trust` })),
      { title: 'Renew every affected client', why: 'Leases from the rogue keep working until they are replaced.', windows: 'ipconfig /release && ipconfig /renew', linux: 'sudo dhclient -r && sudo dhclient' },
    ],
    verify: (f) => `Capture a client renewing. Only ${f.legit} should answer.`,
  },
  'rogue-dhcp-misconfig': {
    plain: (f) => `A second router at ${f.server} is handing out addresses. It looks like a device someone plugged in by mistake, not an attack, but it will break connections for anyone it answers.`,
    technical: (f) => `DHCP server ${f.server}${f.vendor ? ` (${f.vendor} hardware)` : ''} competes with ${f.legit}, offering itself as gateway and DNS in a private range. No DNS answers were altered.`,
    analyst: (f) => `second_server=${f.server} mac=${f.serverMac} vendor=${f.vendor} legit=${f.legit} router=${f.router} dns=${f.dns}`,
    cause: (f) => `Most likely a${f.vendor ? ` ${f.vendor}` : ''} router plugged in through a LAN port with its DHCP left on.`,
    whyNot: () => 'A malicious server points clients at foreign DNS and alters answers. This one uses factory-style settings and nothing was altered.',
    analogy: 'A helpful new employee started giving directions at the door. They mean well, but the directions are wrong.',
    filter: (f) => `dhcp.option.dhcp_server_id == ${f.server}`, bpf: () => 'udp port 67 or udp port 68',
    fix: (f) => [
      ...step([f.serverMac], () => ({ title: `Locate the device at ${f.server}`, why: 'Walk to the switch port and identify what was plugged in.', router: `show mac address-table address ${f.serverMac}`, linux: `ip neigh | grep -i ${f.serverMac}`, windows: `arp -a | findstr ${s(f.serverMac).replace(/:/g, '-')}` })),
      ...step([f.server], () => ({ title: 'Turn off its DHCP or unplug it', why: `Open http://${f.server} from a wired client and disable the DHCP server.` })),
      { title: 'Renew affected clients', why: 'Their leases point at the wrong gateway until renewed.', windows: 'ipconfig /release && ipconfig /renew', linux: 'sudo dhclient -r && sudo dhclient' },
    ],
    verify: (f) => `Capture a client renewing. Only ${f.legit} should answer.`,
  },
  'dns-hijack': {
    plain: (f) => `Someone is giving false directions for ${f.qname || 'websites'}. Instead of the real site, computers are sent to ${f.forged || 'a wrong address'}.`,
    technical: (f) => `Forged responses for ${f.qname}: answer ${f.forged}${f.real ? `, real answer ${f.real}` : ''}${f.forger ? `, sent by ${f.forger}` : ''}. Resolver asked was ${f.resolver}.`,
    analyst: (f) => `qname=${f.qname} forged=${f.forged} real=${f.real} forger=${f.forger} resolver=${f.resolver} victim=${f.victim}`,
    cause: (f) => `${f.forger ? `${f.forger} is racing` : 'Something on the path is racing'} the real resolver, or the resolver itself was tampered with.`,
    whyNot: () => 'A failing DNS server gives errors or silence. This one gives confident, wrong, or conflicting answers, which a fault cannot produce.',
    analogy: 'Someone slipped a forged page into the phone book, so you dial the wrong number with total confidence.',
    filter: (f) => `dns.qry.name == "${f.qname}"`, bpf: () => 'udp port 53',
    fix: (f) => [
      ...step([f.forged], () => ({ title: `Block ${f.forged} at the firewall`, why: 'Stops clients reaching the fake destination.', router: `access-list 110 deny ip any host ${f.forged}\naccess-list 110 permit ip any any`, linux: `sudo iptables -I FORWARD -d ${f.forged} -j DROP` })),
      ...step([f.victim], () => ({ title: `Flush the DNS cache on ${f.victim}`, why: 'Forged answers stay cached until their timer runs out.', windows: 'ipconfig /flushdns', linux: 'sudo resolvectl flush-caches' })),
      ...step([f.qname], () => ({ title: `Check ${f.qname} against a trusted resolver`, why: 'Compare with what your network returns.', windows: `nslookup ${f.qname} 9.9.9.9`, linux: `dig @9.9.9.9 ${f.qname}` })),
    ],
    verify: (f) => `Look up ${f.qname} again. Only ${f.resolver} should answer, with a public address.`,
  },
  'dns-failure': {
    plain: (f) => `Your computers cannot turn website names into addresses, so sites seem down even when the internet works. ${f.failed} of ${f.total} lookups to ${f.server} failed.`,
    technical: (f) => `Resolver ${f.server}: ${f.timeouts} timeouts, ${f.servfail} SERVFAIL or REFUSED, ${f.nxdomain} NXDOMAIN out of ${f.total} queries.`,
    analyst: (f) => `resolver=${f.server} total=${f.total} failed=${f.failed} timeout=${f.timeouts} servfail=${f.servfail} nxdomain=${f.nxdomain} sample=${f.sample}`,
    cause: (f) => Number(f.timeouts) > Number(f.servfail) ? `${f.server} is not reachable or not running.` : `${f.server} is up but cannot complete lookups, often because its upstream is unreachable.`,
    whyNot: () => 'Hijacking returns confident wrong answers. These are errors and silence, and no second answerer appears.',
    analogy: 'You keep calling directory enquiries and the line just rings out.',
    filter: (f) => `dns and ip.addr == ${f.server}`, bpf: (f) => `udp port 53 and host ${f.server}`,
    fix: (f) => [
      ...step([f.server, f.sample], () => ({ title: `Test ${f.server} directly`, why: 'Shows whether the server or the client is at fault.', windows: `nslookup ${f.sample} ${f.server}`, linux: `dig @${f.server} ${f.sample}` })),
      ...step([f.server], () => ({ title: 'Check the resolver is running', why: 'A stopped service gives exactly this pattern.', linux: `ping -c 3 ${f.server}\nsudo systemctl status named`, windows: `ping ${f.server}\nGet-Service DNS` })),
      { title: 'Point clients at a backup resolver', why: 'Keeps people working while you repair the server.', windows: 'netsh interface ip set dns "Ethernet" static 9.9.9.9', linux: 'sudo resolvectl dns eth0 9.9.9.9' },
    ],
    verify: (f) => `Capture lookups again. Failures to ${f.server} should fall below 5%.`,
  },
  'tcp-loss': {
    plain: (f) => `Data between ${f.a} and ${f.b} keeps getting lost and sent again. Things feel slow or stutter. About ${f.rate}% of packets had to be repeated.`,
    technical: (f) => `${f.count} retransmissions on ${f.a} to ${f.b}:${f.port}: ${f.fast} fast, ${f.rto} after a timeout.`,
    analyst: (f) => `a=${f.a} b=${f.b} port=${f.port} retrans=${f.count} rate=${f.rate}% fast=${f.fast} rto=${f.rto}`,
    cause: () => 'Congestion or a bad link is dropping packets somewhere between these two hosts.',
    whyNot: () => 'Attack traffic does not back off. These repeats follow TCP\'s own recovery rules, which means real software meeting a real problem.',
    analogy: 'Repeating a sentence on a bad phone line because the other person missed it.',
    filter: (f) => `tcp.analysis.retransmission and ip.addr == ${f.a} and ip.addr == ${f.b}`, bpf: (f) => `tcp and host ${f.a} and host ${f.b}`,
    fix: (f) => [
      ...step([f.b], () => ({ title: `Measure the path to ${f.b}`, why: 'Shows where loss starts.', windows: `pathping ${f.b}`, linux: `mtr -rwc 100 ${f.b}` })),
      { title: 'Check link errors on the switch and NIC', why: 'A bad cable or duplex mismatch produces this pattern.', router: 'show interfaces counters errors', linux: 'ip -s link show eth0', windows: 'Get-NetAdapterStatistics' },
    ],
    verify: (f) => `Capture the same transfer. Repeats between ${f.a} and ${f.b} should fall below ${1}%.`,
  },
  'tcp-reset': {
    plain: (f) => `${f.count} connections to ${f.server} on port ${f.port} were slammed shut. Apps show "connection refused" or sudden disconnects.`,
    technical: (f) => `${f.early} resets at connection start, ${f.mid} mid-stream, service ${f.server}:${f.port}.`,
    analyst: (f) => `server=${f.server} port=${f.port} rst=${f.count} early=${f.early} mid=${f.mid} clients=${s(f.clients)}`,
    cause: (f) => Number(f.early) >= Number(f.mid) ? `Nothing is listening on port ${f.port}, or a firewall rejects it.` : 'The application or a middlebox is ending sessions early.',
    whyNot: () => 'A scan touches many ports from one source. These resets concentrate on one service from normal clients.',
    analogy: 'Knocking on a shop door and being told "closed" before you finish your sentence.',
    filter: (f) => `tcp.flags.reset == 1 and ip.addr == ${f.server}`, bpf: (f) => `tcp[tcpflags] & tcp-rst != 0 and host ${f.server}`,
    fix: (f) => step([f.server, f.port], () => ({ title: `Check the service on ${f.server} port ${f.port}`, why: 'Confirms whether it is listening.', windows: `Test-NetConnection ${f.server} -Port ${f.port}`, linux: `nc -vz ${f.server} ${f.port}\nsudo ss -ltnp | grep :${f.port}` })),
    verify: (f) => `Connect to ${f.server}:${f.port} while capturing. The handshake should finish with no reset.`,
  },
  'syn-unanswered': {
    plain: (f) => `Computers tried to reach ${f.server} on port ${f.port} ${f.attempts} times and heard nothing back. A firewall or wrong address is the likely reason.`,
    technical: (f) => `${f.attempts} SYNs to ${f.server}:${f.port} from ${f.sources} sources with no SYN-ACK or RST.`,
    analyst: (f) => `server=${f.server} port=${f.port} syn=${f.attempts} sources=${f.sources}`,
    cause: () => 'A silent drop on the path: firewall rule, wrong route, or a host that is off.',
    whyNot: () => 'A flood comes from many sources at machine speed. These are a few clients retrying politely.',
    analogy: 'Posting letters to an address that never writes back or returns them.',
    filter: (f) => `tcp.flags.syn == 1 and ip.dst == ${f.server}`, bpf: (f) => `tcp and dst host ${f.server} and dst port ${f.port}`,
    fix: (f) => step([f.server, f.port], () => ({ title: `Trace the path to ${f.server}:${f.port}`, why: 'Finds the last hop that responds.', windows: `tracert ${f.server}\nTest-NetConnection ${f.server} -Port ${f.port}`, linux: `traceroute -T -p ${f.port} ${f.server}` })),
    verify: (f) => `Capture a new attempt. ${f.server} should answer with SYN-ACK.`,
  },
  'server-outage': {
    plain: (f) => `The server at ${f.server} stopped answering on port ${f.port}. Normal computers keep trying and giving up. This looks like a crash, not an attack.`,
    technical: (f) => `${f.attempts} unanswered SYNs from ${f.sources} clients with exponential backoff; connections to this service worked earlier.`,
    analyst: (f) => `server=${f.server} port=${f.port} syn=${f.attempts} sources=${s(f.sourceList)}`,
    cause: (f) => `The service on ${f.server} crashed, or the host went down.`,
    whyNot: () => 'A SYN flood uses many sources at high speed and gets answers it ignores. Here a few known clients back off the way real software does, and the server answers nothing.',
    analogy: 'The shop closed without notice and the regulars keep trying the door.',
    filter: (f) => `ip.addr == ${f.server} and tcp.port == ${f.port}`, bpf: (f) => `host ${f.server} and tcp port ${f.port}`,
    fix: (f) => step([f.server, f.port], () => ({ title: `Check ${f.server} directly`, why: 'Confirms host versus service.', windows: `ping ${f.server}\nTest-NetConnection ${f.server} -Port ${f.port}`, linux: `ping -c 3 ${f.server}\nnc -vz ${f.server} ${f.port}` })),
    verify: (f) => `Capture a client connecting. ${f.server} should answer the SYN.`,
  },
  'syn-flood': {
    plain: (f) => `${f.server} is being flooded with fake connection requests from ${f.sources} sources, so real visitors cannot get in.`,
    technical: (f) => `${f.attempts} half-open attempts at ${f.server}:${f.port} from ${f.sources} sources.`,
    analyst: (f) => `target=${f.server} port=${f.port} syn=${f.attempts} sources=${f.sources}`,
    cause: () => 'Someone is deliberately exhausting the server\'s pending-connection queue.',
    whyNot: () => 'A failed server stays silent and real clients back off. Here the attempts come at machine speed from many addresses and never finish the handshake.',
    analogy: 'A crowd rings the doorbell and runs away, over and over, so the owner never reaches a real visitor.',
    filter: (f) => `tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == ${f.server}`, bpf: (f) => `tcp[tcpflags] & tcp-syn != 0 and dst host ${f.server}`,
    fix: (f) => [
      ...step([f.server], () => ({ title: `Turn on SYN cookies on ${f.server}`, why: 'The server stops reserving memory for half-open connections.', linux: 'sudo sysctl -w net.ipv4.tcp_syncookies=1' })),
      ...step([f.port], () => ({ title: 'Rate-limit SYNs at the edge', why: 'Sheds the flood before it reaches the server.', linux: `sudo iptables -A INPUT -p tcp --dport ${f.port} --syn -m limit --limit 50/s -j ACCEPT`, router: `ip tcp intercept mode watch` })),
    ],
    verify: (f) => `Capture during peak. Half-open attempts at ${f.server} should stop growing.`,
  },
  'port-scan': {
    plain: (f) => `${f.source} is trying door after door on ${f.target}, looking for a way in. Nothing has been broken yet, but this is usually the first step of an attack.`,
    technical: (f) => `${f.mode} scan from ${f.source}: ${f.ports} ports, ${f.hosts} hosts. Open ports found: ${s(f.open) || 'none'}.`,
    analyst: (f) => `src=${f.source} target=${f.target} mode=${f.mode} ports=${f.ports} hosts=${f.hosts} open=${s(f.open)}`,
    cause: (f) => `A scanning tool is running on ${f.source}, by an intruder, or by a staff member nobody told you about.`,
    whyNot: () => 'A broken app retries a few ports. This one touches many in a tight burst and almost never finishes a handshake.',
    analogy: 'Someone walks down a corridor trying every door handle.',
    filter: (f) => `ip.src == ${f.source} and tcp.flags.syn == 1`, bpf: (f) => `src host ${f.source} and tcp[tcpflags] & tcp-syn != 0`,
    fix: (f) => [
      ...step([f.source], () => ({ title: `Block ${f.source}`, why: 'Stops further probing while you find out who owns it.', linux: `sudo iptables -I INPUT -s ${f.source} -j DROP`, windows: `New-NetFirewallRule -DisplayName "Block scanner" -Direction Inbound -RemoteAddress ${f.source} -Action Block`, router: `access-list 110 deny ip host ${f.source} any` })),
      ...step([f.targetIp, f.open], () => ({ title: `Close what the scan found on ${f.targetIp}`, why: `Ports ${s(f.open)} answered.`, linux: `sudo ss -ltnp` })),
    ],
    verify: (f) => `Capture for ten minutes. ${f.source} should make no new connection attempts.`,
  },
  'mtu-blackhole': {
    plain: (f) => `Big packets from ${f.host} are too large for part of the path and they silently vanish. Small things work, but large downloads and uploads hang.`,
    technical: (f) => `${f.size}-byte DF packets to ${f.peer}${f.nextMtu ? `; router ${f.router} reports next-hop MTU ${f.nextMtu}` : ' are lost with no ICMP warning'}.`,
    analyst: (f) => `host=${f.host} peer=${f.peer} size=${f.size} next_mtu=${f.nextMtu} router=${f.router} mss=${f.mss}`,
    cause: () => 'A link on the path, often a VPN or tunnel, has a smaller MTU than the sender expects.',
    whyNot: () => 'Random loss hits packets of every size. Here only full-size packets disappear, while small ones on the same connection work.',
    analogy: 'A parcel too big for a doorway, and nobody tells the courier, who keeps bringing it back.',
    filter: (f) => `icmp.type == 3 and icmp.code == 4 or (ip.src == ${f.host} and ip.flags.df == 1 and frame.len > 1400)`, bpf: (f) => `(icmp[0] == 3 and icmp[1] == 4) or (host ${f.host} and greater 1400)`,
    fix: (f) => [
      ...step([f.peer, f.suggest], () => ({ title: `Find the real path MTU to ${f.peer}`, why: 'Sends do-not-fragment probes to find the largest size that gets through.', windows: `ping ${f.peer} -f -l ${f.suggest}`, linux: `ping -M do -s ${f.suggest} ${f.peer}` })),
      ...step([f.suggest], () => ({ title: `Clamp TCP segment size to ${f.suggest}`, why: 'Hosts then never send a packet the path cannot carry.', linux: `sudo iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${f.suggest}`, router: `interface tunnel0\n ip tcp adjust-mss ${f.suggest}`, windows: `netsh interface ipv4 set subinterface "Ethernet" mtu=${Number(f.suggest) + 40} store=persistent` })),
      { title: 'Allow ICMP type 3 code 4 through firewalls', why: 'Blocking it is what turns a small MTU into a black hole.', linux: 'sudo iptables -I INPUT -p icmp --icmp-type fragmentation-needed -j ACCEPT' },
    ],
    verify: (f) => `Repeat the large transfer to ${f.peer}. No full-size packet should be resent.`,
  },
  'high-latency': {
    plain: (f) => `Some connections are taking far longer than normal to answer: up to ${f.slowMs} ms when ${f.typicalMs} ms is typical here.`,
    technical: (f) => `${f.count} handshake RTT outliers by median/MAD; worst ${f.a} to ${f.b}:${f.port} at ${f.slowMs} ms.`,
    analyst: (f) => `worst=${f.slowMs}ms median=${f.typicalMs}ms outliers=${f.count} flow=${f.a}->${f.b}:${f.port}`,
    cause: () => 'A congested link, overloaded server, or long route on this path.',
    whyNot: () => 'Delay alone has no attack signature here: identities, answers and handshakes are all consistent.',
    analogy: 'A queue at one till while every other till is empty.',
    filter: (f) => `ip.addr == ${f.b} and tcp.flags.syn == 1`, bpf: (f) => `host ${f.b} and tcp[tcpflags] & tcp-syn != 0`,
    fix: (f) => step([f.b], () => ({ title: `Trace the delay to ${f.b}`, why: 'Shows which hop adds the time.', windows: `pathping ${f.b}`, linux: `mtr -rwc 50 ${f.b}` })),
    verify: (f) => `Capture again. Handshakes to ${f.b} should be near ${f.typicalMs} ms.`,
  },
  'dhcp-failure': {
    plain: (f) => `Device ${f.mac} asked for a network address ${f.tries} times and got nowhere, so it cannot get online.`,
    technical: (f) => `${f.tries} DHCP attempts from ${f.mac} without an OFFER, or with NAK replies.`,
    analyst: (f) => `client_mac=${f.mac} tries=${f.tries}`,
    cause: () => 'The DHCP server is down, unreachable from this VLAN, or out of addresses.',
    whyNot: () => 'A rogue server would answer. Here nobody answers at all.',
    analogy: 'Waiting at reception for a visitor badge, and nobody is at the desk.',
    filter: () => 'dhcp', bpf: () => 'udp port 67 or udp port 68',
    fix: () => [{ title: 'Check the DHCP scope and service', why: 'Exhausted pools and stopped services give this pattern.', router: 'show ip dhcp pool\nshow ip dhcp binding', linux: 'sudo systemctl status isc-dhcp-server', windows: 'Get-DhcpServerv4ScopeStatistics' }],
    verify: () => 'Capture the client joining. It should complete DISCOVER, OFFER, REQUEST, ACK.',
  },
  'zero-window': {
    plain: (f) => `${f.host} is receiving data faster than it can handle and keeps telling ${f.peer} to wait. Transfers stall.`,
    technical: (f) => `${f.count} zero-window advertisements from ${f.host}.`,
    analyst: (f) => `host=${f.host} peer=${f.peer} port=${f.port} zero_windows=${f.count}`,
    cause: (f) => `The application on ${f.host} is not reading fast enough: CPU, disk or memory pressure.`,
    whyNot: () => 'The receiver asks for the pause itself, so the network is doing its job.',
    analogy: 'An inbox tray that is full, so the post waits outside.',
    filter: (f) => `tcp.analysis.zero_window and ip.src == ${f.host}`, bpf: (f) => `tcp and src host ${f.host} and tcp[14:2] = 0`,
    fix: (f) => step([f.host], () => ({ title: `Check load on ${f.host}`, why: 'Find what is starving the receiving app.', linux: 'top -bn1 | head -15\niostat -x 1 3', windows: 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 10' })),
    verify: (f) => `Capture again. ${f.host} should not advertise a zero window.`,
  },
  'llmnr-poison': {
    plain: (f) => `${f.source} is answering "that's me" for names it does not own. Computers then send it their login details.`,
    technical: (f) => `${f.source} answered LLMNR/NBT-NS for: ${s(f.names)}. Victims: ${s(f.victims)}.`,
    analyst: (f) => `responder=${f.source} mac=${f.mac} names=${s(f.names)} victims=${s(f.victims)}`,
    cause: () => 'A poisoning tool such as Responder is running on the network.',
    whyNot: () => 'A real device answers only for its own name. This one answers for every name it hears.',
    analogy: 'Someone in a crowd answers to every name called, then asks for your ID.',
    filter: () => 'llmnr or nbns', bpf: () => 'udp port 5355 or udp port 137',
    fix: (f) => [
      ...step([f.source], () => ({ title: `Isolate ${f.source}`, why: 'Stops credential capture.', linux: `sudo iptables -I FORWARD -s ${f.source} -j DROP`, router: `access-list 110 deny ip host ${f.source} any` })),
      { title: 'Turn off LLMNR and NetBIOS name service', why: 'Removes the broadcast lookups this attack depends on.', windows: 'Set-ItemProperty "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" EnableMulticast 0' },
      ...step([f.victims], () => ({ title: 'Reset passwords used by the victims', why: `${s(f.victims)} may have sent password hashes.` })),
    ],
    verify: () => 'Capture for ten minutes. No host should answer LLMNR for names it does not own.',
  },
  'dns-tunnel': {
    plain: (f) => `${f.host} is hiding data inside website lookups for ${f.domain}, about ${f.bytes} bytes so far. This is a known way to sneak data past firewalls.`,
    technical: (f) => `${f.count} high-entropy queries under ${f.domain} from ${f.host} via ${f.resolver}.`,
    analyst: (f) => `host=${f.host} domain=${f.domain} queries=${f.count} bytes=${f.bytes}`,
    cause: () => 'A tunnelling tool or malware is using DNS as a covert channel.',
    whyNot: () => 'Normal names are short and readable. These are long and random-looking with no benign pattern.',
    analogy: 'Passing secret notes hidden inside ordinary-looking address labels.',
    filter: (f) => `dns.qry.name contains "${f.domain}"`, bpf: () => 'udp port 53',
    fix: (f) => [
      ...step([f.domain], () => ({ title: `Block ${f.domain} at your resolver`, why: 'Cuts the channel.', linux: `echo "local-zone: \\"${f.domain}\\" refuse" | sudo tee -a /etc/unbound/unbound.conf` })),
      ...step([f.host], () => ({ title: `Investigate ${f.host}`, why: 'Something on it is running the tunnel.', linux: 'sudo ss -tunap', windows: 'Get-NetUDPEndpoint | Sort-Object OwningProcess' })),
    ],
    verify: (f) => `Capture again. No lookups under ${f.domain} should appear.`,
  },
  beaconing: {
    plain: (f) => `${f.host} contacts ${f.domain || f.peer} every ${f.every} seconds like clockwork. Malware checks in with its controller this way.`,
    technical: (f) => `${f.count} connections to ${f.peer}:${f.port} at ${f.every}s intervals with very low jitter.`,
    analyst: (f) => `host=${f.host} peer=${f.peer} port=${f.port} interval=${f.every}s count=${f.count} domain=${f.domain}`,
    cause: () => 'An automated client, possibly malware, is polling a remote server.',
    whyNot: () => 'People browse irregularly, and common update services are on the allowlist. This is neither.',
    analogy: 'A guard who signals out of the window at exactly the same second every hour.',
    filter: (f) => `ip.addr == ${f.peer} and tcp.port == ${f.port}`, bpf: (f) => `host ${f.peer} and tcp port ${f.port}`,
    fix: (f) => [
      ...step([f.peer], () => ({ title: `Block ${f.peer}`, why: 'Cuts the check-in while you investigate.', linux: `sudo iptables -I FORWARD -d ${f.peer} -j DROP`, router: `access-list 110 deny ip any host ${f.peer}` })),
      ...step([f.peer, f.host], () => ({ title: `Find the process on ${f.host}`, why: 'A capture cannot name it, the host can.', windows: `Get-NetTCPConnection -RemoteAddress ${f.peer}`, linux: `sudo ss -tnp dst ${f.peer}` })),
    ],
    verify: (f) => `Capture for several intervals. ${f.host} should stop contacting ${f.peer}.`,
  },
  'dga-domain': {
    plain: (f) => `${f.host} looked up ${f.count} random-looking website names such as ${f.sample}. Malware uses names like these to find its controller.`,
    technical: (f) => `${f.count} high-entropy, low-vowel names from ${f.host}.`,
    analyst: (f) => `host=${f.host} unique_names=${f.count} sample=${f.sample}`,
    cause: () => 'Software generating domain names by algorithm, a common malware trait.',
    whyNot: () => 'Mistyped names look like words. These look like noise and come in bulk.',
    analogy: 'Someone trying hundreds of made-up phone numbers, hoping one is the contact.',
    filter: (f) => `dns and ip.src == ${f.host}`, bpf: (f) => `udp port 53 and src host ${f.host}`,
    fix: (f) => step([f.host], () => ({ title: `Scan and isolate ${f.host}`, why: 'Treat it as infected until shown otherwise.', windows: 'Start-MpScan -ScanType FullScan', linux: 'sudo clamscan -r /home' })),
    verify: (f) => `Capture again. ${f.host} should not produce random-looking lookups.`,
  },
  'parser-evasion': {
    plain: (f) => `This capture has ${f.count} packets built to confuse analysis tools. PacketMD refused to be fooled and counted them.`,
    technical: (f) => `Malformed structures: ${s(f.kinds)}.`,
    analyst: (f) => `malformed=${f.count} kinds=${s(f.kinds)} first_source=${f.host}`,
    cause: () => 'Crafted traffic, or a damaged capture file, designed to slip past or crash parsers.',
    whyNot: () => 'Normal network stacks do not produce these field combinations.',
    analogy: 'A package with a false bottom, meant to fool the scanner at the door.',
    filter: () => 'malformed or _ws.expert', bpf: () => 'ip',
    fix: (f) => step([f.host], () => ({ title: `Investigate ${f.host}`, why: 'Crafted packets need a deliberate sender.', linux: `sudo iptables -I FORWARD -s ${f.host} -j LOG --log-prefix "packetmd "` })),
    verify: () => 'Capture again. The malformed count should be zero.',
  },
  benign: {
    plain: (f) => `${f.benignKind ? `This is ${s(f.benignKind).toLowerCase()}. ` : ''}It looks odd at first, but the evidence points to normal behaviour and no action is needed.`,
    technical: (f) => `Benign explanation matched${f.benignKind ? `: ${f.benignKind}` : ''}.`,
    analyst: (f) => `benign=${f.benignKind ?? 'pattern'} hosts=${s(f.ip ?? f.server ?? f.source)}`,
    cause: () => 'Routine network behaviour.',
    whyNot: () => 'The attack explanation needs signals that a benign check ruled out.',
    analogy: 'A fire drill: the alarm sounded, and everyone knew it was planned.',
    filter: () => '', bpf: () => '',
    fix: () => [],
    verify: () => 'Nothing to verify.',
  },
};

export function nextCapture(c: Case): string {
  const h = c.hosts[0] ?? 'the affected host';
  if (c.topic === 'identity') return `Capture ARP on the gateway port for 60 seconds while the problem recurs, and save a baseline from a known-good day. Focus on ${h}.`;
  if (c.topic === 'dhcp') return `Capture a client doing a full renew on the same switch as ${h}.`;
  if (c.topic === 'reachability') return `Capture on the server side of ${h} for 60 seconds to see whether SYNs arrive at all.`;
  return `Capture for 60 seconds closer to ${h}, while the problem is happening.`;
}
