"""Captures built to slip past the detectors, plus clean look-alikes that must stay quiet. Written to labgen/evasion/."""
import json, pathlib, random
from scapy.all import ARP, DNS, DNSQR, DNSRR, Dot1Q, ICMP, IP, IPv6, TCP, UDP, Ether, Raw, wrpcap
import generate as g
from generate import A_IP, A_MAC, B_IP, B_MAC, BCAST, C_IP, C_MAC, DNS_IP, EVIL_IP, EVIL_MAC, GW_IP, GW_MAC, WEB, T, eth, ip_pkt, normal, tcp_session, dns_q, dns_r, dhcp_flow, tls_hello

OUT = pathlib.Path(__file__).resolve().parent / "evasion"
OUT.mkdir(exist_ok=True)
random.seed(4242)
cases = []


def save(name, pkts, must=None, why=""):
    """must lists hypotheses of which one has to be raised. None means a clean look-alike that must raise nothing."""
    wrpcap(str(OUT / f"{name}.pcap"), sorted(pkts, key=lambda p: float(p.time)))
    cases.append({"file": name, "must": must, "why": why})


def forged(c, n, gap=0.5):
    p = []
    for _ in range(n):
        p.append(c.at(eth(EVIL_MAC, A_MAC) / ARP(op=2, hwsrc=EVIL_MAC, psrc=GW_IP, hwdst=A_MAC, pdst=A_IP), gap))
    return p


# --- identity ---
c = T(); p = normal(c, 2) + forged(c, 2) + tcp_session(c, A_MAC, A_IP, EVIL_MAC, WEB, 443, n=6, payload=tls_hello("www.example.com"))
save("arp-low-rate", p, ["arp-spoof"], "Only two forged replies, just under the burst threshold")

c = T(); p = normal(c, 2)
for _ in range(10):
    p.append(c.at(eth(EVIL_MAC, A_MAC) / ARP(op=2, hwsrc=EVIL_MAC, psrc=B_IP, hwdst=A_MAC, pdst=A_IP), 0.4))
    p.append(c.at(eth(B_MAC, A_MAC) / ARP(op=2, hwsrc=B_MAC, psrc=B_IP, hwdst=A_MAC, pdst=A_IP), 0.1))
save("arp-spoof-peer", p, ["arp-spoof"], "Targets a workstation, not the gateway")

c = T(); p = normal(c, 2)
p.append(c.at(eth(EVIL_MAC, BCAST) / ARP(op=1, hwsrc=EVIL_MAC, psrc=GW_IP, pdst=GW_IP), 1))
p.append(c.at(eth(EVIL_MAC, BCAST) / ARP(op=1, hwsrc=EVIL_MAC, psrc=GW_IP, pdst=GW_IP), 0.2))
p += tcp_session(c, A_MAC, A_IP, GW_MAC, WEB, 443, n=6, payload=tls_hello("www.example.com"))
save("arp-fake-failover", p, ["arp-spoof"], "Announces once like a failover, but the real gateway is still forwarding traffic")

c = T(); p = normal(c, 1)
for _ in range(10):
    p.append(c.at(Ether(src=EVIL_MAC, dst=A_MAC) / Dot1Q(vlan=20) / ARP(op=2, hwsrc=EVIL_MAC, psrc=GW_IP, hwdst=A_MAC, pdst=A_IP), 0.3))
p.append(c.at(Ether(src=EVIL_MAC, dst=BCAST) / Dot1Q(vlan=20) / ARP(op=1, hwsrc=EVIL_MAC, psrc=EVIL_IP, pdst=GW_IP), 0.1))
save("arp-vlan-tagged", p, ["arp-spoof"], "Same spoof inside VLAN tags")

# --- scans ---
ua = b"GET / HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0 (compatible; Nessus SOAP)\r\n\r\n"
c = T(); p = normal(c, 1) + tcp_session(c, EVIL_MAC, EVIL_IP, A_MAC, A_IP, 80, n=1, size=100, payload=ua)
for port in range(1000, 1200):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=40000 + port, dport=port, flags="S"), 0.002))
    p.append(c.at(ip_pkt(A_MAC, EVIL_MAC, A_IP, EVIL_IP) / TCP(sport=port, dport=40000 + port, flags="RA"), 0.001))
save("scan-fake-scanner-name", p, ["port-scan"], "SYN scan that claims to be Nessus in one HTTP request")

c = T(); p = normal(c, 1)
for i, port in enumerate(range(20, 44)):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=41000 + i, dport=port, flags="S"), 25))
save("scan-slow", p, ["port-scan"], "One probe every 25 seconds")

c = T(); p = normal(c, 1)
for i, port in enumerate(random.sample(range(1, 1024), 12)):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=42000 + i, dport=port, flags="S"), 0.05))
    p.append(c.at(ip_pkt(A_MAC, EVIL_MAC, A_IP, EVIL_IP) / TCP(sport=port, dport=42000 + i, flags="RA"), 0.001))
save("scan-just-under", p, ["port-scan"], "Twelve ports, just below the fifteen-port threshold")

for name, flags in [("fin", "F"), ("null", ""), ("xmas", "FPU")]:
    c = T(); p = normal(c, 1)
    for port in range(20, 80):
        p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=43000 + port, dport=port, flags=flags), 0.004))
        p.append(c.at(ip_pkt(A_MAC, EVIL_MAC, A_IP, EVIL_IP) / TCP(sport=port, dport=43000 + port, flags="RA"), 0.001))
    save(f"scan-{name}", p, ["port-scan"], f"Stealth {name.upper()} scan, sends no SYN at all")

c = T(); p = normal(c, 1)
for port in range(100, 160):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / UDP(sport=44000, dport=port) / Raw(b"x"), 0.01))
    inner = bytes(IP(src=EVIL_IP, dst=A_IP, proto=17, len=29))[:20] + b"\0" * 8
    p.append(c.at(ip_pkt(A_MAC, EVIL_MAC, A_IP, EVIL_IP) / ICMP(type=3, code=3) / Raw(inner), 0.001))
save("scan-udp", p, ["port-scan"], "UDP port scan")

c = T(); p = normal(c, 1)
for h in range(20, 70):
    p.append(c.at(ip_pkt(EVIL_MAC, BCAST, EVIL_IP, f"192.168.1.{h}") / ICMP(type=8), 0.01))
save("scan-ping-sweep", p, ["port-scan"], "ICMP sweep of the subnet")

c = T(); p = normal(c, 1)
for h in range(20, 80):
    p.append(c.at(eth(EVIL_MAC, BCAST) / ARP(op=1, hwsrc=EVIL_MAC, psrc=EVIL_IP, pdst=f"192.168.1.{h}"), 0.01))
save("scan-arp", p, ["port-scan"], "ARP sweep of the subnet")

c = T(); p = normal(c, 1); s6, d6 = "2001:db8::66", "2001:db8::10"
for port in range(20, 80):
    p.append(c.at(eth(EVIL_MAC, A_MAC) / IPv6(src=s6, dst=d6) / TCP(sport=45000 + port, dport=port, flags="S"), 0.004))
save("scan-ipv6", p, ["port-scan"], "SYN scan over IPv6")

# --- dns ---
c = T(); p = normal(c, 2)
q, i, sp = dns_q(c, A_MAC, A_IP, "www.paypal.com"); p.append(q)
p.append(dns_r(c, A_MAC, A_IP, "www.paypal.com", "185.220.101.9", i, sp, srv=DNS_IP, srvm=EVIL_MAC, ttl=30, dt=0.002))
save("dns-forged-from-resolver-ip", p, ["dns-hijack"], "Forged answer sent as the real resolver, from a different MAC, with a public address")

# --- dhcp ---
c = T(); p = dhcp_flow(c, A_MAC, GW_IP, GW_MAC, A_IP, GW_IP, [DNS_IP]) + normal(c, 1)
fake = "192.168.1.250"; hm = "50:c7:bf:11:22:33"
p += dhcp_flow(c, B_MAC, fake, hm, "192.168.1.101", fake, [fake])
q, i, sp = dns_q(c, B_MAC, B_IP, "www.google.com", srv=fake, srvm=hm)
p += [q, dns_r(c, B_MAC, B_IP, "www.google.com", "10.9.9.9", i, sp, srv=fake, srvm=hm)]
save("dhcp-fake-home-router", p, ["rogue-dhcp-attack"], "Spoofs a home-router MAC, but then forges DNS answers")

c = T(); p = dhcp_flow(c, A_MAC, EVIL_IP, EVIL_MAC, A_IP, "45.33.32.1", ["45.33.32.156"]) + normal(c, 1)
save("dhcp-only-server-foreign", p, ["rogue-dhcp-attack"], "The only DHCP server seen hands out a gateway outside the client subnet")

c = T(); p = normal(c, 1)
for i in range(150):
    m = "02:00:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(4))
    p += dhcp_flow(c, m, GW_IP, GW_MAC, f"192.168.1.{i % 200 + 20}", GW_IP, [DNS_IP])[:2]
save("dhcp-starvation", p, ["dhcp-starvation"], "One attacker requests leases as 150 invented devices")

# --- floods ---
c = T(); p = normal(c, 1); srv = "192.168.1.80"; sm = "00:1a:2b:00:00:80"
for i in range(400):
    src = f"203.0.113.{i % 6 + 1}"; sport = 1024 + i
    p.append(c.at(ip_pkt(GW_MAC, sm, src, srv) / TCP(sport=sport, dport=80, flags="S", seq=i), 0.001))
    p.append(c.at(ip_pkt(sm, GW_MAC, srv, src) / TCP(sport=80, dport=sport, flags="SA", ack=i + 1), 0.0005))
save("flood-few-sources", p, ["syn-flood"], "Heavy SYN flood from only six sources, under the source threshold")

# --- names ---
c = T(); p = normal(c, 1)
for name in ("fileserver", "wpad"):
    qid = random.randint(1, 60000); sp = 50000 + qid % 9000
    p.append(c.at(eth(A_MAC, "01:00:5e:00:00:fc") / IP(src=A_IP, dst="224.0.0.252") / UDP(sport=sp, dport=5355) / DNS(id=qid, qd=DNSQR(qname=name)), 0.3))
    p.append(c.at(eth(EVIL_MAC, A_MAC) / IP(src=EVIL_IP, dst=A_IP) / UDP(sport=5355, dport=sp) / DNS(id=qid, qr=1, aa=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type="A", rdata=EVIL_IP, ttl=30)), 0.002))
p += tcp_session(c, A_MAC, A_IP, EVIL_MAC, EVIL_IP, 445, n=2, size=200)
save("llmnr-two-names", p, ["llmnr-poison"], "Answers only two names, then takes an SMB connection")

# --- covert channels ---
c = T(); p = normal(c, 1)
for i in range(40):
    n = "".join(random.choices("abcdefghijklmnopqrstuvwxyz234567", k=24)) + ".c2.exfil-lab.example"
    p += g.lookup(c, C_MAC, C_IP, n, "192.0.2.5")
save("tunnel-short-labels", p, ["dns-tunnel"], "24-character labels, under the 30-character threshold")

c = T(); p = normal(c, 1)
for i in range(14):
    c.t += 30 + random.uniform(-6, 6)
    p += tcp_session(c, C_MAC, C_IP, GW_MAC, "185.220.101.7", 8443, n=1, size=64, gap=0.001)
save("beacon-jittered", p, ["beaconing"], "Beacon with 20% random jitter")

# --- tampering and floods at layer 2 ---
c = T(); s = tcp_session(c, A_MAC, A_IP, GW_MAC, WEB, 443, n=8, close=False, payload=tls_hello("www.example.com"))
last = s[-1][TCP]
s.append(c.at(ip_pkt(EVIL_MAC, A_MAC, WEB, A_IP) / TCP(sport=443, dport=last.sport, flags="R", seq=last.ack), 0.01))
c.t += 0.2
for j in range(3):
    t2 = tcp_session(c, A_MAC, A_IP, GW_MAC, WEB, 443, n=3, close=False)
    l2 = t2[-1][TCP]; t2.append(c.at(ip_pkt(EVIL_MAC, A_MAC, WEB, A_IP) / TCP(sport=443, dport=l2.sport, flags="R", seq=l2.ack), 0.01)); s += t2
save("rst-injection", normal(T(), 1) + s, ["rst-injection"], "Forged resets kill live connections, sent from the wrong MAC")

c = T(); p = normal(c, 2)
for _ in range(3):
    inner = bytes(IP(src=A_IP, dst=WEB, proto=6, len=40))[:20] + b"\0" * 8
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / ICMP(type=5, code=1, gw=EVIL_IP) / Raw(inner), 0.2))
save("icmp-redirect", p, ["icmp-redirect"], "Forged ICMP redirect steers a client through the attacker")

c = T(); p = normal(c, 1)
for i in range(40):
    p += tcp_session(c, EVIL_MAC, EVIL_IP, A_MAC, A_IP, 22, n=1, size=80, gap=0.001, rtt=0.001)
save("ssh-brute-force", p, ["brute-force"], "Forty short SSH connections, a password-guessing rhythm")

c = T(); p = normal(c, 1)
for i in range(800):
    m = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))
    p.append(c.at(eth(m, BCAST) / IP(src=f"10.{i % 200}.0.1", dst="10.0.0.1") / UDP(sport=1, dport=1), 0.0005))
save("mac-flood", p, ["mac-flood"], "800 invented MACs to overflow the switch table")

# --- clean look-alikes ---
c = T(); p = normal(c, 2)
for h in range(20, 34):
    p += tcp_session(c, A_MAC, A_IP, GW_MAC, f"93.184.216.{h}", 443, n=3, payload=tls_hello(f"cdn{h}.example.com"))
save("clean-busy-browser", p, None, "A browser opening fourteen sites")

c = T(); p = normal(c, 1)
for port in (80, 443, 8080, 8443, 3000, 5000):
    p += tcp_session(c, A_MAC, A_IP, B_MAC, B_IP, port, n=3)
save("clean-dev-server", p, None, "A developer using six ports on a test machine")

c = T(); p = normal(c, 1)
for i in range(30):
    m = "00:1a:2b:00:03:%02x" % i
    p += dhcp_flow(c, m, GW_IP, GW_MAC, f"192.168.1.{i + 100}", GW_IP, [DNS_IP], name=f"pc{i}")
save("clean-morning-dhcp", p, None, "Thirty real devices all joining at nine o'clock")

c = T(); p = normal(c, 1)
for h in range(20, 26):
    d = f"192.168.1.{h}"; m = "00:1a:2b:00:04:%02x" % h
    p.append(c.at(ip_pkt(A_MAC, m, A_IP, d) / ICMP(type=8), 1)); p.append(c.at(ip_pkt(m, A_MAC, d, A_IP) / ICMP(type=0), 0.001))
save("clean-ping-monitor", p, None, "A monitor pinging six servers")

c = T(); p = normal(c, 1)
for h in range(20, 36):
    p.append(c.at(eth(A_MAC, BCAST) / ARP(op=1, hwsrc=A_MAC, psrc=A_IP, pdst=f"192.168.1.{h}"), 1))
save("clean-arp-busy-host", p, None, "A host resolving sixteen neighbours")

c = T(); p = normal(c, 1)
for i in range(8):
    p += tcp_session(c, A_MAC, A_IP, GW_MAC, "140.82.112.4", 22, n=3, size=200)
save("clean-git-over-ssh", p, None, "Eight git pulls over SSH with real data")

c = T(); p = normal(c, 1)
for i in range(12):
    c.t += 300 + random.uniform(-90, 90)
    p += tcp_session(c, A_MAC, A_IP, GW_MAC, "142.250.1.94", 443, n=4, payload=tls_hello("mail.google.com"))
save("clean-mail-polling", p, None, "A mail app polling roughly every five minutes")

(OUT / "manifest.json").write_text(json.dumps(cases, indent=1))
print(len(cases), "evasion cases")
