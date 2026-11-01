"""A second held-out batch, written after the first was fixed. The first run of it is the reported figure."""
import json, pathlib, random
from scapy.all import ARP, DNS, DNSQR, DNSRR, Dot1Q, ICMP, ICMPv6ND_RA, IP, IPv6, TCP, UDP, Ether, Raw, wrpcap
from generate import A_IP, A_MAC, B_IP, BCAST, C_IP, C_MAC, DNS_IP, EVIL_IP, EVIL_MAC, GW_IP, GW_MAC, WEB, T, eth, ip_pkt, normal, tcp_session, dns_q, tls_hello

OUT = pathlib.Path(__file__).resolve().parent / "blind2"
OUT.mkdir(exist_ok=True)
random.seed(4242)
cases = []


def save(name, pkts, must, why, allow=None):
    wrpcap(str(OUT / f"{name}.pcap"), sorted(pkts, key=lambda p: float(p.time)))
    cases.append({"file": name, "must": must, "why": why, "allow": allow or []})


c = T(); p = normal(c, 1)
for i in range(800):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / UDP(sport=40000 + i, dport=9999) / Raw(b"f" * 512), 0.001))
save("udp-flood", p, ["udp-flood"], "Hundreds of large UDP packets at one host")

c = T(); p = normal(c, 1)
for i in range(800):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / ICMP(type=8, id=9, seq=i), 0.001))
save("icmp-flood", p, ["udp-flood"], "Ping flood with small packets")

c = T(); p = normal(c, 1)
for i in range(300):
    p.append(c.at(ip_pkt(GW_MAC, A_MAC, f"198.51.100.{i % 200 + 1}", A_IP) / UDP(sport=53, dport=33000) / Raw(b"a" * 1400), 0.002))
save("dns-amplification", p, ["reflection"], "Large DNS replies the victim never asked for")

c = T(); p = normal(c, 1)
for i in range(300):
    p.append(c.at(ip_pkt(GW_MAC, A_MAC, f"203.0.113.{i % 200 + 1}", A_IP) / UDP(sport=123, dport=33000) / Raw(b"n" * 468), 0.002))
save("ntp-amplification", p, ["reflection"], "NTP monlist replies reflected at a victim")

c = T(); p = normal(c, 1)
for i in range(120):
    sp = 41000 + i
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=sp, dport=80, flags="S", seq=1000), 0.01))
    p.append(c.at(ip_pkt(A_MAC, EVIL_MAC, A_IP, EVIL_IP) / TCP(sport=80, dport=sp, flags="SA", seq=2000, ack=1001), 0.001))
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=sp, dport=80, flags="A", seq=1001, ack=2001), 0.001))
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=sp, dport=80, flags="PA", seq=1001, ack=2001) / Raw(b"GET / HTTP/1.1\r\nX-a: b\r\n"), 0.001))
save("slowloris", p, ["slowloris"], "Many connections that never finish their request")

c = T(); p = normal(c, 1)
for i in range(60):
    p += tcp_session(c, GW_MAC, f"45.33.{i}.7", A_MAC, A_IP, 22, n=1, size=300, gap=0.002, rtt=0.002)
save("distributed-ssh-guessing", p, ["brute-force"], "Sixty sources each try SSH once")

c = T(); p = normal(c, 1)
for port in range(20, 80):
    p.append(c.at(eth(EVIL_MAC, A_MAC) / IPv6(src="2001:db8::bad", dst="2001:db8::10") / TCP(sport=49000, dport=port, flags="S"), 0.003))
save("scan-ipv6", p, ["port-scan"], "SYN scan over IPv6")

c = T(); p = normal(c, 1)
for i in range(6):
    p.append(c.at(eth(EVIL_MAC, "33:33:00:00:00:01") / IPv6(src="fe80::bad", dst="ff02::1") / ICMPv6ND_RA(), 1))
save("rogue-ipv6-router", p, ["rogue-ra"], "Rogue IPv6 router advertisements")

c = T(); p = normal(c, 1)
for i in range(20):
    p.append(c.at(eth(EVIL_MAC, A_MAC) / Dot1Q(vlan=1) / Dot1Q(vlan=20) / IP(src=EVIL_IP, dst=A_IP) / ICMP(), 0.1))
save("vlan-hopping", p, ["vlan-hopping"], "Double tagged frames jump into another VLAN")

c = T(); p = normal(c, 1)
for i in range(40):
    p.append(c.at(ip_pkt(EVIL_MAC, BCAST, A_IP, "192.168.1.255") / ICMP(type=8, id=3, seq=i), 0.02))
save("smurf", p, ["reflection"], "Forged pings to broadcast, so every host answers the victim")

c = T(); p = normal(c, 1)
for i in range(10):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, A_IP, A_IP) / TCP(sport=80, dport=80, flags="S"), 0.05))
save("land-attack", p, ["parser-evasion"], "Source and destination both the victim")

c = T(); p = normal(c, 1)
q, qid, sp = dns_q(c, C_MAC, C_IP, "bank.example"); p.append(q)
for i in range(200):
    p.append(c.at(ip_pkt(EVIL_MAC, C_MAC, DNS_IP, C_IP) / UDP(sport=53, dport=sp) / DNS(id=random.randint(0, 65535), qr=1, qd=DNSQR(qname="bank.example"), an=DNSRR(rrname="bank.example", rdata=EVIL_IP, ttl=86400)), 0.0005))
save("dns-race-poison", p, ["dns-hijack", "dns-hijack-attack", "dns-spoof"], "Guesses the query ID with a burst of forged replies")

c = T(); p = normal(c, 1)
for i in range(30):
    p.append(c.at(ip_pkt(C_MAC, GW_MAC, C_IP, "8.8.8.8") / ICMP(type=8, id=1, seq=i) / Raw(b"abcdefgh" * 170), 0.5))
    p.append(c.at(ip_pkt(GW_MAC, C_MAC, "8.8.8.8", C_IP) / ICMP(type=0, id=1, seq=i) / Raw(b"abcdefgh" * 170), 0.02))
save("clean-mtu-test", p, None, "An admin testing path MTU with large pings")

c = T(); p = normal(c, 1)
for i in range(16):
    c.t += 25
    p.append(c.at(ip_pkt(C_MAC, GW_MAC, C_IP, "162.159.192.1") / UDP(sport=51820, dport=51820) / Raw(b"w" * 32), 0))
    p.append(c.at(ip_pkt(GW_MAC, C_MAC, "162.159.192.1", C_IP) / UDP(sport=51820, dport=51820) / Raw(b"w" * 32), 0.03))
save("clean-vpn-keepalive", p, None, "WireGuard keepalive every 25 seconds, which may be questioned but never called an attack", ["beaconing"])

c = T(); p = normal(c, 1)
for i in range(24):
    c.t += 60
    p += tcp_session(c, A_MAC, A_IP, GW_MAC, WEB, 8080, n=1, size=200, payload=b"POST /oauth/token HTTP/1.1\r\nHost: api\r\n\r\n")
save("clean-token-refresh", p, None, "An app refreshing its token once a minute. Known limit: regular calls to an unnamed host still read as beaconing", ["beaconing"])

c = T(); p = normal(c, 1)
for i in range(12):
    n = f"mail{i}.example.org"
    q, qid, sp = dns_q(c, A_MAC, A_IP, n); p.append(q)
    p.append(c.at(ip_pkt(GW_MAC, A_MAC, DNS_IP, A_IP) / UDP(sport=53, dport=sp) / DNS(id=qid, qr=1, qd=DNSQR(qname=n, qtype="TXT"), an=DNSRR(rrname=n, type="TXT", rdata="v=spf1 include:_spf.example.org ~all", ttl=300)), 0.01))
save("clean-mail-txt-lookups", p, None, "A mail server checking SPF records")

c = T(); p = normal(c, 1)
for i in range(30):
    sp = 52000 + i
    p.append(c.at(ip_pkt(GW_MAC, A_MAC, "13.107.42.14", A_IP) / TCP(sport=443, dport=sp, flags="A", seq=5, ack=5), 0.01))
    p.append(c.at(ip_pkt(A_MAC, GW_MAC, A_IP, "13.107.42.14") / TCP(sport=sp, dport=443, flags="A", seq=5, ack=5), 0.01))
save("clean-capture-started-late", p, None, "Capture began after thirty connections were already open")

c = T(); p = normal(c, 1)
p += tcp_session(c, A_MAC, A_IP, GW_MAC, "52.216.8.3", 443, n=0, close=False, payload=tls_hello("backups.s3.example"))
for i in range(300):
    p.append(c.at(ip_pkt(A_MAC, GW_MAC, A_IP, "52.216.8.3") / TCP(sport=44555, dport=443, flags="PA", seq=i) / Raw(b"B" * 1400), 0.002))
save("clean-cloud-backup", p, None, "A nightly backup, which may be questioned but never called an attack", ["data-exfil"])

c = T(); p = normal(c, 1)
for i in range(1500):
    p.append(c.at(ip_pkt(GW_MAC, A_MAC, "142.250.1.94", A_IP) / UDP(sport=443, dport=55000) / Raw(b"q" * 1200), 0.0005))
    if i % 30 == 0: p.append(c.at(ip_pkt(A_MAC, GW_MAC, A_IP, "142.250.1.94") / UDP(sport=55000, dport=443) / Raw(b"a" * 40), 0))
save("clean-quic-download", p, None, "A fast download over QUIC with few acknowledgements")

c = T(); p = normal(c, 1)
for i in range(1000):
    p.append(c.at(ip_pkt(GW_MAC, A_MAC, "52.114.8.8", A_IP) / UDP(sport=3478, dport=50000) / Raw(b"v" * 160), 0.005))
    p.append(c.at(ip_pkt(A_MAC, GW_MAC, A_IP, "52.114.8.8") / UDP(sport=50000, dport=3478) / Raw(b"v" * 160), 0.005))
save("clean-video-call", p, None, "A video call sending both ways")

c = T(); p = normal(c, 1)
for i in range(4):
    p.append(c.at(eth(GW_MAC, "33:33:00:00:00:01") / IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_RA(), 3))
save("clean-real-router-ra", p, None, "The real gateway advertising itself over IPv6")

(OUT / "manifest.json").write_text(json.dumps(cases, indent=1))
print(len(cases), "cases")
