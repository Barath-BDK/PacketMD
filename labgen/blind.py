"""A held-out batch written after the detectors were fixed. Results here are reported, not tuned against."""
import json, pathlib, random
from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, TCP, UDP, Ether, Raw, fragment, wrpcap
from generate import A_IP, A_MAC, B_IP, B_MAC, BCAST, C_IP, C_MAC, DNS_IP, EVIL_IP, EVIL_MAC, GW_IP, GW_MAC, WEB, T, eth, ip_pkt, normal, tcp_session, dns_q, dns_r, dhcp_flow, tls_hello, lookup

OUT = pathlib.Path(__file__).resolve().parent / "blind"
OUT.mkdir(exist_ok=True)
random.seed(9001)
cases = []


def save(name, pkts, must, why):
    wrpcap(str(OUT / f"{name}.pcap"), sorted(pkts, key=lambda p: float(p.time)))
    cases.append({"file": name, "must": must, "why": why})


c = T(); p = normal(c, 2)
for _ in range(8):
    p.append(c.at(eth(EVIL_MAC, BCAST) / ARP(op=1, hwsrc=EVIL_MAC, psrc=GW_IP, pdst=A_IP), 0.6))
p += tcp_session(c, A_MAC, A_IP, EVIL_MAC, WEB, 443, n=5, payload=tls_hello("www.example.com"))
save("arp-poison-by-request", p, ["arp-spoof"], "Poisons with ARP requests rather than replies")

c = T(); p = normal(c, 1)
for port in range(20, 90):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=46000 + port, dport=port, flags="A", seq=1, ack=1), 0.004))
    p.append(c.at(ip_pkt(A_MAC, EVIL_MAC, A_IP, EVIL_IP) / TCP(sport=port, dport=46000 + port, flags="R"), 0.001))
save("scan-ack", p, ["port-scan"], "ACK scan used to map firewall rules")

c = T(); p = normal(c, 1)
for port in range(20, 60):
    for pkt in fragment(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP)[IP] / TCP(sport=47000 + port, dport=port, flags="S", options=[("NOP", None)] * 20) / Raw(b"z" * 24), fragsize=16):
        p.append(c.at(eth(EVIL_MAC, A_MAC) / pkt, 0.002))
save("scan-fragmented", p, ["port-scan", "parser-evasion"], "SYN scan split into tiny fragments")

c = T(); p = normal(c, 1)
decoys = [f"203.0.113.{i}" for i in range(1, 9)] + [EVIL_IP]
for port in range(20, 50):
    for d in decoys:
        p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, d, A_IP) / TCP(sport=48000 + port, dport=port, flags="S"), 0.002))
save("scan-decoys", p, ["port-scan"], "Each probe repeated from eight forged decoy addresses")

c = T(); p = normal(c, 1)
for i in range(30):
    n = "".join(random.choices("abcdefghijklmnop", k=16)) + ".t.exfil-lab.example"
    q, qid, sp = dns_q(c, C_MAC, C_IP, n); p.append(q)
    p.append(c.at(ip_pkt(GW_MAC, C_MAC, DNS_IP, C_IP) / UDP(sport=53, dport=sp) / DNS(id=qid, qr=1, qd=DNSQR(qname=n, qtype="TXT"), an=DNSRR(rrname=n, type="TXT", rdata="x" * 180, ttl=1)), 0.01))
save("tunnel-txt-replies", p, ["dns-tunnel"], "Short names, with data carried in large TXT replies")

c = T(); p = normal(c, 1)
for i in range(14):
    c.t += 20 + random.uniform(-1, 1)
    p.append(c.at(ip_pkt(C_MAC, GW_MAC, C_IP, "185.220.101.7") / UDP(sport=51000, dport=443) / Raw(b"k" * 80), 0))
    p.append(c.at(ip_pkt(GW_MAC, C_MAC, "185.220.101.7", C_IP) / UDP(sport=443, dport=51000) / Raw(b"k" * 80), 0.05))
save("beacon-udp", p, ["beaconing"], "Beacon over UDP instead of TCP")

c = T(); p = normal(c, 1)
for i in range(40):
    p.append(c.at(ip_pkt(C_MAC, GW_MAC, C_IP, "185.220.101.9") / ICMP(type=8, id=7, seq=i) / Raw(b"E" * 900), 0.1))
    p.append(c.at(ip_pkt(GW_MAC, C_MAC, "185.220.101.9", C_IP) / ICMP(type=0, id=7, seq=i) / Raw(b"R" * 900), 0.02))
save("icmp-tunnel", p, ["icmp-tunnel"], "Data hidden in large ping payloads")

c = T(); p = dhcp_flow(c, A_MAC, GW_IP, GW_MAC, A_IP, GW_IP, [DNS_IP]) + normal(c, 1)
p += dhcp_flow(c, B_MAC, EVIL_IP, EVIL_MAC, "192.168.1.102", EVIL_IP, [EVIL_IP])
save("rogue-dhcp-self-only", p, ["rogue-dhcp-attack"], "Unknown vendor offers itself as gateway and DNS, no follow-up traffic in the capture")

c = T(); p = normal(c, 1); s6 = "2001:db8::80"
for i in range(400):
    p.append(c.at(eth(GW_MAC, A_MAC) / IPv6(src=f"2001:db8:{i % 251:x}::1", dst=s6) / TCP(sport=1024 + i, dport=80, flags="S", seq=i), 0.001))
save("flood-ipv6", p, ["syn-flood"], "SYN flood over IPv6")

c = T(); p = normal(c, 1)
for i in range(30):
    p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / UDP(sport=45000 + i, dport=5060) / Raw(b"OPTIONS sip:100@x SIP/2.0\r\n"), 0.05))
for i in range(60):
    p += tcp_session(c, EVIL_MAC, EVIL_IP, A_MAC, A_IP, 8080, n=1, size=100, gap=0.001, rtt=0.001, payload=b"POST /login HTTP/1.1\r\nHost: x\r\n\r\n")
save("web-login-guessing", p, ["brute-force"], "Sixty POSTs to /login on a non-standard port")

c = T(); p = normal(c, 1)
p += tcp_session(c, C_MAC, C_IP, GW_MAC, "185.220.101.11", 443, n=0, close=False, payload=tls_hello("files.mega-share.example"))
for i in range(300):
    p.append(c.at(ip_pkt(C_MAC, GW_MAC, C_IP, "185.220.101.11") / TCP(sport=44444, dport=443, flags="PA", seq=i) / Raw(b"D" * 1400), 0.002))
save("exfil-large-upload", p, ["data-exfil"], "A large one-way upload to an unknown host")

(OUT / "manifest.json").write_text(json.dumps(cases, indent=1))
print(len(cases), "blind cases")
