"""Generates lab captures and their ground truth. Scapy is used only here, never in the analysis."""
import json, random, sys, pathlib
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap, NBNSQueryRequest

OUT = pathlib.Path(__file__).resolve().parent.parent / "samples"
OUT.mkdir(exist_ok=True)
random.seed(1337)

GW_IP, GW_MAC = "192.168.1.1", "00:1a:2b:00:00:01"
DNS_IP = "192.168.1.2"; DNS_MAC = "00:1a:2b:00:00:02"
A_IP, A_MAC = "192.168.1.10", "00:1a:2b:00:00:10"
B_IP, B_MAC = "192.168.1.11", "00:1a:2b:00:00:11"
C_IP, C_MAC = "192.168.1.12", "00:1a:2b:00:00:12"
EVIL_IP, EVIL_MAC = "192.168.1.66", "de:ad:be:ef:00:66"
WEB = "93.184.216.34"
BCAST = "ff:ff:ff:ff:ff:ff"
expected = {}


class T:
    """A clock so every sample has believable, deterministic timing."""
    def __init__(s, t=1760000000.0): s.t = t
    def at(s, pkt, dt=0.001):
        s.t += dt; pkt.time = s.t; return pkt


def eth(sm, dm): return Ether(src=sm, dst=dm)
def ip_pkt(sm, dm, si, di, **k): return eth(sm, dm) / IP(src=si, dst=di, **k)


def tcp_session(c, cm, cip, sm, sip, dport=443, n=20, size=1200, sport=None, gap=0.01, rtt=0.02, payload=None, close=True, df=False):
    sport = sport or random.randint(40000, 60000)
    kw = {"flags": "DF"} if df else {}
    seq, ack = random.randint(1, 2**31), random.randint(1, 2**31)
    out = [c.at(ip_pkt(cm, sm, cip, sip, **kw) / TCP(sport=sport, dport=dport, flags="S", seq=seq, options=[("MSS", 1460)]), 0.05)]
    out.append(c.at(ip_pkt(sm, cm, sip, cip, **kw) / TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq + 1, options=[("MSS", 1460)]), rtt))
    seq += 1; ack += 1
    out.append(c.at(ip_pkt(cm, sm, cip, sip, **kw) / TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack)))
    if payload:
        out.append(c.at(ip_pkt(cm, sm, cip, sip, **kw) / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack) / Raw(payload)))
        seq += len(payload)
    for _ in range(n):
        out.append(c.at(ip_pkt(sm, cm, sip, cip, **kw) / TCP(sport=dport, dport=sport, flags="A", seq=ack, ack=seq) / Raw(b"x" * size), gap))
        ack += size
        out.append(c.at(ip_pkt(cm, sm, cip, sip, **kw) / TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack), 0.002))
    if close:
        out.append(c.at(ip_pkt(cm, sm, cip, sip, **kw) / TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=ack)))
        out.append(c.at(ip_pkt(sm, cm, sip, cip, **kw) / TCP(sport=dport, dport=sport, flags="FA", seq=ack, ack=seq + 1), rtt))
    return out


def tls_hello(sni):
    name = sni.encode()
    ext_sni = b"\x00\x00" + (len(name) + 5).to_bytes(2, "big") + (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
    ext = ext_sni + bytes.fromhex("000a00080006001d00170018000b00020100")
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x04\x13\x01\xc0\x2b" + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def ech_hello():
    ext = b"\xfe\x0d\x00\x04\x00\x01\x02\x03"
    body = b"\x03\x03" + b"\x22" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def dns_q(c, cm, cip, name, srv=DNS_IP, srvm=GW_MAC, qid=None):
    qid = qid if qid is not None else random.randint(1, 65000)
    sp = random.randint(40000, 60000)
    return c.at(ip_pkt(cm, srvm, cip, srv) / UDP(sport=sp, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name)), 0.03), qid, sp


def dns_r(c, cm, cip, name, ans, qid, sp, srv=DNS_IP, srvm=GW_MAC, rcode=0, ttl=300, dt=0.012):
    an = DNSRR(rrname=name, type="A", rdata=ans, ttl=ttl) if ans else None
    return c.at(ip_pkt(srvm, cm, srv, cip) / UDP(sport=53, dport=sp) / DNS(id=qid, qr=1, ra=1, rcode=rcode, qd=DNSQR(qname=name), an=an, ancount=1 if an else 0), dt)


def lookup(c, cm, cip, name, ans, **k):
    q, i, sp = dns_q(c, cm, cip, name)
    return [q, dns_r(c, cm, cip, name, ans, i, sp, **k)]


def normal(c, rounds=3):
    """Everyday office traffic used as a background in every sample."""
    out = []
    names = [("www.example.com", WEB), ("docs.example.org", "93.184.216.40"), ("connectivitycheck.gstatic.com", "142.250.1.94"), ("swscan.apple.com", "17.253.1.20")]
    for r in range(rounds):
        for name, ans in names:
            cm, cip = random.choice([(A_MAC, A_IP), (B_MAC, B_IP), (C_MAC, C_IP)])
            out += lookup(c, cm, cip, name, ans)
            out += tcp_session(c, cm, cip, GW_MAC, ans, 443, n=4, payload=tls_hello(name))
        out.append(c.at(eth(A_MAC, GW_MAC) / IP(src=A_IP, dst="129.6.15.28") / UDP(sport=123, dport=123) / Raw(b"\x23" + b"\0" * 47), 0.1))
        out.append(c.at(eth(B_MAC, "01:00:5e:00:00:fb") / IP(src=B_IP, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="printer.local")), 0.1))
    for ip, mac in [(GW_IP, GW_MAC)]:
        out.append(c.at(eth(A_MAC, BCAST) / ARP(op=1, hwsrc=A_MAC, psrc=A_IP, pdst=ip), 0.01))
        out.append(c.at(eth(mac, A_MAC) / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=A_MAC, pdst=A_IP), 0.002))
    return out


def dhcp_flow(c, cli_mac, srv_ip, srv_mac, yi, router, dns_ips, name=None, xid=None, giaddr="0.0.0.0", server_id=None, src_ip=None):
    xid = xid or random.randint(1, 2**31)
    chaddr = bytes.fromhex(cli_mac.replace(":", "")) + b"\0" * 10
    server_id = server_id or srv_ip
    src_ip = src_ip or srv_ip
    opts = [("message-type", "offer"), ("server_id", server_id), ("router", router), ("name_server", *dns_ips), ("subnet_mask", "255.255.255.0"), ("lease_time", 3600), "end"]
    ack = list(opts); ack[0] = ("message-type", "ack")
    dis = [("message-type", "discover")] + ([("hostname", name)] if name else []) + ["end"]
    req = [("message-type", "request"), ("requested_addr", yi), ("server_id", server_id), "end"]
    def base(sm, dm, si, di, sp, dp, op, y="0.0.0.0"):
        return eth(sm, dm) / IP(src=si, dst=di) / UDP(sport=sp, dport=dp) / BOOTP(op=op, xid=xid, chaddr=chaddr, yiaddr=y, giaddr=giaddr, flags=0x8000)
    return [
        c.at(base(cli_mac, BCAST, "0.0.0.0", "255.255.255.255", 68, 67, 1) / DHCP(options=dis), 0.2),
        c.at(base(srv_mac, BCAST, src_ip, "255.255.255.255", 67, 68, 2, yi) / DHCP(options=opts), 0.01),
        c.at(base(cli_mac, BCAST, "0.0.0.0", "255.255.255.255", 68, 67, 1) / DHCP(options=req), 0.01),
        c.at(base(srv_mac, BCAST, src_ip, "255.255.255.255", 67, 68, 2, yi) / DHCP(options=ack), 0.01),
    ]


def save(name, pkts, findings=None, allowed=None, note=""):
    wrpcap(str(OUT / f"{name}.pcap"), sorted(pkts, key=lambda p: float(p.time)))
    expected[name] = {"findings": findings or [], "allowed": allowed or [], "note": note}


def s_normal():
    c = T(); p = dhcp_flow(c, A_MAC, GW_IP, GW_MAC, A_IP, GW_IP, [DNS_IP], name="reception-pc") + normal(c, 5)
    save("normal-baseline", p, note="A clean network, also used to save a baseline")


def s_retrans():
    c = T(); p = normal(c, 1)
    s = tcp_session(c, A_MAC, A_IP, GW_MAC, WEB, 443, n=40, close=False, payload=tls_hello("www.example.com"))
    out = []
    data = [x for x in s if x.haslayer(Raw) and x[TCP].sport == 443]
    for i, x in enumerate(s):
        out.append(x)
        if x in data and i % 5 == 0:
            for j, w in enumerate((0.25, 0.5, 1.0)[: 1 + i % 3]):
                r = x.copy(); c.t += w; r.time = c.t; out.append(r)
    p += sorted(out, key=lambda z: float(z.time))
    save("tcp-retransmissions-congestion", p, ["tcp-loss"])


def s_resets():
    c = T(); p = normal(c, 1)
    for i in range(12):
        sp = 41000 + i
        p.append(c.at(ip_pkt(A_MAC, GW_MAC, A_IP, "10.20.0.5") / TCP(sport=sp, dport=8443, flags="S", seq=100 + i), 0.4))
        p.append(c.at(ip_pkt(GW_MAC, A_MAC, "10.20.0.5", A_IP) / TCP(sport=8443, dport=sp, flags="RA", ack=101 + i, seq=0), 0.002))
    save("tcp-resets", p, ["tcp-reset"])


def s_dns_fail():
    c = T(); p = normal(c, 1)
    for i in range(14):
        n = f"intranet{i % 3}.corp.example"
        q, qid, sp = dns_q(c, A_MAC, A_IP, n)
        p.append(q)
        if i % 2: p.append(dns_r(c, A_MAC, A_IP, n, None, qid, sp, rcode=2))
    save("dns-failures", p, ["dns-failure"])


def s_dup():
    c = T(); p = normal(c, 1)
    dup = "192.168.1.50"; m1, m2 = "00:1a:2b:00:00:50", "00:1a:2b:00:00:51"
    p.append(c.at(eth(m1, BCAST) / ARP(op=1, hwsrc=m1, psrc=dup, pdst=dup), 0.2))
    for i in range(3):
        p.append(c.at(eth(A_MAC, BCAST) / ARP(op=1, hwsrc=A_MAC, psrc=A_IP, pdst=dup), 0.5))
        p.append(c.at(eth(m1, A_MAC) / ARP(op=2, hwsrc=m1, psrc=dup, hwdst=A_MAC, pdst=A_IP), 0.002))
        p.append(c.at(eth(m2, A_MAC) / ARP(op=2, hwsrc=m2, psrc=dup, hwdst=A_MAC, pdst=A_IP), 0.003))
    p += dhcp_flow(c, m2, GW_IP, GW_MAC, dup, GW_IP, [DNS_IP])
    save("duplicate-ip", p, ["duplicate-ip"], note="Static device inside the DHCP pool")


def spoof_frames(c, n=12):
    p = []
    for i in range(n):
        p.append(c.at(eth(EVIL_MAC, A_MAC) / ARP(op=2, hwsrc=EVIL_MAC, psrc=GW_IP, hwdst=A_MAC, pdst=A_IP), 0.5))
        p.append(c.at(eth(EVIL_MAC, GW_MAC) / ARP(op=2, hwsrc=EVIL_MAC, psrc=A_IP, hwdst=GW_MAC, pdst=GW_IP), 0.001))
    p.append(c.at(eth(EVIL_MAC, BCAST) / ARP(op=1, hwsrc=EVIL_MAC, psrc=EVIL_IP, pdst=GW_IP), 0.01))
    return p


def s_arp():
    c = T(); p = normal(c, 2)
    p.append(c.at(eth(GW_MAC, A_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=A_MAC, pdst=A_IP), 0.1))
    p += spoof_frames(c)
    p += tcp_session(c, A_MAC, A_IP, EVIL_MAC, WEB, 443, n=6, payload=tls_hello("www.example.com"))
    save("arp-spoof", p, ["arp-spoof"])


def mtu_frames(c, icmp=True):
    host, peer = B_IP, "198.51.100.20"
    s = tcp_session(c, B_MAC, host, GW_MAC, peer, 443, n=0, close=False, df=True)
    seq = s[0][TCP].seq + 1; ack = s[1][TCP].seq + 1
    p = list(s)
    small = c.at(ip_pkt(B_MAC, GW_MAC, host, peer, flags="DF") / TCP(sport=s[0][TCP].sport, dport=443, flags="PA", seq=seq, ack=ack) / Raw(b"GET / small" * 4))
    p.append(small); seq += 44
    p.append(c.at(ip_pkt(GW_MAC, B_MAC, peer, host, flags="DF") / TCP(sport=443, dport=s[0][TCP].sport, flags="A", seq=ack, ack=seq), 0.02))
    big = ip_pkt(B_MAC, GW_MAC, host, peer, flags="DF") / TCP(sport=s[0][TCP].sport, dport=443, flags="A", seq=seq, ack=ack) / Raw(b"U" * 1446)
    for w in (0.2, 0.4, 0.8, 1.6, 3.2):
        r = big.copy(); p.append(c.at(r, w))
        if icmp and w == 0.4:
            inner = bytes(IP(src=host, dst=peer, flags="DF", proto=6, len=1500))[:20] + b"\0" * 8
            p.append(c.at(ip_pkt(GW_MAC, B_MAC, "198.51.100.1", host) / ICMP(type=3, code=4, nexthopmtu=1400) / Raw(inner), 0.01))
    return p


def s_mtu():
    c = T(); p = normal(c, 1) + mtu_frames(c)
    save("mtu-blackhole", p, ["mtu-blackhole"])


def s_scan():
    c = T(); p = normal(c, 1)
    for port in range(20, 100):
        sp = 50000 + port
        p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=sp, dport=port, flags="S", seq=port), 0.003))
        if port in (22, 80):
            p.append(c.at(ip_pkt(A_MAC, EVIL_MAC, A_IP, EVIL_IP) / TCP(sport=port, dport=sp, flags="SA", ack=port + 1), 0.001))
            p.append(c.at(ip_pkt(EVIL_MAC, A_MAC, EVIL_IP, A_IP) / TCP(sport=sp, dport=port, flags="R", seq=port + 1), 0.001))
        else:
            p.append(c.at(ip_pkt(A_MAC, EVIL_MAC, A_IP, EVIL_IP) / TCP(sport=port, dport=sp, flags="RA", ack=port + 1), 0.001))
    save("port-scan-vertical", p, ["port-scan"])
    c = T(); p = normal(c, 1)
    for h in range(20, 60):
        d = f"192.168.1.{h}"
        p.append(c.at(ip_pkt(EVIL_MAC, BCAST, EVIL_IP, d) / TCP(sport=51000 + h, dport=445, flags="S", seq=h), 0.004))
    save("port-scan-horizontal", p, ["port-scan"])
    c = T(); p = normal(c, 1); scanner, sm = "192.168.1.200", "00:1a:2b:00:02:00"
    ua = b"GET / HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0 (compatible; Nessus SOAP)\r\n\r\n"
    for port in range(8000, 8030):
        p += tcp_session(c, sm, scanner, A_MAC, A_IP, port, n=1, size=100, payload=ua, rtt=0.001, gap=0.001)
    save("port-scan-benign-scanner", p, [], note="Hard negative: declared vulnerability scanner finishing real connections", allowed=["benign"])


def s_hijack():
    c = T(); p = normal(c, 2)
    q, i, sp = dns_q(c, A_MAC, A_IP, "www.paypal.com")
    p.append(q)
    p.append(dns_r(c, A_MAC, A_IP, "www.paypal.com", "10.66.6.6", i, sp, srv=DNS_IP, srvm=EVIL_MAC, ttl=30, dt=0.002))
    p.append(dns_r(c, A_MAC, A_IP, "www.paypal.com", "151.101.1.21", i, sp, dt=0.02))
    p += tcp_session(c, A_MAC, A_IP, EVIL_MAC, "10.66.6.6", 443, n=3, payload=tls_hello("www.paypal.com"))
    save("dns-hijack", p, ["dns-hijack"])


def s_rogue():
    c = T(); p = dhcp_flow(c, A_MAC, GW_IP, GW_MAC, A_IP, GW_IP, [DNS_IP]) + normal(c, 1)
    home, hm = "192.168.1.254", "50:c7:bf:aa:bb:cc"
    p += dhcp_flow(c, B_MAC, home, hm, "192.168.1.101", home, [home]) + normal(c, 1)
    save("rogue-dhcp-benign-router", p, ["rogue-dhcp-misconfig"], note="Home router plugged in by accident")
    c = T(); p = dhcp_flow(c, A_MAC, GW_IP, GW_MAC, A_IP, GW_IP, [DNS_IP]) + normal(c, 1)
    p += dhcp_flow(c, B_MAC, EVIL_IP, EVIL_MAC, "192.168.1.102", EVIL_IP, ["45.33.32.156"])
    q, i, sp = dns_q(c, B_MAC, B_IP, "www.google.com", srv="45.33.32.156", srvm=EVIL_MAC)
    p += [q, dns_r(c, B_MAC, B_IP, "www.google.com", "45.33.32.200", i, sp, srv="45.33.32.156", srvm=EVIL_MAC)]
    save("rogue-dhcp-malicious", p, ["rogue-dhcp-attack"])


def s_flood():
    c = T(); p = normal(c, 1); srv = "192.168.1.80"; sm = "00:1a:2b:00:00:80"
    for i in range(300):
        src = f"203.0.{random.randint(1, 250)}.{random.randint(1, 250)}"; sp = random.randint(1024, 65000)
        p.append(c.at(ip_pkt(GW_MAC, sm, src, srv) / TCP(sport=sp, dport=80, flags="S", seq=i), 0.001))
        p.append(c.at(ip_pkt(sm, GW_MAC, srv, src) / TCP(sport=80, dport=sp, flags="SA", ack=i + 1), 0.0005))
    save("syn-flood", p, ["syn-flood"])
    c = T(); p = normal(c, 1)
    p += tcp_session(c, A_MAC, A_IP, sm, srv, 80, n=5)
    p += tcp_session(c, B_MAC, B_IP, sm, srv, 80, n=5)
    for cm, cip in [(A_MAC, A_IP), (B_MAC, B_IP), (C_MAC, C_IP)]:
        for k in range(2):
            sp = random.randint(41000, 60000); w = 1.0
            for _ in range(4):
                p.append(c.at(ip_pkt(cm, sm, cip, srv) / TCP(sport=sp, dport=80, flags="S", seq=500), w)); w *= 2
    save("server-outage", p, ["server-outage"], note="Fault twin of syn-flood")


def s_failover():
    c = T(); p = normal(c, 2); vip = "192.168.1.1"; n2 = "00:1a:2b:00:00:02"
    p.append(c.at(eth(n2, BCAST) / ARP(op=1, hwsrc=n2, psrc=vip, pdst=vip), 3))
    p.append(c.at(eth(n2, BCAST) / ARP(op=1, hwsrc=n2, psrc=vip, pdst=vip), 0.2))
    p.append(c.at(eth(A_MAC, BCAST) / ARP(op=1, hwsrc=A_MAC, psrc=A_IP, pdst=vip), 1))
    p.append(c.at(eth(n2, A_MAC) / ARP(op=2, hwsrc=n2, psrc=vip, hwdst=A_MAC, pdst=A_IP), 0.002))
    save("failover-gratuitous-arp", p, [], note="Hard negative: redundant gateway taking over", allowed=["benign"])


def s_relay():
    c = T(); p = dhcp_flow(c, A_MAC, "10.9.9.9", GW_MAC, A_IP, GW_IP, [DNS_IP], giaddr=GW_IP, server_id="10.9.9.9", src_ip=GW_IP) + normal(c, 1)
    p += dhcp_flow(c, B_MAC, "10.9.9.9", GW_MAC, B_IP, GW_IP, [DNS_IP], giaddr=GW_IP, server_id="10.9.9.9", src_ip="192.168.1.3")
    save("dhcp-relay", p, [], note="Hard negative: relay addresses differ, server identity does not", allowed=["benign"])


def llmnr_frames(c):
    p = []
    for name in ("fileserver", "printr", "wpad"):
        qid = random.randint(1, 60000); sp = random.randint(50000, 60000)
        p.append(c.at(eth(A_MAC, "01:00:5e:00:00:fc") / IP(src=A_IP, dst="224.0.0.252") / UDP(sport=sp, dport=5355) / DNS(id=qid, qd=DNSQR(qname=name)), 0.3))
        p.append(c.at(eth(EVIL_MAC, A_MAC) / IP(src=EVIL_IP, dst=A_IP) / UDP(sport=5355, dport=sp) / DNS(id=qid, qr=1, aa=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type="A", rdata=EVIL_IP, ttl=30)), 0.002))
    p += tcp_session(c, A_MAC, A_IP, EVIL_MAC, EVIL_IP, 445, n=2, size=200)
    return p


def s_llmnr():
    c = T(); p = normal(c, 1) + llmnr_frames(c)
    save("llmnr-poisoning", p, ["llmnr-poison"])


def s_mixed():
    c = T(); p = dhcp_flow(c, A_MAC, GW_IP, GW_MAC, A_IP, GW_IP, [DNS_IP], name="reception-pc") + normal(c, 2)
    p += mtu_frames(c) + spoof_frames(c) + normal(c, 1)
    p += tcp_session(c, A_MAC, A_IP, EVIL_MAC, WEB, 443, n=6, payload=tls_hello("www.example.com"))
    save("mixed-incident", p, ["arp-spoof", "mtu-blackhole"], allowed=["benign"], note="Demo centrepiece: everything is broken, one fault and one attack")


def s_beacon():
    c = T(); p = normal(c, 1)
    c2 = "185.220.101.7"
    for i in range(14):
        c.t += 30 + random.uniform(-0.3, 0.3)
        p += tcp_session(c, C_MAC, C_IP, GW_MAC, c2, 8443, n=1, size=64, gap=0.001)
    save("beacon-fixed-interval", p, ["beaconing"])


def s_dga():
    c = T(); p = normal(c, 1)
    for i in range(14):
        n = "".join(random.choices("bcdfghjklmnpqrstvwxz0123456789", k=18)) + ".net"
        q, qid, sp = dns_q(c, C_MAC, C_IP, n); p.append(q); p.append(dns_r(c, C_MAC, C_IP, n, "192.0.2.77", qid, sp))
    save("dga-lookups", p, ["dga-domain"])


def s_tunnel():
    c = T(); p = normal(c, 1)
    for i in range(30):
        n = "".join(random.choices("abcdefghijklmnopqrstuvwxyz234567", k=48)) + ".t.exfil-lab.example"
        p += lookup(c, C_MAC, C_IP, n, "192.0.2.5")
    save("dns-tunnel", p, ["dns-tunnel"])


def s_hidden():
    c = T(); p = normal(c, 1)
    p += tcp_session(c, A_MAC, A_IP, GW_MAC, "104.16.1.1", 443, n=4, payload=ech_hello())
    p += tcp_session(c, A_MAC, A_IP, GW_MAC, "9.9.9.9", 853, n=2, size=120)
    save("hidden-domain-ech", p, [], note="Domain must show as hidden, never guessed", allowed=["benign"])


def s_ambiguous():
    c = T(); m2 = "00:1a:2b:00:00:77"
    p = normal(c, 1)
    p += dhcp_flow(c, m2, DNS_IP, DNS_MAC, GW_IP, GW_IP, [DNS_IP])
    for i in range(7):
        p.append(c.at(eth(m2, A_MAC) / ARP(op=2, hwsrc=m2, psrc=GW_IP, hwdst=A_MAC, pdst=A_IP), 0.4))
        p.append(c.at(eth(GW_MAC, A_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=A_MAC, pdst=A_IP), 0.2))
    save("arp-gateway-ambiguous", p, ["inconclusive:arp-spoof"], note="Could be a spoof or a bad DHCP lease: the evidence does not settle it")


def s_fix_demo():
    """Private before and after pair for the demo video, written outside the repo and never published."""
    out = OUT.parent.parent / "demo-captures"
    out.mkdir(exist_ok=True)
    c = T(1760200000.0)
    p = dhcp_flow(c, A_MAC, GW_IP, GW_MAC, A_IP, GW_IP, [DNS_IP], name="reception-pc") + normal(c, 2)
    p.append(c.at(eth(GW_MAC, A_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=A_MAC, pdst=A_IP), 0.1))
    p += spoof_frames(c, 14)
    p += tcp_session(c, A_MAC, A_IP, EVIL_MAC, WEB, 443, n=8, payload=tls_hello("www.example.com"))
    wrpcap(str(out / "fix-demo-1-attack.pcap"), sorted(p, key=lambda x: float(x.time)))
    c = T(1760203600.0)
    p = dhcp_flow(c, A_MAC, GW_IP, GW_MAC, A_IP, GW_IP, [DNS_IP], name="reception-pc") + normal(c, 2)
    for _ in range(3):
        p.append(c.at(eth(A_MAC, BCAST) / ARP(op=1, hwsrc=A_MAC, psrc=A_IP, pdst=GW_IP), 2))
        p.append(c.at(eth(GW_MAC, A_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=A_MAC, pdst=A_IP), 0.002))
    p += tcp_session(c, A_MAC, A_IP, GW_MAC, WEB, 443, n=8, payload=tls_hello("www.example.com"))
    wrpcap(str(out / "fix-demo-2-after-fix.pcap"), sorted(p, key=lambda x: float(x.time)))


def s_verify():
    c = T(1760100000.0); p = normal(c, 3)
    save("mixed-incident-after-fix", p, [], note="Same network after the fixes, used by Verify Fix", allowed=["benign"])


def s_large():
    c = T(); p = []
    while sum(len(x) for x in p[-1:]) == 0 or len(p) < 40000:
        p += tcp_session(c, A_MAC, A_IP, GW_MAC, WEB, 443, n=60, size=1400, gap=0.0005)
    wrpcap(str(OUT / "large-capture.pcap"), p)


if __name__ == "__main__":
    for fn in (s_normal, s_retrans, s_resets, s_dns_fail, s_dup, s_arp, s_mtu, s_scan, s_hijack, s_rogue, s_flood, s_failover, s_relay, s_llmnr, s_mixed, s_beacon, s_dga, s_tunnel, s_hidden, s_verify, s_ambiguous):
        fn()
    if "--demo" in sys.argv:
        s_fix_demo()
    if "--large" in sys.argv:
        s_large()
    (OUT / "expected.json").write_text(json.dumps(expected, indent=2))
    print(len(expected), "samples")
