"""Builds the hostile corpus by hand with struct: these files are meant to be wrong in ways a library would refuse to write."""
import json, pathlib, struct

OUT = pathlib.Path(__file__).resolve().parent / "hostile"
OUT.mkdir(exist_ok=True)
MAC = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
manifest = []


def ghdr(snap=65535, link=1): return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, snap, link)
def rec(data, cap=None, ts=1760000000): return struct.pack("<IIII", ts, 0, cap if cap is not None else len(data), len(data)) + data


def ip(proto, payload, src=b"\x0a\0\0\x01", dst=b"\x0a\0\0\x02", vihl=0x45, ident=1, frag=0, total=None):
    return struct.pack(">BBHHHBBH", vihl, 0, total if total is not None else 20 + len(payload), ident, frag, 64, proto, 0) + src + dst + payload


def eth_ip(*a, **k): return MAC + b"\x08\x00" + ip(*a, **k)
def udp(sp, dp, data): return struct.pack(">HHHH", sp, dp, 8 + len(data), 0) + data
def dnsmsg(body, an=0): return struct.pack(">HHHHHH", 0x1234, 0x8180 if an else 0x0100, 1, an, 0, 0) + body
def label(name): return b"".join(bytes([len(p)]) + p for p in name.split(b".")) + b"\0"


def add(file, why, expect, data, upload=None):
    (OUT / file).write_bytes(data)
    manifest.append({"file": file, "uploadName": upload or file, "attack": why, "expect": expect})


add("renamed-exe.pcap", "Windows program renamed to .pcap", "rejected", b"MZ\x90\0" + b"\0" * 200)
add("zip-polyglot.pcap", "Zip archive named as a capture", "rejected", b"PK\x03\x04" + b"\0" * 200)
add("ext-mismatch.pcapng", "pcap bytes under a .pcapng name", "rejected", ghdr() + rec(b"\0" * 20))
add("truncated-header.pcap", "Valid signature, header cut short", "rejected", struct.pack("<I", 0xa1b2c3d4) + b"\0" * 6)
add("pcapng-block-past-eof.pcapng", "Block length larger than the file", "survives", struct.pack("<IIIHHq", 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1) + struct.pack("<I", 28) + struct.pack("<II", 6, 0x7fffff00) + b"\0" * 32)
add("pcapng-block-zero.pcapng", "Block length 0, the infinite loop trap", "survives", struct.pack("<IIIHHq", 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1) + struct.pack("<I", 28) + struct.pack("<II", 1, 0) + b"\0" * 32)
add("record-length-lie.pcap", "Record header claims millions of bytes", "survives", ghdr() + rec(b"\0" * 40, cap=50_000_000))
add("snaplen-4gb.pcap", "Header snaplen of 4 GB", "survives", ghdr(snap=0xffffffff) + rec(eth_ip(17, udp(1, 2, b"hi"))))
add("many-tiny-records.pcap", "A flood of 30,000 minimal records", "survives", ghdr() + rec(b"\0" * 14) * 30000)

ptr = dnsmsg(b"\xc0\x0c" + struct.pack(">HH", 1, 1))
add("dns-pointer-loop.pcap", "DNS compression pointer that points at itself", "evasion", ghdr() + rec(eth_ip(17, udp(5353, 53, ptr))))
lab = (b"a" * 63 + b".") * 8
add("dns-max-labels.pcap", "DNS name of maximum-length labels", "evasion", ghdr() + rec(eth_ip(17, udp(5353, 53, dnsmsg(label(lab[:-1]) + struct.pack(">HH", 1, 1))))))
evil = dnsmsg(label(b"<img src=x onerror=alert(1)>") + struct.pack(">HH", 1, 1))
bidi = dnsmsg(label("safe‮gnp.exe".encode()) + struct.pack(">HH", 1, 1))
nul = dnsmsg(label(b"host\0name") + struct.pack(">HH", 1, 1))
add("hostile-hostnames.pcap", "Hostnames carrying HTML, bidi overrides and null bytes", "survives", ghdr() + rec(eth_ip(17, udp(5353, 53, evil))) + rec(eth_ip(17, udp(5354, 53, bidi))) + rec(eth_ip(17, udp(5355, 53, nul))))
add("ipv4-ihl-low.pcap", "IPv4 header length below 20 bytes", "evasion", ghdr() + rec(eth_ip(6, b"\0" * 40, vihl=0x42)))
tcp = struct.pack(">HHIIBBHHH", 1, 2, 3, 4, 0xf0, 2, 100, 0, 0)
add("tcp-offset-past-end.pcap", "TCP data offset past the end of the packet", "evasion", ghdr() + rec(eth_ip(6, tcp)))
frag1 = eth_ip(17, b"A" * 40, ident=7, frag=0x2000)
frag2 = eth_ip(17, b"B" * 40, ident=7, frag=0x0002)
add("overlapping-fragments.pcap", "IP fragments that overlap each other", "evasion", ghdr() + rec(frag1) + rec(frag2))
opts = struct.pack(">HHIIBBHHH", 1, 2, 3, 4, 0xf0, 2, 100, 0, 0) + b"\x08\xff" + b"\0" * 38
add("huge-options.pcap", "TCP option claiming more bytes than exist", "evasion", ghdr() + rec(eth_ip(6, opts)))
eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
add("eicar-payload.pcap", "Antivirus test string inside a payload", "survives", ghdr() + rec(eth_ip(17, udp(1234, 80, eicar))))
add("path-traversal-name.pcap", "Filename with ../ traversal", "survives", ghdr() + rec(eth_ip(17, udp(1, 2, b"x"))), upload="../../etc/passwd.pcap")
add("unicode-name.pcap", "Filename using a right-to-left override", "survives", ghdr() + rec(eth_ip(17, udp(1, 2, b"x"))), upload="invoice‮gnp.pcap")
add("wifi-linktype.pcap", "802.11 capture, a link type outside scope", "survives", ghdr(link=105) + rec(b"\x80\0" + b"\0" * 30))

(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
print(len(manifest), "hostile files")
