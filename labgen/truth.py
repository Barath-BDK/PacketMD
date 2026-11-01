"""Differential oracle: writes Scapy's view of every sample so tests can compare it with our parser."""
import json, pathlib
from scapy.all import IP, TCP, UDP, rdpcap
from scapy.utils import PcapNgWriter

S = pathlib.Path(__file__).resolve().parent.parent / "samples"
out = {}
for f in sorted(S.glob("*.pcap")):
    if f.name.startswith("large"):
        continue
    rows = []
    for p in rdpcap(str(f)):
        l4 = p[TCP] if TCP in p else p[UDP] if UDP in p else None
        rows.append([len(p), p[IP].src if IP in p else None, p[IP].dst if IP in p else None, l4.sport if l4 else None, l4.dport if l4 else None])
    out[f.stem] = rows
# Same packets in pcapng, so the second container format is tested on valid files as well as hostile ones.
w = PcapNgWriter(str(S / "format-check.pcapng"))
for p in rdpcap(str(S / "arp-spoof.pcap")):
    w.write(p)
w.close()
(S / "scapy-truth.json").write_text(json.dumps(out))
print(len(out))
