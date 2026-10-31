// Every tunable number in the engine lives here, with the reason it has that value.
export const BUDGET = {
  maxFileBytes: 100 * 1024 * 1024,   // browser memory stays bounded on a laptop
  maxPackets: 1_000_000,             // well above the 100 MB budget's typical packet count
  maxPacketBytes: 262_144,           // the snaplen tcpdump and Wireshark default to
  maxParseMs: 60_000,                // watchdog limit before the Worker is killed
  maxFlows: 200_000,                 // oldest flows are evicted past this
  maxString: 255,                    // longest legal DNS name
  maxDnsPointers: 16,                // real names need a handful; loops need infinity
  maxDnsRecords: 64,                 // parsed per message, the rest is counted as an anomaly
  maxPcapngBlock: 16 * 1024 * 1024,  // no sane block is bigger than a jumbo capture chunk
  chunkBytes: 4 * 1024 * 1024,       // File.slice read size
  maxStream: 64 * 1024,              // Follow Stream output cap
};

export const T = {
  // verdict
  MARGIN: 0.2,          // top-vs-second probability gap below this is INCONCLUSIVE
  MIN_ATTACK_PROB: 0.5, // ATTACK label needs a majority of the probability mass

  // tcp
  RETRANS_MIN: 5,            // fewer repeats than this is ordinary internet noise
  RETRANS_RATE: 0.03,        // 3% repeats per flow is visible to users
  RTO_GAP_S: 0.18,           // Linux minimum RTO is 200 ms; 180 allows for clock jitter
  ZERO_WINDOW_MIN: 3,
  RST_STORM_MIN: 10,
  RST_MIN: 3,

  // scans and floods
  SCAN_PORTS: 15,            // distinct ports on one host from one source
  SCAN_HOSTS: 10,            // distinct hosts on one port from one source
  SCAN_SYN_ONLY: 0.7,        // share of contacts that never finished a handshake
  FLOOD_HALF_OPEN: 40,       // half-open attempts at one service
  FLOOD_SOURCES: 8,          // many sources: flood; few: broken client
  OUTAGE_MIN_SYN: 5,

  // dns
  DNS_FAIL_RATIO: 0.25,
  DNS_FAIL_MIN: 3,
  DNS_TIMEOUT_S: 2,
  DNS_SLOW_S: 0.5,
  TUNNEL_LABEL: 30,          // labels this long are rare in human names
  TUNNEL_ENTROPY: 3.5,       // bits per char for base32/base64-looking text
  TUNNEL_MIN_QUERIES: 10,

  // arp and identity
  GRATUITOUS_BURST: 3,
  ARP_REPLY_RATE: 5,         // unsolicited replies from one MAC
  FAILOVER_WINDOW_S: 2,      // HA announces then stays; old MAC goes silent

  // mtu and delay
  LARGE_PACKET: 1400,
  MTU_RETRANS_MIN: 3,
  MAD_Z: 3.5,                // standard robust outlier cut-off
  DELAY_MIN_S: 0.2,          // below this nobody notices, whatever the z-score says
  DELAY_MIN_SAMPLES: 6,
  IDLE_GAP_S: 5,

  // dhcp
  DHCP_DISCOVER_MIN: 3,
  DHCP_SLOW_S: 3,

  // behaviour
  BEACON_MIN: 8,             // repeats before a rhythm means anything
  BEACON_JITTER: 0.1,        // stddev/mean below this looks machine-timed
  BEACON_MIN_S: 2,           // faster than this is keepalive or streaming
  DGA_ENTROPY: 3.3,
  DGA_MIN_LEN: 12,
  LARGE_UPLOAD_RATIO: 10,
  LARGE_UPLOAD_MIN: 5_000_000,
};
