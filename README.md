# PacketMD

PacketMD reads a packet capture and tells you whether your network has a fault or is under attack. It explains the problem in plain language, shows the exact packets that prove each claim, and writes a fix using the real addresses from your file. The capture never leaves your device.

Built for the IIITDM Kancheepuram cybersecurity hackathon, Network Track. Live site: https://packetmd.vercel.app. Demo video: *link to be added before submission*.

## The problem

Small offices and labs have no network engineer. When "the internet is broken", someone opens a capture and drowns. Existing tools list symptoms and expect the reader to infer the cause. They cannot say whether a rogue DHCP server is an intern's home router or an attacker. Opening an untrusted capture in a desktop analyser is itself a risk, because capture files can be crafted to attack parsers.

## The solution

Detectors never decide anything. They report signals. Competing explanations (specific faults, specific attacks and "normal behaviour") collect weight from those signals, like a doctor's differential diagnosis.

- If one explanation wins clearly, it gets a verdict: **FAULT**, **ATTACK** or **BENIGN**.
- If the race is close, the verdict is **INCONCLUSIVE**, and PacketMD says exactly what to capture next.
- An attack label is blocked if an innocent explanation matched. This is the false-alarm guard.

Every signal, weight and proof packet stays visible in the Differential tab.

## Features

**Core**
- Differential diagnosis with a visible signal ledger and four verdict lanes
- Inconclusive verdicts with "capture this next" advice
- Claim-to-packet binding: a finding with no evidence cannot be created
- Source Locator: exact file offset and byte range for any packet or field
- File-specific fixes with Windows, Linux and router commands. A step is dropped if any value in it cannot be filled from the capture
- Red-Team Self-Test: 20 hostile files run through the real pipeline in your browser
- Animated attack stories built only from capture data, each with a real-life analogy, plus "Play whole incident"

**Also included**
- Verify Fix: open a second capture and get RESOLVED, STILL PRESENT or NEW per finding. Try it with `samples/mixed-incident.pcap` then `samples/mixed-incident-after-fix.pcap`
- Causal links between symptoms and root causes, blast radius, and a fix-first order
- Beginner, Technical and Analyst reading levels
- Timeline you can adjust: packets or bytes, level of detail, drag to zoom, highlight one problem
- Investigator: packet list, decoded tree, hex view with field highlighting, our own filter language, Follow Stream, copy as Wireshark filter or BPF
- Activity: domain attribution from SNI, HTTP Host and DNS, inferred traffic class, offline reputation checks
- Known-good baseline, Markdown and JSON export, print to PDF, optional accounts and share links
- Investigations: logged-in users can reopen, in full, the reports they chose to save, and delete them. Packets are never stored and addresses are replaced with labels, so Investigator and Verify Fix need the original capture

**Detects**

Faults: TCP retransmissions, resets, unanswered connections, zero-window stalls, DNS failures, duplicate IP, MTU black holes, unusual delay, DHCP failure, server outage, misconfigured second DHCP server.

Attacks: ARP spoofing, DNS hijacking, rogue DHCP, DHCP starvation, port scans (SYN, stealth, ACK, UDP, ping and ARP sweeps), SYN, UDP and ping floods, reflection and amplification, Slowloris, DNS and ICMP tunnelling, rogue IPv6 routers, VLAN hopping, LLMNR/NBT-NS poisoning, forged TCP resets, forged ICMP redirects, password guessing, MAC flooding, parser evasion, beaconing, algorithm-generated domains, and possible data theft.

## Run it

You need Node 20 or later and pnpm. Nothing else, and no account.

On Windows, clone to a short path such as `C:\dev\packetmd`. Very long paths can break the test runner.

```bash
pnpm i
pnpm dev
```

Open http://localhost:3000 and choose **Try the mixed incident**.

Command line:

```bash
pnpm cli samples/mixed-incident.pcap
pnpm cli analyze samples/arp-spoof.pcap --level analyst
pnpm cli locate samples/arp-spoof.pcap --packet 137
```

Tests and checks:

```bash
pnpm test
pnpm accuracy
pnpm handshake
```

Regenerating the captures needs Python and Scapy: `pip install scapy`, then `python labgen/generate.py`, `python labgen/hostile.py` and `python labgen/truth.py`. Add `--large` to the first command for a 30 MB capture.

## Architecture

```
Browser (your device)                                     Supabase (optional)
+---------------------------------------+                +----------------------+
| Intake gate: extension + magic bytes  |                | Auth, Postgres + RLS |
|   | File.slice chunks                 |   findings     | Edge Function        |
|   v                                   |   only, with   | share-report:        |
| Sandboxed Web Worker                  |   addresses    | zod, size cap,       |
|  connect-src 'none': it cannot call   |   replaced     | rate limit           |
|  out, even if a parser bug is hit     | -------------> |                      |
|  parse > decode > flows > detectors   |   only if you  +----------------------+
|  > verdict > explain                  |   choose to
|   | plain JSON                        |   share
|   v                                   |
| React UI: inert text rendering only   |
+---------------------------------------+
CLI (Node): same engine, packages/core
```

| Path | What it is |
|---|---|
| `packages/core` | The engine, with no runtime dependencies |
| `packages/cli` | Command line tool |
| `apps/web` | Next.js app |
| `labgen` | Sample and hostile capture generators |
| `samples` | Lab captures and ground truth |
| `supabase` | Migrations and the share function |

## Security model

- **Allowlist intake.** Only `.pcap` and `.pcapng`, and the extension and magic bytes must agree.
- **Budgets.** File size, packets, packet length, parse time, flow table, string length and DNS compression depth are all capped in `packages/core/src/thresholds.ts`.
- **Own bounds-checked parser.** Files are streamed. Bad packets are counted and skipped, and malformed structures become `parser-evasion` findings.
- **Sandboxed Worker.** It is served with `connect-src 'none'`, and the Security page proves this by having the Worker try the network. The browser console shows that blocked request as an error: it is expected.
- **Inert rendering.** Packet-derived text passes `safeText()` and renders as React text nodes. A lint rule bans `dangerouslySetInnerHTML`. Exports neutralise formula injection.
- **Site headers.** Per-request nonce CSP with no `unsafe-eval` in production, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, HSTS and COOP.
- **Passwords.** New accounts need 12 or more characters with mixed case, a number and a symbol, and cannot use runs, common words or the email name. The rule is in `packages/core/src/password.ts` and is checked live as you type. The same minimums must also be set in Supabase Auth, because a browser check alone can be bypassed.
- **Temporary emails.** Throwaway addresses are refused in the sign-up form and again by a database trigger, so the sign-up API cannot be used to get around the form. The blocklist cannot catch every such service.
- **Backend.** RLS on every table, owner-only access, no raw payload columns and no client-side way to change a role. Guests have no direct table access. The share function validates with zod, caps body size and rate-limits. The Supabase security advisor's one open item is leaked-password protection, an Auth setting.
- **No hardcoded secrets.** Only `.env.example` is tracked, and the anon key is public by design. Gitleaks is part of the CI workflow, kept at `docs/ci.yml` until it is enabled under `.github/workflows/`.
- **No LLM** is called on user data. Explanations come from deterministic templates.

### Roles

Scanning needs no account. Signed-in **Analysts** see only their own reports. **Admins** also see team feedback and saved report counts. RLS enforces this in the database, not the page. To promote a user, run this in the Supabase SQL editor:

```sql
update public.profiles set role = 'admin' where id = '<user id>';
```

## Measured accuracy

From `pnpm accuracy` on 25 lab captures, 6 of them clean or benign look-alikes:

| Precision | Recall | False-alarm rate |
|---|---|---|
| 1.0 | 1.0 | 0.0 |

**Read this with care.** We generated these captures ourselves and tuned the thresholds on them, so this shows the logic works as designed. It does not predict results on real networks. The per-file table is on the Methodology page.

### Attacking our own detectors

Lab scores on tuned captures prove little, so we built captures designed to evade each check (`labgen/evasion.py`) and clean look-alikes that must stay quiet.

| Round | Result |
|---|---|
| First evasion round, before any fixes | 8 of 26 caught, 1 false alarm on 7 look-alikes |
| First held-out round (`labgen/blind.py`), written after those fixes, run untuned | **5 of 11 caught** |
| Second held-out round (`labgen/blind2.py`), written after the next fixes, run untuned | **2 of 12 caught, 4 false alarms on 6 look-alikes** |
| All 49 attacks plus 16 look-alikes after fixing, now permanent tests | 49 of 49 caught, 15 of 16 quiet |

The held-out rounds are the honest numbers here: 7 of 23 attacks caught when nobody had tuned for them, about 30%. The second round was worse because it tried attack families the engine had never modelled, and 3 of its 4 false alarms came from detectors added the round before. Passing every test now shows those cases are fixed. It does not show a new technique would be caught. The remaining false alarm is a known limit: an app calling an unnamed host on a fixed timer reads as beaconing, because the capture looks the same. Run `npx tsx scripts/evasion.ts evasion`, `blind` or `blind2` to see each round. Volume attacks on the engine itself are covered by `tests/stress.test.ts`, which also found and fixed a real crash.

A capture also has limits. PacketMD cannot see inside encrypted traffic, cannot tell a large backup from data theft (it reports Inconclusive), does not read application payloads for attacks such as SQL injection, and sees only the part of the network the capture covers. A VPN keepalive and a UDP beacon look alike, so those stay Inconclusive. A clean report means nothing we know how to see, never that a network is safe.

Our parser's packet count, addresses and ports are checked against Scapy on every sample. Tests also confirm that recorded offsets reproduce the exact file bytes, and fuzzing checks that mutated samples never cause an unhandled error.

## Limitations

- A capture holds no process names or user accounts, so traffic classes are inferences with the basis shown, and PacketMD never names a process or a person.
- Encrypted names (ECH, DoH, DoT) are reported as hidden, not guessed.
- A single capture cannot always separate a spoof from a failover. That is what the baseline and Inconclusive are for.
- TCP streams are not reassembled across packets for TLS or HTTP parsing, so a Client Hello split over two packets gives no SNI.
- Thresholds are tuned on lab traffic and will need adjustment on busy real networks.
- 802.11, TLS decryption and live capture are out of scope.
- Not built: TCP time-sequence graph, packet and flow diff, export of a selection as pcap, saved filters, bookmarks, column show and hide, list sorting, pin and hide noise, hex-to-field selection, Learn glossary, online reputation lookup (the app states offline checks only), JA3 family matching, attribution accuracy scoring, and a public Storage bucket for samples (samples ship with the app instead).
- Password complexity is enforced in the browser. The same minimums must also be set in Supabase Auth.

## Libraries and APIs

Parsing, decoding, detection and diagnosis are our own code. Wireshark, tshark, Zeek and Suricata are not used or wrapped.

| Library or API | Used for | License |
|---|---|---|
| Next.js | Web framework | MIT |
| React, React DOM | Interface | MIT |
| Tailwind CSS | Styling base | MIT |
| Lenis | Smooth scrolling | MIT |
| @supabase/supabase-js | Optional accounts and share links | MIT |
| Supabase (Auth, Postgres, Edge Functions) | Optional backend | Hosted service |
| Zod | Validation in the Edge Function | MIT |
| Scapy | Generates lab captures, in `labgen/` only | GPL-2.0 |
| Vitest | Tests | MIT |
| esbuild, tsx, TypeScript, ESLint, typescript-eslint | Build and tooling | MIT, Apache-2.0 |
| Big Shoulders, Hanken Grotesk, JetBrains Mono | Fonts, self-hosted at build time | SIL OFL 1.1 |
| Dot Cursor and Click Effect | Interaction ideas from the supplied component file, rebuilt in the canvas layer | Hackathon-supplied |

## Responsible use

Analyse only captures you are authorised to inspect. Every sample here was generated in a lab, and no real network was captured.
