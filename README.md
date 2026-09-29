# PacketQuest

**Learn to read packet captures the way an analyst does.** Drop a `.pcap` / `.pcapng` / `.cap` file exported from Wireshark (or pick a built-in sample) and PacketQuest turns *your* traffic into an animated quiz game: find the handshake, decode the DNS answer, locate the SNI byte-for-byte, spot the port scan. Every answer comes with an explanation tied to the exact fields and bytes involved.

Aimed at Security+ / Network+ learners and early SOC analysts.

- **Private by design.** Captures are parsed entirely in your browser, in a Web Worker. No packet data is uploaded anywhere; after page load the app makes no network requests (fonts are bundled locally).
- **Analyst terminal UI.** Three retro monitor themes selectable in the header or config: amber phosphor (default), green phosphor, and paper (light, line-printer look). Optional CRT scanlines. IBM Plex Mono font throughout, VT323 for the wordmark; both bundled locally. Design rules in [docs/STYLE.md](docs/STYLE.md).
- **Wireshark feel.** Packet list with Wireshark-style coloring, a collapsible details tree, and a hex/ASCII pane with two-way highlighting. Plus a display-filter bar, Conversations, Follow Stream and an animated flow (ladder) diagram.
- **Ten game modes**, generated from whatever you load (see below), with XP, streaks, ranks, weak-area tracking and a session summary.

## Quick start

```bash
npm install
npm run dev        # http://localhost:5173
```

| Command | What it does |
| --- | --- |
| `npm run dev` | Vite dev server |
| `npm run build` | Type-check and build the production bundle into `dist/` |
| `npm test` | Vitest suite: parser, dissectors, filters, heuristics, generators, performance |
| `npm run samples` | Regenerate the sample captures in `samples/` |
| `npm run typecheck` | `tsc -b` only |
| `npm run lint` | oxlint |

Requires Node 20+. Works in current Chrome, Firefox, Safari and Edge, on desktop and phones.

## What it understands

**Containers:** classic PCAP in both byte orders (`0xa1b2c3d4` / `0xd4c3b2a1`), the nanosecond variant (`0xa1b23c4d`) and the modified-PCAP header; PCAPNG with Section Header, Interface Description (multiple interfaces, per-interface link type, `if_tsresol`, `if_tsoffset`), Enhanced, Simple and obsolete Packet Blocks.

**Link types:** Ethernet (1, including 802.1Q/QinQ), Linux cooked SLL (113) and SLL2 (276), raw IP (101/228/229) and BSD loopback/null (0).

**Protocols** (every field carries its byte offset and length):

| Layer | Protocols |
| --- | --- |
| 2 | Ethernet II, 802.1Q VLAN, ARP (including gratuitous ARP) |
| 3 | IPv4 (flags, TTL, fragmentation, checksum verification), IPv6 (extension headers), ICMP, ICMPv6 |
| 4 | TCP (flags, relative seq/ack, window, MSS/SACK/WS/timestamp options), UDP |
| 7 | DNS (queries, answers, record types, rcodes, compression, DNS-over-TCP), HTTP/1.x, TLS (records, ClientHello SNI/cipher suites/supported versions/ALPN, ServerHello chosen suite, alerts), DHCP (DORA and options), FTP, Telnet, SMTP, POP3 and IMAP command lines, SSH banner, NTP, SNMP basics |
| — | Anything else becomes `Data`; malformed or truncated frames are marked `[Malformed Packet]` and never crash the app |

**Cleartext credentials** (FTP USER/PASS, HTTP Basic, IMAP LOGIN, SMTP AUTH PLAIN, and Telnet logins reassembled from keystroke packets) are flagged as teaching moments. Secrets are masked in the list, tree, hex pane, stream view and every question until you press **Reveal**.

**Display filters:** a Wireshark subset — `ip.addr/src/dst` (including CIDR), `ipv6.addr` (including IPv6 prefixes), `tcp.port`, `udp.port`, `tcp.flags` (numeric, e.g. `== 0x12`) and `tcp.flags.syn/ack/fin/reset/push`, `tcp.stream`/`udp.stream` (numbered per protocol, as in Wireshark), protocol names (`dns`, `http`, `tls`, `arp`, …), `dns.qry.name`, `dns.qry.type` (`== 28` or `== AAAA`), `http.response.code`, `frame.len` and more; operators `== != > < >= <= contains` (and `eq`/`ne`/…); combinators `&& || ! and or not ( )`. As in Wireshark, text comparisons are case-sensitive (addresses are not), and `a != b` never matches packets that lack the field. Unsupported syntax gets a friendly error with suggestions.

## Game modes

| | Mode | What you do |
| --- | --- | --- |
| A | Which Line Is It? | Read a plain-English description and click the matching row. Some questions are multi-select, e.g. "all three handshake packets". |
| B | What Is This Line Saying? | One packet is highlighted; pick its literal meaning from 4 options |
| C | What Does It Mean? | Analyst interpretation: NXDOMAIN, handshake RTT, SNI leakage, scan and flood intent, forwarded TTLs, … |
| D | Field Hunt | Click the exact field in the tree, or its bytes in the hex pane. The right data in the wrong container earns partial credit. |
| E | Put It In Order | Drag shuffled cards (DNS → SYN → SYN-ACK → … → FIN) into wire order |
| F | Spot the Anomaly | Identify the attack, find evidence, choose the next step. Only asked when a heuristic actually detected it. |
| G | Story Mode | A narrated, packet-by-packet walkthrough with quick checks |
| H | Type the Answer | Read a value from the capture (TTL, port, domain, resolved IP, status code, SNI, cipher suite, DHCP-offered IP, FTP username, impostor MAC, scan counts) and type it. Numbers, IPs and MACs are normalised, and a pasted URL counts for a host name. Small letter typos are forgiven, but a digit typo never is; cipher-suite names are checked token by token. |
| I | Filter Forge | Write a display filter. It is compiled and dry-run on every keystroke (matches / right / extra / missing), graded on exactly which frames it matches: exact = full credit; half credit when at least 80% of the matches are right and at least 80% of the target is found. A reference filter is shown afterwards. |
| J | Keystroke Drill | 60-second typing drill on terms, filter fields and values from the loaded capture. Per-character feedback, live WPM/accuracy, best WPM saved, XP awarded (capped at 120). |
| ⏱ | Blitz | 60 seconds, as many as you can |

Ranks run **Recruit → Analyst (250 XP) → Hunter (700 XP) → Threat Hunter (1500 XP)**. Recruit unlocks A, B, E, G, H, J; Analyst unlocks C, D, I; Hunter unlocks F and Blitz. XP scales with difficulty tier, speed and streak; a hint halves it. Concepts you miss come up more often. Settings → *Unlock all modes* for instructors. Progress lives in `localStorage` (the app still works if storage is blocked) and can be exported/imported as JSON or reset.

## Keyboard

**Start screen:** `1–8` loads a sample, `o` opens the file picker. **Console:** letter keys start modes (`m` mixed, `a–j` modes A–J, `z` blitz); `1–4` answer multiple-choice; `↵` submits; `n` goes to the next case; `?` shows a hint (−50% XP); `/` focuses the display filter; `↑/↓` move the packet list; `←/→` step through Story Mode; `esc` restarts a drill. Single-key shortcuts can be switched off in settings (`cfg`).

## Samples

Eight synthetic captures are generated programmatically (`src/samples/samples.ts`) and also committed under `samples/`, so you can open them in Wireshark too. All eight parse cleanly in an independent parser (dpkt) with valid IP/TCP/UDP checksums.

| File | Tier | What you'll learn |
| --- | --- | --- |
| `01-web-basic.pcap` | Recruit | DNS → TCP handshake → HTTP GET/200 (and a 404) → FIN teardown |
| `02-https-visit.pcapng` | Recruit | TLS 1.3 ClientHello/ServerHello; SNI leaks the site name |
| `03-dhcp-arp.pcap` | Recruit | DHCP DORA, gratuitous ARP, resolving the gateway, ping |
| `04-ftp-login.pcap` | Analyst | Cleartext USER/PASS, a failed and a successful login |
| `05-syn-scan.pcap` | Analyst | Nmap-style SYN scan: RST/ACK from closed ports, SYN-ACK+RST on open ones |
| `06-arp-spoof.pcap` | Hunter | Two MACs claiming the gateway IP; forwarded traffic with TTL−1 |
| `07-dns-tunnel.pcap` | Hunter | Long, high-entropy subdomains and TXT queries |
| `08-syn-flood.pcap` | Hunter | 120 SYNs from spoofed sources, almost no completed handshakes |

## Architecture

```
File ─▶ Web Worker ─────────────────────────────────────────────▶ main thread
        container.ts   parse PCAP/PCAPNG → RawRecord[] (offsets into the buffer)
        dissect/*      frame → Field tree + PacketFacts + Info/Protocol/color
        indexer.ts     PacketSummary[] (facts only, no trees), relative TCP seq,
                       conversations.ts (5-tuple streams, handshake/teardown state)
                       anomalies.ts (scan, flood, ARP spoof, creds, tunnel, …)
        ── summaries streamed back in 2,000-packet chunks ──
main    store/capture  keeps the file bytes; re-dissects any packet on demand
                       (cached) for the details tree / hex pane / field hunt
        game/engine    GenCtx → generators → validate → QuestionBank → decks
        ui/*           panes, flow view, game panel (React + Framer Motion)
```

1. **Parser → index.** The worker does one pass: container records, full dissection of each frame to extract `PacketFacts` (TCP flags, DNS names, TLS SNI, DHCP type, credentials, …), then conversations and anomaly heuristics. Field trees are thrown away and rebuilt lazily on the main thread for whichever packet you look at, so large captures stay light. A 20 MB / 23k-packet capture indexes in about 1 s, and the UI never blocks for long.
2. **Index → generators.** `game/knowledge.ts` classifies each packet into a teaching *kind* (`tcp-synack`, `dns-nxdomain`, `tls-ch`, …). Each kind carries a literal statement, a meaning template, an analyst "why it matters" line, RFC detail and a list of *confusables*. Generators query the index and fill templates with real values from the capture.
3. **Generators → game.** Every question passes `validateQuestion`: frames exist, and multiple-choice options are within 25% of each other in length, with the correct one no more than 3 characters longer than the longest distractor. Short options are padded with neutral phrases, and never only the wrong ones; if that isn't enough the question is dropped. Decks are sampled with weights that favour weak concepts and are ordered Recruit → Hunter.

### Adding a protocol dissector

1. Create a function in `src/core/dissect/` that takes `(ctx, offset, length)`, calls `layer(ctx, name, key, offset, length)`, and adds fields with `add(parent, label, key, value, offset, length)`. Offsets are relative to the frame start, which is what makes hex highlighting work.
2. Record anything games or filters need in `ctx.facts` (extend `PacketFacts` in `src/core/types.ts`), and set `ctx.protocol`, `ctx.info` and `ctx.color`.
3. Dispatch to it by port or heuristic in `dissectTcpApp` / `dissectUdpApp` in `src/core/dissect/index.ts`.
4. Optionally expose filter fields in `FIELDS` (`src/core/filter/filter.ts`), and add a test in `tests/dissect.test.ts` asserting offsets against known bytes.

### Adding a question generator

1. If the packet type is new, add a `Kind` to `src/game/knowledge.ts`, with `classify` logic, a `statement`, `means`, `matters`, `deeper` and `confusables`. Write the statement to be role-generic and similar in length to its confusables.
2. Add a `Generator` to the relevant file in `src/game/generators/`: `{ id, mode, needs, generate(ctx) }`. Use `ctx.of(kind)`, `ctx.index.conversations`, `ctx.findField(no, key)`, and the `choice()` helper, which balances and shuffles options. **Typing mode** (mode H) generators live in `src/game/generators/typed.ts`. **Filter mode** (mode I) generators declare a `select(packet)` predicate and a `reference` filter string; any challenge whose reference doesn't match the predicate's frames exactly is dropped. See `src/game/generators/filters.ts`.
3. Register it in `ALL_GENERATORS` (`src/game/engine.ts`). `tests/generators.test.ts` then runs it against every sample: it must fire on at least one, produce valid questions, grade its own answers as correct, and never leak a secret.

### Optional AI explain hook

Off by default and not connected to any provider. A build can call `registerAiProvider(fn)` (`src/game/ai.ts`); once the learner also enables *AI explain* in Settings, an explanation card shows a clearly labelled **external** button. It sends only the already-masked text summary, never raw packets.

## Working on this repo with Claude

See [CLAUDE.md](CLAUDE.md) for codebase architecture and local setup. The project includes subagents for specialized tasks in `.claude/agents`:

| Agent | Model | Role |
| --- | --- | --- |
| ui-reskin | Sonnet | Restyles UI components from a brief |
| test-writer | Sonnet | Writes Vitest tests and reports src bugs instead of editing src |
| browser-check | Haiku | Runs Playwright smoke tests and screenshots |
| docs-writer | Haiku | Makes doc edits |

Architecture and core logic stay with the main (Opus) session.

## Tests

`npm test` runs 7 files and 305 tests:

- **Parser:** both endians, nanosecond timestamps, PCAPNG multi-interface with different resolutions, SPB, truncation and corruption handling.
- **Dissectors:** field offsets checked against a hand-assembled SYN frame and constructed DNS/TLS/HTTP/FTP/DHCP/ARP/ICMP/IPv6/SLL/SLL2/null/VLAN frames; byte→field mapping.
- **Filters:** semantics and error messages.
- **Heuristics:** exactly the planted anomalies are found on each sample, with no false positives on the normal captures; Telnet credentials are reassembled from keystrokes.
- **Generators:** at least 15 valid questions and at least 3 modes per sample, option balance, self-grading, secret masking, and weak-concept weighting.
- **Typing modes:** gradeText normalisation and typo rules, every sample's text/filter questions self-grade, invalid filters score 0 without throwing, drill word lists and WPM maths.
- **Performance:** a 20 MB capture indexes in under 10 s (about 1 s in practice).
