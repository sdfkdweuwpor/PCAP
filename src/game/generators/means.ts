// Mode C — "What Does It Mean?": analyst-level interpretation questions.

import { entropy } from '../../core/bytes'
import { short } from '../knowledge'
import type { ChoiceQuestion, Concept, Explanation, Tier } from '../types'
import { choice, GenCtx, notNull, type Generator } from './context'

interface MeansSpec {
  id: string
  tier: Tier
  concept: Concept
  prompt: string
  hint: string
  correct: string
  distractors: string[]
  explanation: Explanation
  packets: number[]
  focus?: number
}

function means(ctx: GenCtx, s: MeansSpec): ChoiceQuestion | null {
  return choice(
    ctx,
    {
      id: s.id,
      mode: 'means',
      tier: s.tier,
      concept: s.concept,
      prompt: s.prompt,
      hint: s.hint,
      explanation: s.explanation,
      highlight: s.packets.map((packet) => ({ packet })),
      focusPacket: s.focus ?? s.packets[0],
    },
    s.correct,
    s.distractors,
  )
}

const gen = (id: string, needs: string, f: (ctx: GenCtx) => MeansSpec | null): Generator => ({
  id,
  mode: 'means',
  needs,
  generate: (ctx) => {
    const s = f(ctx)
    return [s && means(ctx, s)].filter(notNull)
  },
})

export const meansGenerators: Generator[] = [
  gen('means.nxdomain', 'an NXDOMAIN response', (ctx) => {
    const p = ctx.of('dns-nxdomain')[0]
    if (!p) return null
    return {
      id: `means.nxdomain:${p.no}`,
      tier: 'Analyst',
      concept: 'dns',
      prompt: `Packet #${p.no} says "No such name" for ${short(p.facts.dns!.qname, 40)}. What does NXDOMAIN tell you?`,
      hint: 'RCODE 3 is an authoritative answer, not a failure to answer.',
      correct: 'The name does not exist, so the client cannot reach it by name.',
      distractors: [
        'The DNS server is down and quietly dropped the client query.',
        'A firewall rule blocked the client from reaching that site.',
        'The name exists but has no IPv6 address, only an IPv4 one.',
      ],
      explanation: {
        ...ctx.explain(p.no),
        means: 'The resolver authoritatively says the domain is not registered. The client gets no address and gives up (or tries a search suffix).',
      },
      packets: [p.no],
    }
  }),
  gen('means.rtt', 'a complete TCP handshake', (ctx) => {
    const c = ctx.index.conversations.find((c) => c.handshake?.syn && c.handshake.synAck)
    if (!c) return null
    const syn = ctx.pkt(c.handshake!.syn!)
    const sa = ctx.pkt(c.handshake!.synAck!)
    const ms = ((sa.relTime - syn.relTime) * 1000).toFixed(1)
    return {
      id: `means.rtt:${c.id}`,
      tier: 'Analyst',
      concept: 'tcp-handshake',
      prompt: `The SYN (#${syn.no}) and the SYN-ACK (#${sa.no}) are ${ms} ms apart. What does that gap mostly measure?`,
      hint: 'The server answers a SYN almost instantly; what dominates is travel time.',
      correct: 'The network round-trip time between the two hosts.',
      distractors: [
        'How long the server took to build the web page.',
        'The time the DNS lookup needed to resolve the name.',
        'The delay a client waits before resending lost data.',
      ],
      explanation: {
        says: `SYN at ${syn.relTime.toFixed(3)} s, SYN-ACK at ${sa.relTime.toFixed(3)} s.`,
        means: `The kernel answers a SYN immediately, so ~${ms} ms is the time for a packet to reach ${c.b.addr} and come back: the RTT.`,
        matters: 'Handshake RTT is a quick latency baseline; unusually high or jittery RTT can reveal congestion or traffic being routed through an interceptor.',
        deeper: 'Wireshark shows this as tcp.analysis.initial_rtt (SYN → ACK). Since the capture was taken at the client, SYN → SYN-ACK is the network RTT.',
      },
      packets: [syn.no, sa.no],
      focus: sa.no,
    }
  }),
  gen('means.cleartext', 'cleartext credentials', (ctx) => {
    const p = ctx.packets.find((x) => x.facts.creds?.secret)
    if (!p) return null
    return {
      id: `means.cleartext:${p.no}`,
      tier: 'Analyst',
      concept: 'cleartext',
      prompt: `Packet #${p.no} is a ${p.facts.creds!.proto} login. Why is this login a security problem?`,
      hint: 'Look at the bytes pane. Can you read them?',
      correct: 'Anyone on the network path can read the password as plain text.',
      distractors: [
        'The server will lock the account after too many failed attempts.',
        'The password is too short to satisfy the company password policy.',
        'The client connected to the file server on the wrong TCP port.',
      ],
      explanation: {
        ...ctx.explain(p.no),
        means: `${p.facts.creds!.proto} has no encryption, so the password bytes appear verbatim in the capture — reveal them in the details pane to see.`,
        matters: 'Any sniffer, compromised switch or malicious Wi-Fi hotspot on the path now has a working password. Use SFTP/FTPS/HTTPS instead.',
      },
      packets: [p.no],
    }
  }),
  gen('means.sni', 'a TLS ClientHello with SNI', (ctx) => {
    const p = ctx.of('tls-ch').find((x) => x.facts.tls?.sni)
    if (!p) return null
    return {
      id: `means.sni:${p.no}`,
      tier: 'Analyst',
      concept: 'tls',
      prompt: `This session is encrypted with TLS. What can an eavesdropper still learn from packet #${p.no}?`,
      hint: 'The ClientHello is sent before any keys exist.',
      correct: 'Which website the client is visiting, from the SNI field.',
      distractors: [
        'The full URL path and the query string being requested.',
        'The username and the password typed into the web page.',
        'The HTML content of the page that the server sends back.',
      ],
      explanation: {
        ...ctx.explain(p.no),
        means: `The Server Name Indication extension carries "${p.facts.tls!.sni}" in cleartext so the server can pick the right certificate.`,
        matters: 'Firewalls and analysts use SNI to see (and block) destinations without decrypting; Encrypted Client Hello (ECH) is designed to hide it.',
      },
      packets: [p.no],
    }
  }),
  gen('means.cipher', 'a TLS ServerHello', (ctx) => {
    const p = ctx.of('tls-sh').find((x) => x.facts.tls?.chosenCipher)
    if (!p) return null
    return {
      id: `means.cipher:${p.no}`,
      tier: 'Analyst',
      concept: 'tls',
      prompt: `In packet #${p.no} the server chose ${p.facts.tls!.chosenCipher}. What does that choice decide?`,
      hint: 'The client offered a list; the server picks exactly one.',
      correct: 'Which algorithms will encrypt and protect this session.',
      distractors: [
        'Which website the client is trying to reach by its name.',
        'Which authority signed the certificate of the server.',
        'Which HTTP version the browser and server will speak.',
      ],
      explanation: {
        ...ctx.explain(p.no),
        means: 'The cipher suite fixes the bulk encryption (e.g. AES-128-GCM) and hash (SHA-256) used for the rest of the session.',
      },
      packets: [p.no],
    }
  }),
  gen('means.scan', 'a port scan', (ctx) => {
    const a = ctx.index.anomalies.find((x) => x.kind === 'port-scan')
    if (!a) return null
    return {
      id: 'means.scan',
      tier: 'Hunter',
      concept: 'recon',
      prompt: `Why might ${a.evidence.scanner} send SYNs to ${a.evidence.ports} different ports on ${a.evidence.target}?`,
      hint: 'Each SYN goes to a different port and none of them carries data.',
      correct: 'It is mapping which services are open: a port scan.',
      distractors: [
        'It keeps retrying one connection that fails each time.',
        'It is downloading a large file in many parallel parts.',
        'It is the normal way a web browser loads a website.',
      ],
      explanation: {
        says: a.detail,
        means: 'A SYN per port, then a reset, is a "half-open" (SYN/stealth) scan: the scanner learns open vs closed without completing connections.',
        matters: 'Scans are reconnaissance — often the first stage of an attack. Note which ports answered: those are what the attacker will try next.',
        deeper: 'nmap -sS sends SYN; SYN-ACK = open, RST = closed, no answer = filtered. The scanner then sends RST instead of the final ACK.',
      },
      packets: a.packets.slice(0, 6),
    }
  }),
  gen('means.rst-closed', 'SYNs refused with RST', (ctx) => {
    const rs = ctx.of('tcp-rst-closed')
    if (rs.length < 3) return null
    const p = rs[0]
    return {
      id: `means.rst-closed:${p.no}`,
      tier: 'Analyst',
      concept: 'recon',
      prompt: `${p.facts.ip!.src} answers many SYNs with RST, ACK (e.g. #${p.no}). What does that tell the sender?`,
      hint: 'RST in reply to a SYN is the TCP way of saying “no”.',
      correct: 'Those ports are closed; no service listens on them.',
      distractors: [
        'Those ports are open and ready to accept the data.',
        'A firewall silently dropped all of the probe packets.',
        'The target ran out of memory and is now restarting.',
      ],
      explanation: ctx.explain(p.no),
      packets: [p.no],
    }
  }),
  gen('means.scan-rst', 'a scanner resetting open ports', (ctx) => {
    if (!ctx.index.anomalies.some((a) => a.kind === 'port-scan')) return null
    const rst = ctx.of('tcp-rst').find((p) => {
      const c = ctx.kb.conv(p)
      return c && c.handshake?.synAck !== undefined && c.handshake.ack === undefined
    })
    if (!rst) return null
    return {
      id: `means.scan-rst:${rst.no}`,
      tier: 'Hunter',
      concept: 'recon',
      prompt: `In #${rst.no} the scanner sends RST right after the target's SYN-ACK. Why not finish the handshake?`,
      hint: 'What did the scanner already learn from the SYN-ACK?',
      correct: 'It already knows the port is open and wants no connection.',
      distractors: [
        'The SYN-ACK arrived damaged, so the scanner must start over.',
        'Resetting is the normal way for TCP to begin sending data.',
        'The target asked the scanner to slow down its probes.',
      ],
      explanation: {
        ...ctx.explain(rst.no),
        means: 'A SYN scan never completes connections: the SYN-ACK proves the port is open, and the RST avoids leaving a logged, established session.',
      },
      packets: [rst.no],
    }
  }),
  gen('means.syn-flood', 'a SYN flood', (ctx) => {
    const a = ctx.index.anomalies.find((x) => x.kind === 'syn-flood')
    if (!a) return null
    return {
      id: 'means.syn-flood',
      tier: 'Hunter',
      concept: 'dos',
      prompt: `${a.evidence.syns} SYNs hit ${a.evidence.target} from ${a.evidence.sources} addresses and almost none finish. What is the goal?`,
      hint: 'The handshakes are started but never completed, and every source is different.',
      correct: "Exhaust the server's half-open connection table (a DoS).",
      distractors: [
        'Discover which ports on the server are open (a scan).',
        'Spread normal users across several servers (balancing).',
        'Resume downloads that were cut off earlier (recovery).',
      ],
      explanation: {
        says: a.detail,
        means: 'Each SYN makes the server allocate state and send a SYN-ACK to a spoofed address that never replies, filling the backlog so real users can’t connect.',
        matters: 'Mitigations include SYN cookies, backlog tuning, rate limiting and upstream DDoS scrubbing.',
        deeper: 'RFC 4987 describes SYN flooding and defenses. High, random TTLs and random source IPs are typical of spoofed traffic.',
      },
      packets: a.packets.slice(0, 6),
    }
  }),
  gen('means.arp-spoof', 'ARP spoofing', (ctx) => {
    const a = ctx.index.anomalies.find((x) => x.kind === 'arp-spoof')
    if (!a) return null
    return {
      id: 'means.arp-spoof',
      tier: 'Hunter',
      concept: 'mitm',
      prompt: `${a.evidence.attackerMac} keeps saying "${a.evidence.ip} is at" its own MAC. What is the likely effect?`,
      hint: 'Hosts cache ARP replies even when they did not ask.',
      correct: 'Victims send the traffic for that IP to the attacker.',
      distractors: [
        'The gateway receives a new IP address from DHCP.',
        "The victim's DNS lookups start failing entirely.",
        'Nothing: hosts ignore replies they never asked for.',
      ],
      explanation: {
        says: a.detail,
        means: 'The poisoned ARP cache maps the gateway IP to the attacker’s MAC, so the victim’s frames go to the attacker, who can read or modify them and forward them on.',
        matters: 'This is a classic man-in-the-middle. Dynamic ARP Inspection (DAI) on switches and static ARP for critical hosts prevent it.',
        deeper: 'RFC 826 has no authentication; most OSes accept unsolicited replies and overwrite existing cache entries.',
      },
      packets: a.packets.slice(0, 6),
    }
  }),
  gen('means.forwarded-ttl', 'duplicate packets with TTL decremented', (ctx) => {
    const reqs = ctx.of('icmp-echo-req')
    for (let i = 0; i + 1 < reqs.length; i++) {
      const a = reqs[i]
      const b = reqs[i + 1]
      if (b.relTime - a.relTime < 0.05 && a.facts.ip!.src === b.facts.ip!.src && a.facts.ip!.ttl - b.facts.ip!.ttl === 1) {
        return {
          id: `means.forwarded-ttl:${a.no}`,
          tier: 'Hunter',
          concept: 'mitm',
          prompt: `The same ping appears twice: #${a.no} with TTL ${a.facts.ip!.ttl}, then #${b.no} with TTL ${b.facts.ip!.ttl}. What does that suggest?`,
          hint: 'Compare the Ethernet source and destination MACs of the two copies.',
          correct: 'Another host on the LAN is forwarding (routing) the traffic.',
          distractors: [
            'The client resent the ping because the first copy was lost.',
            'The switch duplicates every frame it forwards, by design.',
            'The ping reached the Internet and was bounced back to us.',
          ],
          explanation: {
            says: `#${a.no}: TTL ${a.facts.ip!.ttl}, Ethernet ${a.facts.eth?.src} → ${a.facts.eth?.dst}; #${b.no}: TTL ${b.facts.ip!.ttl}, Ethernet ${b.facts.eth?.src} → ${b.facts.eth?.dst}.`,
            means: 'Each router hop decrements TTL by one. A second copy one hop lower, sent by a different MAC, means a host in the middle received and re-sent it.',
            matters: 'Seeing your own traffic re-emitted by an unexpected MAC is strong evidence of an ARP-spoofing man-in-the-middle.',
            deeper: 'RFC 791: TTL is decremented by every forwarding node; switches (layer 2) never change it.',
          },
          packets: [a.no, b.no],
        }
      }
    }
    return null
  }),
  gen('means.dns-tunnel', 'DNS tunneling', (ctx) => {
    const a = ctx.index.anomalies.find((x) => x.kind === 'dns-tunnel')
    if (!a) return null
    const p = ctx.pkt(a.packets[0])
    return {
      id: 'means.dns-tunnel',
      tier: 'Hunter',
      concept: 'exfil',
      prompt: `What is suspicious about queries like ${short(p.facts.dns!.qname, 36)} (#${p.no})?`,
      hint: 'Would a human ever type that hostname?',
      correct: 'Data is being smuggled out inside long random subdomains.',
      distractors: [
        'The client is using a slow DNS server that is very far away.',
        'The domain is brand new, so its records are not cached yet.',
        'The queries ask for TXT records, which are always malicious.',
      ],
      explanation: {
        says: a.detail,
        means: `The subdomain labels (entropy ≈ ${entropy(p.facts.dns!.qname.split('.')[0]).toFixed(1)} bits/char) look like base32-encoded data; the attacker’s name server for ${a.evidence.domain} decodes them and replies in TXT records.`,
        matters: 'DNS is allowed out of almost every network, making it a favourite covert channel for exfiltration and C2.',
        deeper: 'Tools like iodine and dnscat2 encode data in QNAMEs (max 63 bytes/label, 253/name) and receive data in TXT/NULL/CNAME answers.',
      },
      packets: a.packets.slice(0, 4),
    }
  }),
  gen('means.dhcp-broadcast', 'a DHCP Discover', (ctx) => {
    const p = ctx.of('dhcp-discover')[0]
    if (!p || p.facts.ip?.src !== '0.0.0.0' || p.facts.ip.dst !== '255.255.255.255') return null
    return {
      id: `means.dhcp-broadcast:${p.no}`,
      tier: 'Recruit',
      concept: 'dhcp',
      prompt: `Why is the DHCP Discover (#${p.no}) sent from 0.0.0.0 to 255.255.255.255?`,
      hint: 'What does the client know at this moment?',
      correct: "The client has no IP yet and doesn't know the server.",
      distractors: [
        'Broadcasting makes the request travel much faster.',
        'DHCP servers only accept traffic from 0.0.0.0 hosts.',
        'The client is trying to hide its real IP address.',
      ],
      explanation: {
        ...ctx.explain(p.no),
        means: 'With no address and no idea where the server is, the client uses 0.0.0.0 as source and the limited broadcast address so every host on the LAN — including any DHCP server — hears it.',
      },
      packets: [p.no],
    }
  }),
  gen('means.gratuitous', 'a gratuitous ARP', (ctx) => {
    const p = ctx.of('arp-gratuitous')[0]
    if (!p) return null
    return {
      id: `means.gratuitous:${p.no}`,
      tier: 'Analyst',
      concept: 'arp',
      prompt: `In #${p.no} the host sends an ARP about its own address ${p.facts.arp!.senderIp}. Why?`,
      hint: 'Sender IP and target IP are the same.',
      correct: 'To announce itself and detect another host using the IP.',
      distractors: [
        'To ask the DHCP server to renew its lease a bit early.',
        'To find the MAC address of its default gateway router.',
        'To test whether the network cable is plugged in fully.',
      ],
      explanation: ctx.explain(p.no),
      packets: [p.no],
    }
  }),
  gen('means.404', 'an HTTP 404', (ctx) => {
    const p = ctx.of('http-notfound')[0]
    if (!p) return null
    return {
      id: `means.404:${p.no}`,
      tier: 'Recruit',
      concept: 'http',
      prompt: `The server answered #${p.no} with "404 Not Found". What should you conclude?`,
      hint: '4xx codes blame the request, not the server.',
      correct: "The requested resource doesn't exist on that server.",
      distractors: [
        'The server crashed while it was handling the request.',
        "The client isn't allowed to view the resource at all.",
        'A proxy intercepted the connection and blocked it.',
      ],
      explanation: ctx.explain(p.no),
      packets: [p.no],
    }
  }),
  gen('means.mss', 'a SYN with an MSS option', (ctx) => {
    const p = ctx.of('tcp-syn').find((x) => x.facts.tcp?.mss)
    if (!p) return null
    const mss = p.facts.tcp!.mss
    return {
      id: `means.mss:${p.no}`,
      tier: 'Analyst',
      concept: 'tcp-flags',
      prompt: `What does MSS=${mss} in the SYN (#${p.no}) tell the other side?`,
      hint: 'MSS stands for Maximum Segment Size.',
      correct: 'The largest TCP payload the sender can take per segment.',
      distractors: [
        'The maximum number of packets it may send at once.',
        'The total size of the file the client wants to fetch.',
        'How many seconds to wait before closing the socket.',
      ],
      explanation: {
        ...ctx.explain(p.no),
        means:
          (mss === 1460
            ? `${mss} = 1500-byte Ethernet MTU − 20 (IP) − 20 (TCP). `
            : mss === 1440
              ? `${mss} = 1500-byte MTU − 40 (IPv6) − 20 (TCP). `
              : mss! > 1460
                ? `${mss} is above the usual 1460, so the sender's link allows jumbo frames. `
                : `${mss} is below the usual 1460, which points to a smaller path MTU (a tunnel, VPN or PPPoE link). `) +
          `The peer won't send segments with more than ${mss} bytes of payload.`,
        deeper: 'RFC 9293 §3.7.1: MSS is only sent in SYN segments and counts payload bytes, excluding TCP/IP headers.',
      },
      packets: [p.no],
    }
  }),
  gen('means.login-retry', 'a failed then successful login', (ctx) => {
    const fail = ctx.of('ftp-530')[0]
    const ok = ctx.of('ftp-230').find((p) => fail && p.no > fail.no)
    if (!fail || !ok) return null
    return {
      id: `means.login-retry:${fail.no}`,
      tier: 'Analyst',
      concept: 'cleartext',
      prompt: `The first login attempt got 530 (#${fail.no}) and a later one got 230 (#${ok.no}). What happened?`,
      hint: '5xx = permanent failure, 2xx = success.',
      correct: 'The first password was wrong and the second one worked.',
      distractors: [
        'The server was down, then it recovered for the retry.',
        'Both attempts failed, so the account is locked now.',
        'The client switched over to an encrypted login mode.',
      ],
      explanation: {
        ...ctx.explain(ok.no),
        means: 'Both passwords crossed the wire in cleartext — an attacker learns a valid password and a likely old one the user may reuse elsewhere.',
      },
      packets: [fail.no, ok.no],
    }
  }),
  gen('means.udp-dns', 'DNS over UDP', (ctx) => {
    const p = ctx.of('dns-query').find((x) => x.facts.udp)
    if (!p) return null
    return {
      id: `means.udp-dns:${p.no}`,
      tier: 'Analyst',
      concept: 'udp',
      prompt: `The DNS lookup in #${p.no} uses UDP rather than TCP. Why is that a good fit?`,
      hint: 'How many packets does a lookup need?',
      correct: 'A small question and answer need no connection setup.',
      distractors: [
        'UDP encrypts the query so nobody can see the name.',
        'Every firewall blocks TCP traffic on port 53 anyway.',
        'UDP guarantees the answer arrives in the right order.',
      ],
      explanation: {
        ...ctx.explain(p.no),
        means: 'One request and one reply fit in single datagrams, so skipping the three-way handshake halves the latency. The client simply retries if nothing comes back.',
        deeper: 'RFC 1035 §4.2: DNS uses UDP port 53 for messages up to 512 bytes (more with EDNS0), falling back to TCP for large answers and zone transfers.',
      },
      packets: [p.no],
    }
  }),
  gen('means.teardown', 'a connection closed with FIN', (ctx) => {
    const c = ctx.index.conversations.find((c) => c.closedBy === 'fin' && c.handshake?.ack)
    if (!c) return null
    const fins = c.packets.filter((n) => ctx.pkt(n).facts.tcp?.flags.fin)
    if (fins.length < 2) return null
    return {
      id: `means.teardown:${c.id}`,
      tier: 'Analyst',
      concept: 'tcp-teardown',
      prompt: `How did the connection between ${c.a.addr} and ${c.b.addr}:${c.b.port} end?`,
      hint: 'Look at the last few packets of the stream: FIN or RST?',
      correct: 'Gracefully: both sides sent FIN and acknowledged it.',
      distractors: [
        'Abruptly: one side sent a RST to abort the session.',
        'It timed out because the server stopped replying.',
        'It never ended; the capture stopped mid-transfer.',
      ],
      explanation: {
        ...ctx.explain(fins[0]),
        means: 'Each side sent its own FIN (closing its direction) and the other acknowledged it — the normal four-way close.',
      },
      packets: fins,
    }
  }),
]
