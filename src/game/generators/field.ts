// Mode D — "Field Hunt": find the exact field (tree) or bytes (hex) holding a value.

import type { Kind } from '../knowledge'
import type { Concept, FieldQuestion, Tier } from '../types'
import { GenCtx, notNull, type Generator } from './context'

interface HuntSpec {
  kinds: Kind[]
  key: string
  also?: string[]
  partial?: string[]
  label: string
  prompt: (no: number) => string
  hint: string
  tier: Tier
  concept: Concept
  means: string
  matters: string
}

const HUNTS: HuntSpec[] = [
  {
    kinds: ['tcp-syn', 'dns-query', 'icmp-echo-req'],
    key: 'ip.ttl',
    label: 'Time to Live',
    prompt: (n) => `In packet #${n}, click the byte that holds the IP Time to Live (TTL).`,
    hint: 'TTL is a single byte, 9th byte of the IPv4 header.',
    tier: 'Recruit',
    concept: 'addressing',
    means: 'TTL counts down by one at every router; when it hits 0 the packet is dropped (this is how traceroute works).',
    matters: 'Default TTLs (64 Linux/macOS, 128 Windows, 255 network gear) help fingerprint operating systems and spot spoofing.',
  },
  {
    kinds: ['tcp-syn'],
    key: 'tcp.dstport',
    label: 'Destination Port',
    prompt: (n) => `In the SYN #${n}, click the destination port — the service the client wants to reach.`,
    hint: 'The TCP header starts with the source port, then the destination port (2 bytes each).',
    tier: 'Recruit',
    concept: 'addressing',
    means: 'The destination port selects the listening service on the server (80 = HTTP, 443 = HTTPS, 21 = FTP …).',
    matters: 'Destination ports drive firewall rules and IDS signatures; unusual ones are worth a closer look.',
  },
  {
    kinds: ['dns-query'],
    key: 'udp.srcport',
    label: 'Source Port',
    prompt: (n) => `In the DNS query #${n}, click the client's (ephemeral) source port.`,
    hint: 'The UDP header is 8 bytes: source port, destination port, length, checksum.',
    tier: 'Recruit',
    concept: 'udp',
    means: 'The client picks a random high port so it can match the reply; the reply comes back to this port.',
    matters: 'Randomised source ports (plus the transaction ID) defend against DNS cache-poisoning (the Kaminsky attack).',
  },
  {
    kinds: ['tls-ch'],
    key: 'tls.handshake.extensions_server_name',
    partial: ['tls.handshake.extensions_server_name_list'],
    label: 'Server Name (SNI)',
    prompt: (n) => `Find the SNI — the website name — inside the ClientHello #${n}.`,
    hint: 'Expand Transport Layer Security → Handshake → Extension: server_name.',
    tier: 'Analyst',
    concept: 'tls',
    means: 'SNI tells the server which certificate to present; it is sent before encryption starts.',
    matters: 'SNI is visible to every observer, so it reveals the destination of otherwise-encrypted traffic.',
  },
  {
    kinds: ['dns-query'],
    key: 'dns.qry.name',
    partial: ['dns.qry', 'dns.queries'],
    label: 'Query Name',
    prompt: (n) => `In the DNS query #${n}, click the name being looked up.`,
    hint: 'It is in the Queries section, encoded as length-prefixed labels.',
    tier: 'Recruit',
    concept: 'dns',
    means: 'The QNAME is sent as labels: a length byte then that many characters, ending with a zero byte.',
    matters: 'Query names are a goldmine for threat hunting: known-bad domains, DGAs and tunnels all show up here.',
  },
  {
    kinds: ['dns-answer'],
    key: 'dns.a',
    also: ['dns.aaaa'],
    partial: ['dns.resp', 'dns.answers'],
    label: 'Answer address',
    prompt: (n) => `In the DNS response #${n}, click the IP address the server returned.`,
    hint: 'Look in the Answers section for an A (or AAAA) record.',
    tier: 'Analyst',
    concept: 'dns',
    means: 'The A record’s RDATA is the 4-byte IPv4 address the client will connect to next.',
    matters: 'Correlating resolved IPs with later connections ties network activity back to domain names.',
  },
  {
    kinds: ['tcp-synack'],
    key: 'tcp.flags',
    also: ['tcp.flags.syn', 'tcp.flags.ack'],
    label: 'TCP Flags',
    prompt: (n) => `Click the TCP field that marks packet #${n} as a SYN-ACK.`,
    hint: 'Flags share bytes 13–14 of the TCP header with the header length.',
    tier: 'Analyst',
    concept: 'tcp-flags',
    means: 'The SYN (0x02) and ACK (0x10) bits together make 0x012.',
    matters: 'Flag combinations drive firewall state tracking and are how scans (SYN, FIN, Xmas, NULL) are classified.',
  },
  {
    kinds: ['http-request'],
    key: 'http.request.method',
    partial: ['http.request.line'],
    label: 'Request Method',
    prompt: (n) => `In the HTTP request #${n}, click the request method.`,
    hint: 'It is the first word of the request line.',
    tier: 'Recruit',
    concept: 'http',
    means: 'The method says what the client wants: GET retrieves, POST submits, PUT uploads, DELETE removes.',
    matters: 'Unexpected methods (PUT, DELETE, TRACE) against a web server are a common sign of probing.',
  },
  {
    kinds: ['http-request'],
    key: 'http.host',
    label: 'Host header',
    prompt: (n) => `In the HTTP request #${n}, click the header that names the website.`,
    hint: 'HTTP/1.1 requires one specific header naming the site.',
    tier: 'Analyst',
    concept: 'http',
    means: 'The Host header lets many websites share one IP address (virtual hosting).',
    matters: 'Host headers reveal the real destination behind shared IPs and are key for web proxy logs.',
  },
  {
    kinds: ['http-ok', 'http-notfound'],
    key: 'http.response.code',
    partial: ['http.response.line'],
    label: 'Status Code',
    prompt: (n) => `In the HTTP response #${n}, click the status code.`,
    hint: 'It is the 3-digit number on the status line.',
    tier: 'Recruit',
    concept: 'http',
    means: '1xx info, 2xx success, 3xx redirect, 4xx client error, 5xx server error.',
    matters: 'Status code patterns (many 404s, 401s, 500s) are one of the fastest ways to spot attacks on web apps.',
  },
  {
    kinds: ['dhcp-offer'],
    key: 'dhcp.ip.your',
    partial: ['dhcp.option.requested_ip_address'],
    label: 'Your (client) IP address',
    prompt: (n) => `In the DHCP Offer #${n}, click the field carrying the IP address being offered.`,
    hint: 'BOOTP calls it "yiaddr" — your IP address.',
    tier: 'Analyst',
    concept: 'dhcp',
    means: 'yiaddr is the address the server proposes; the client echoes it in option 50 of its Request.',
    matters: 'DHCP lease data maps IP ↔ MAC ↔ hostname — the first thing to check when attributing an IP to a device.',
  },
  {
    kinds: ['arp-reply'],
    key: 'arp.src.hw_mac',
    partial: ['eth.src'],
    label: 'Sender MAC address',
    prompt: (n) => `In the ARP reply #${n}, click the MAC address the sender claims inside the ARP message.`,
    hint: 'Not the Ethernet header — the ARP payload has its own sender MAC field.',
    tier: 'Analyst',
    concept: 'arp',
    means: 'The ARP sender MAC is what receivers cache for the sender IP; the Ethernet source can differ.',
    matters: 'ARP spoofers put their own MAC here next to someone else’s IP.',
  },
  {
    kinds: ['ftp-pass'],
    key: 'ftp.request.arg',
    partial: ['ftp.request'],
    label: 'Password argument',
    prompt: (n) => `In packet #${n}, click the bytes that contain the cleartext password.`,
    hint: 'It is the argument after the PASS command. The UI masks it, but the bytes are there.',
    tier: 'Analyst',
    concept: 'cleartext',
    means: 'Everything after "PASS " up to CRLF is the password, byte for byte.',
    matters: 'If you can click it, so can an attacker with a sniffer — that is the whole problem with FTP.',
  },
  {
    kinds: ['tcp-syn'],
    key: 'tcp.options.mss_val',
    partial: ['tcp.options.mss', 'tcp.options'],
    label: 'MSS value',
    prompt: (n) => `In the SYN #${n}, click the Maximum Segment Size value.`,
    hint: 'Expand TCP → Options → Maximum segment size.',
    tier: 'Analyst',
    concept: 'tcp-flags',
    means: 'Option kind 2, length 4, then a 2-byte value — usually 1460 on Ethernet.',
    matters: 'Odd MSS values can reveal VPNs/tunnels (smaller MTU) or crafted scanner packets.',
  },
  {
    kinds: ['dns-nxdomain'],
    key: 'dns.flags.rcode',
    partial: ['dns.flags'],
    label: 'Reply code',
    prompt: (n) => `In the DNS response #${n}, click the field saying the name does not exist.`,
    hint: 'It is the last 4 bits of the DNS flags.',
    tier: 'Analyst',
    concept: 'dns',
    means: 'RCODE 3 = NXDOMAIN (“No such name”).',
    matters: 'Spikes of NXDOMAIN are a classic indicator of DGA malware.',
  },
  {
    kinds: ['icmp-echo-req'],
    key: 'icmp.type',
    label: 'ICMP Type',
    prompt: (n) => `In packet #${n}, click the field that identifies it as a ping request.`,
    hint: 'The first byte of the ICMP header.',
    tier: 'Recruit',
    concept: 'icmp',
    means: 'Type 8 = echo request, type 0 = echo reply, type 3 = destination unreachable.',
    matters: 'Filtering by ICMP type lets defenders allow useful ICMP while blocking recon.',
  },
  {
    kinds: ['tls-sh'],
    key: 'tls.handshake.ciphersuite',
    label: 'Cipher Suite',
    prompt: (n) => `In the ServerHello #${n}, click the cipher suite the server chose.`,
    hint: 'The ServerHello has exactly one Cipher Suite field (2 bytes).',
    tier: 'Analyst',
    concept: 'tls',
    means: 'Two bytes identify the negotiated suite, e.g. 0x1301 = TLS_AES_128_GCM_SHA256.',
    matters: 'Auditors flag weak suites (RC4, 3DES, CBC with SHA-1) negotiated in production traffic.',
  },
]

export const fieldGenerators: Generator[] = [
  {
    id: 'field.hunts',
    mode: 'field',
    needs: 'packets with well-known fields',
    generate(ctx: GenCtx) {
      const out: (FieldQuestion | null)[] = []
      for (const h of HUNTS) {
        const p = h.kinds.flatMap((k) => ctx.of(k)).sort((a, b) => a.no - b.no)[0]
        if (!p) continue
        const keys = [h.key, ...(h.also ?? [])]
        const target = keys.map((k) => ctx.findField(p.no, k)).find((f) => f && f.length > 0)
        if (!target) continue
        const ex = ctx.explain(p.no)
        out.push({
          id: `field.${h.key}:${p.no}`,
          mode: 'field',
          kind: 'field',
          tier: h.tier,
          concept: h.concept,
          prompt: h.prompt(p.no),
          hint: h.hint,
          packet: p.no,
          targetKeys: keys,
          partialKeys: h.partial ?? [],
          targetLabel: h.label,
          focusPacket: p.no,
          explanation: {
            says: `${h.label}: ${target.secret ? '•••••• (masked)' : (target.value ?? '')} — bytes ${target.offset}–${target.offset + target.length - 1} of the frame.`,
            means: h.means,
            matters: h.matters,
            deeper: ex.deeper,
          },
          highlight: [{ packet: p.no, fieldKeys: [target.key!] }],
        })
      }
      return out.filter(notNull)
    },
  },
]
