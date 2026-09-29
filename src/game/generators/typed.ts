// Mode H — "Type the Answer": read a value out of the capture and type it.

import { SERVICES } from '../knowledge'
import type { Concept, Explanation, TextQuestion, Tier } from '../types'
import { GenCtx, notNull, type Generator } from './context'

interface Spec {
  id: string
  tier: Tier
  concept: Concept
  prompt: string
  hint: string
  accept: (string | number)[]
  match: TextQuestion['match']
  placeholder: string
  packet: number
  fieldKeys?: string[]
  explanation?: Partial<Explanation>
}

function text(ctx: GenCtx, s: Spec): TextQuestion | null {
  const accept = [...new Set(s.accept.map(String).filter(Boolean))]
  if (!accept.length) return null
  const ex = ctx.explain(s.packet)
  return {
    id: s.id,
    mode: 'type',
    kind: 'text',
    tier: s.tier,
    concept: s.concept,
    prompt: s.prompt,
    hint: s.hint,
    accept,
    match: s.match,
    placeholder: s.placeholder,
    focusPacket: s.packet,
    explanation: { ...ex, ...s.explanation },
    highlight: [{ packet: s.packet, fieldKeys: s.fieldKeys }],
  }
}

const gen = (id: string, needs: string, f: (ctx: GenCtx) => (Spec | null)[]): Generator => ({
  id,
  mode: 'type',
  needs,
  generate: (ctx) => f(ctx).map((s) => (s ? text(ctx, s) : null)).filter(notNull),
})

export const typedGenerators: Generator[] = [
  gen('type.ttl', 'an IPv4 packet', (ctx) => {
    const p = ctx.packets.find((x) => x.facts.ip?.version === 4 && (x.facts.tcp?.flags.syn || x.facts.dns || x.facts.icmp))
    if (!p) return []
    return [
      {
        id: `type.ttl:${p.no}`,
        tier: 'Recruit',
        concept: 'addressing',
        prompt: `What is the IP Time to Live (TTL) of packet #${p.no}?`,
        hint: 'Expand "Internet Protocol Version 4" in the details pane.',
        accept: [p.facts.ip!.ttl],
        match: 'number',
        placeholder: 'a number, e.g. 128',
        packet: p.no,
        fieldKeys: ['ip.ttl'],
        explanation: { says: `ip.ttl = ${p.facts.ip!.ttl}`, means: `The packet may cross ${p.facts.ip!.ttl} more routers before it is dropped. 64 is the Linux/macOS default, 128 Windows, 255 network gear.` },
      },
    ]
  }),
  gen('type.dstport', 'a TCP SYN', (ctx) => {
    const syns = ctx.of('tcp-syn')
    const p = syns[Math.min(syns.length - 1, 1)] ?? syns[0]
    if (!p) return []
    const port = p.facts.tcp!.dstPort
    return [
      {
        id: `type.dstport:${p.no}`,
        tier: 'Recruit',
        concept: 'addressing',
        prompt: `Packet #${p.no} is a connection attempt. Which destination port is it aimed at?`,
        hint: 'The Info column shows "srcport → dstport".',
        accept: [port],
        match: 'number',
        placeholder: 'port number',
        packet: p.no,
        fieldKeys: ['tcp.dstport'],
        explanation: { says: `tcp.dstport = ${port}`, means: `Port ${port} is ${SERVICES[port] ? `the well-known port for ${SERVICES[port]}` : 'the service the client wants to reach'}.` },
      },
    ]
  }),
  gen('type.qname', 'a DNS query', (ctx) => {
    const p = ctx.of('dns-query').find((x) => x.facts.dns!.qname.length < 40)
    if (!p) return []
    const n = p.facts.dns!.qname
    return [
      {
        id: `type.qname:${p.no}`,
        tier: 'Recruit',
        concept: 'dns',
        prompt: `Which domain name is the client looking up in packet #${p.no}?`,
        hint: 'It is in the Queries section of the DNS layer (and in the Info column).',
        accept: [n, n + '.'],
        match: 'fuzzy',
        placeholder: 'e.g. www.example.com',
        packet: p.no,
        fieldKeys: ['dns.qry.name'],
      },
    ]
  }),
  gen('type.answer-ip', 'a DNS answer with an A record', (ctx) => {
    const p = ctx.of('dns-answer').find((x) => x.facts.dns!.answers.some((a) => a.type === 'A'))
    if (!p) return []
    const a = p.facts.dns!.answers.filter((x) => x.type === 'A').map((x) => x.data)
    return [
      {
        id: `type.answer-ip:${p.no}`,
        tier: 'Recruit',
        concept: 'dns',
        prompt: `According to the DNS response #${p.no}, what IPv4 address does ${p.facts.dns!.qname} resolve to?`,
        hint: 'Look for the A record in the Answers section.',
        accept: a,
        match: 'ip',
        placeholder: 'dotted IPv4 address',
        packet: p.no,
        fieldKeys: ['dns.a'],
      },
    ]
  }),
  gen('type.rcode', 'an NXDOMAIN response', (ctx) => {
    const p = ctx.of('dns-nxdomain')[0]
    if (!p) return []
    return [
      {
        id: `type.rcode:${p.no}`,
        tier: 'Analyst',
        concept: 'dns',
        prompt: `Packet #${p.no} is a failed lookup. What is the common name for its DNS reply code?`,
        hint: 'RCODE 3 has a short, well-known name starting with NX…',
        accept: ['NXDOMAIN', 'No such name', 'NX domain', '3'],
        match: 'fuzzy',
        placeholder: 'reply code name',
        packet: p.no,
        fieldKeys: ['dns.flags.rcode'],
      },
    ]
  }),
  gen('type.dns-transport', 'DNS over UDP', (ctx) => {
    const p = ctx.of('dns-query').find((x) => x.facts.udp)
    if (!p) return []
    return [
      {
        id: `type.dns-transport:${p.no}`,
        tier: 'Recruit',
        concept: 'udp',
        prompt: `Which transport-layer protocol carries the DNS query in packet #${p.no}?`,
        hint: 'Look at the layer directly under DNS in the details tree.',
        accept: ['UDP', 'User Datagram Protocol'],
        match: 'fuzzy',
        placeholder: 'protocol name',
        packet: p.no,
        fieldKeys: ['udp.srcport', 'udp.dstport'],
      },
    ]
  }),
  gen('type.flags', 'a SYN-ACK', (ctx) => {
    const p = ctx.of('tcp-synack')[0]
    if (!p) return []
    return [
      {
        id: `type.flags:${p.no}`,
        tier: 'Analyst',
        concept: 'tcp-handshake',
        prompt: `Which two TCP flags are set in packet #${p.no}?`,
        hint: 'The flags appear in square brackets in the Info column.',
        accept: ['SYN, ACK', 'SYN ACK', 'SYN-ACK', 'SYNACK', 'ACK, SYN', 'ACK SYN', 'SYN/ACK', 'SYN+ACK'],
        match: 'fuzzy',
        placeholder: 'e.g. FIN, ACK',
        packet: p.no,
        fieldKeys: ['tcp.flags'],
      },
    ]
  }),
  gen('type.mss', 'a SYN with MSS', (ctx) => {
    const p = ctx.of('tcp-syn').find((x) => x.facts.tcp!.mss)
    if (!p) return []
    return [
      {
        id: `type.mss:${p.no}`,
        tier: 'Analyst',
        concept: 'tcp-flags',
        prompt: `What Maximum Segment Size (MSS) does the SYN in packet #${p.no} advertise?`,
        hint: 'Options are listed at the end of the Info column for SYN packets.',
        accept: [p.facts.tcp!.mss!],
        match: 'number',
        placeholder: 'bytes',
        packet: p.no,
        fieldKeys: ['tcp.options.mss_val'],
      },
    ]
  }),
  gen('type.http', 'HTTP traffic', (ctx) => {
    const out: (Spec | null)[] = []
    const req = ctx.of('http-request')[0]
    if (req?.facts.http?.host)
      out.push({
        id: `type.host:${req.no}`,
        tier: 'Recruit',
        concept: 'http',
        prompt: `Which website (Host header) does the request in packet #${req.no} ask for?`,
        hint: 'Expand the HTTP layer and read the Host: line.',
        accept: [req.facts.http.host],
        match: 'fuzzy',
        placeholder: 'hostname',
        packet: req.no,
        fieldKeys: ['http.host'],
      })
    const err = ctx.packets.find((p) => (p.facts.http?.status ?? 0) >= 400)
    if (err)
      out.push({
        id: `type.status:${err.no}`,
        tier: 'Recruit',
        concept: 'http',
        prompt: `Packet #${err.no} is an HTTP response. What status code did the server return?`,
        hint: 'The 3-digit number right after HTTP/1.1.',
        accept: [err.facts.http!.status!],
        match: 'number',
        placeholder: '3-digit code',
        packet: err.no,
        fieldKeys: ['http.response.code'],
      })
    return out
  }),
  gen('type.tls', 'a TLS handshake', (ctx) => {
    const out: (Spec | null)[] = []
    const ch = ctx.of('tls-ch').find((x) => x.facts.tls?.sni)
    if (ch)
      out.push({
        id: `type.sni:${ch.no}`,
        tier: 'Analyst',
        concept: 'tls',
        prompt: `The page is encrypted, but packet #${ch.no} still reveals the site name. Type the SNI.`,
        hint: 'TLS → Handshake → Extension: server_name.',
        accept: [ch.facts.tls!.sni!],
        match: 'fuzzy',
        placeholder: 'server name',
        packet: ch.no,
        fieldKeys: ['tls.handshake.extensions_server_name'],
      })
    const sh = ctx.of('tls-sh').find((x) => x.facts.tls?.chosenCipher)
    if (sh) {
      const name = sh.facts.tls!.chosenCipher!
      const version = sh.facts.tls!.supportedVersions?.[0] ?? sh.facts.tls!.helloVersion ?? ''
      out.push({
        id: `type.cipher:${sh.no}`,
        tier: 'Hunter',
        concept: 'tls',
        prompt: `Type the full name of the cipher suite the server chose in packet #${sh.no}.`,
        hint: 'ServerHello → Cipher Suite. Starts with TLS_.',
        accept: [name],
        match: 'fuzzy',
        placeholder: 'TLS_…',
        packet: sh.no,
        fieldKeys: ['tls.handshake.ciphersuite'],
      })
      if (version)
        out.push({
          id: `type.tlsver:${sh.no}`,
          tier: 'Analyst',
          concept: 'tls',
          prompt: `Which TLS version did the server negotiate in packet #${sh.no}?`,
          hint: 'In TLS 1.3 the real version is in the supported_versions extension, not the record header.',
          accept: [version, version.replace(' ', ''), version.replace('TLS ', 'TLSv'), version.replace('TLS ', '')],
          match: 'fuzzy',
          placeholder: 'e.g. TLS 1.2',
          packet: sh.no,
          fieldKeys: ['tls.handshake.extensions.supported_version'],
        })
    }
    return out
  }),
  gen('type.dhcp', 'a DHCP offer', (ctx) => {
    const p = ctx.of('dhcp-offer')[0]
    if (!p) return []
    return [
      {
        id: `type.dhcp:${p.no}`,
        tier: 'Recruit',
        concept: 'dhcp',
        prompt: `Which IP address does the DHCP server offer to the new client in packet #${p.no}?`,
        hint: 'BOOTP field "Your (client) IP address".',
        accept: [p.facts.dhcp!.yiaddr],
        match: 'ip',
        placeholder: 'dotted IPv4 address',
        packet: p.no,
        fieldKeys: ['dhcp.ip.your'],
      },
    ]
  }),
  gen('type.ftp-user', 'an FTP login', (ctx) => {
    const p = ctx.of('ftp-user')[0]
    if (!p?.facts.creds?.user) return []
    return [
      {
        id: `type.ftp-user:${p.no}`,
        tier: 'Recruit',
        concept: 'cleartext',
        prompt: 'FTP sends logins in cleartext. Which username is used to log in?',
        hint: 'Filter with "ftp" and look for the USER command.',
        accept: [p.facts.creds.user],
        match: 'fuzzy',
        placeholder: 'username',
        packet: p.no,
        fieldKeys: ['ftp.request.arg'],
      },
    ]
  }),
  gen('type.arp-spoof', 'ARP spoofing', (ctx) => {
    const a = ctx.index.anomalies.find((x) => x.kind === 'arp-spoof')
    if (!a) return []
    return [
      {
        id: 'type.arp-attacker',
        tier: 'Hunter',
        concept: 'mitm',
        prompt: `Two MAC addresses claim ${a.evidence.ip}. Type the MAC address of the impostor (the one that appears second).`,
        hint: `Filter with "arp" and compare the "${a.evidence.ip} is at …" replies.`,
        accept: [String(a.evidence.attackerMac)],
        match: 'mac',
        placeholder: 'aa:bb:cc:dd:ee:ff',
        packet: a.packets[0],
        fieldKeys: ['arp.src.hw_mac'],
        explanation: { says: a.detail, means: `${a.evidence.attackerMac} is poisoning caches so traffic for ${a.evidence.ip} flows to it.` },
      },
    ]
  }),
  gen('type.scan', 'a port scan', (ctx) => {
    const a = ctx.index.anomalies.find((x) => x.kind === 'port-scan')
    if (!a) return []
    const open = String(a.evidence.openPorts)
      .split(',')
      .map((x) => x.trim())
      .filter((x) => /^\d+$/.test(x))
    const out: Spec[] = [
      {
        id: 'type.scan-count',
        tier: 'Hunter',
        concept: 'recon',
        prompt: `How many different destination ports did ${a.evidence.scanner} probe on ${a.evidence.target}?`,
        hint: 'Filter tcp.flags.syn == 1 && tcp.flags.ack == 0 and count the distinct destination ports (Conversations helps).',
        accept: [a.evidence.ports],
        match: 'number',
        placeholder: 'count',
        packet: a.packets[0],
        explanation: { says: a.detail, means: 'One SYN per port is the fingerprint of a SYN (half-open) scan.' },
      },
    ]
    if (open.length)
      out.push({
        id: 'type.scan-open',
        tier: 'Hunter',
        concept: 'recon',
        prompt: `The scan found open ports on ${a.evidence.target}. Type any one of them.`,
        hint: 'Open ports answer the SYN with SYN, ACK.',
        accept: open,
        match: 'number',
        placeholder: 'port number',
        packet: ctx.of('tcp-synack')[0]?.no ?? a.packets[0],
        fieldKeys: ['tcp.srcport'],
        explanation: { says: `Open ports: ${open.join(', ')}`, means: 'These are the services an attacker would try to exploit next.' },
      })
    return out
  }),
  gen('type.tunnel', 'DNS tunneling', (ctx) => {
    const a = ctx.index.anomalies.find((x) => x.kind === 'dns-tunnel')
    if (!a) return []
    const dom = String(a.evidence.domain)
    return [
      {
        id: 'type.tunnel-domain',
        tier: 'Hunter',
        concept: 'exfil',
        prompt: 'Data is being tunnelled out over DNS. Which base domain (e.g. example.com) receives it?',
        hint: 'Ignore the random-looking labels on the left; read the last two labels.',
        accept: [dom, dom + '.'],
        match: 'fuzzy',
        placeholder: 'domain',
        packet: a.packets[0],
        fieldKeys: ['dns.qry.name'],
        explanation: { says: a.detail, means: `Everything left of ${dom} is encoded data; the attacker runs the authoritative name server for ${dom}.` },
      },
    ]
  }),
]

// ---------------------------------------------------------------- grading

export function normalise(s: string): string {
  return s
    .trim()
    .toLowerCase()
    .replace(/^["'`]|["'`]$/g, '')
    .replace(/\s+/g, ' ')
    .replace(/\.$/, '')
}

function lev(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 3) return 99
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)])
  for (let j = 1; j <= b.length; j++) dp[0][j] = j
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
  return dp[a.length][b.length]
}

const macNorm = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^0-9a-f]/g, '')
    .padStart(12, '0')

/** Returns 1 for correct, 0 for wrong, plus a note when a typo was forgiven. */
export function gradeText(q: TextQuestion, input: string): { score: number; note: string } {
  const raw = input.trim()
  if (!raw) return { score: 0, note: 'Nothing typed.' }
  switch (q.match) {
    case 'number': {
      const n = raw.match(/\d+/)?.[0]
      return { score: n !== undefined && q.accept.includes(String(Number(n))) ? 1 : 0, note: '' }
    }
    case 'ip': {
      const v = raw.replace(/\s/g, '').replace(/\.$/, '')
      const ok = q.accept.some((a) => a.split('.').map(Number).join('.') === v.split('.').map(Number).join('.'))
      return { score: ok ? 1 : 0, note: '' }
    }
    case 'mac':
      return { score: q.accept.some((a) => macNorm(a) === macNorm(raw)) ? 1 : 0, note: '' }
    case 'exact':
      return { score: q.accept.some((a) => normalise(a) === normalise(raw)) ? 1 : 0, note: '' }
    case 'fuzzy': {
      const v = normalise(raw)
      if (q.accept.some((a) => normalise(a) === v)) return { score: 1, note: '' }
      const squash = (s: string) => normalise(s).replace(/[^a-z0-9]/g, '')
      if (q.accept.some((a) => squash(a) === squash(raw))) return { score: 1, note: 'Accepted (punctuation/spacing differs).' }
      const tolerance = (len: number) => (len >= 16 ? 2 : len >= 5 ? 1 : 0)
      // In short answers the digits carry the meaning ("TLS 1.2" must never pass for "TLS 1.3"), so typos are
      // forgiven only in letters. Long names (cipher suites) tolerate small slips anywhere.
      const digits = (s: string) => s.replace(/\D/g, '')
      const close = q.accept.find((a) => {
        const na = normalise(a)
        if (na.length < 16 && digits(na) !== digits(v)) return false
        return lev(na, v) <= tolerance(na.length)
      })
      if (close) return { score: 1, note: `Accepted despite a small typo (expected "${close}").` }
      return { score: 0, note: '' }
    }
  }
}
