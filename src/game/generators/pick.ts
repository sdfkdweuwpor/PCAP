// Mode A — "Which Line Is It?": describe a packet in plain English, learner clicks the row(s).

import { short } from '../knowledge'
import type { Concept, PickQuestion, Tier } from '../types'
import { GenCtx, notNull, spread, type Generator } from './context'

function pick(
  ctx: GenCtx,
  id: string,
  tier: Tier,
  concept: Concept,
  prompt: string,
  hint: string,
  answer: number[],
  explainFrom = answer[0],
  multi = false,
): PickQuestion | null {
  if (!answer.length) return null
  return {
    id,
    mode: 'pick',
    kind: 'pick',
    tier,
    concept,
    prompt,
    hint,
    answer,
    multi,
    explanation: ctx.explain(explainFrom),
    highlight: answer.map((packet) => ({ packet })),
  }
}

export const pickGenerators: Generator[] = [
  {
    id: 'pick.dns-query',
    mode: 'pick',
    needs: 'a DNS query',
    generate(ctx) {
      const qs = ctx.of('dns-query').filter((p) => p.facts.dns!.qname.length < 60)
      return spread(qs, 2)
        .map((p) => {
          const d = p.facts.dns!
          const what = d.qtype === 'A' ? 'IPv4 address' : d.qtype === 'AAAA' ? 'IPv6 address' : `${d.qtype} record`
          const same = qs.filter((q) => q.facts.dns!.qname === d.qname && q.facts.dns!.qtype === d.qtype).map((q) => q.no)
          return pick(
            ctx,
            `pick.dns-query:${p.no}`,
            'Recruit',
            'dns',
            `Click the packet where the client asks the DNS server for the ${what} of ${d.qname}.`,
            'Filter with "dns" and look for a "Standard query" (not a response).',
            same,
          )
        })
        .filter(notNull)
    },
  },
  {
    id: 'pick.dns-answer',
    mode: 'pick',
    needs: 'a DNS response with an address',
    generate(ctx) {
      const rs = ctx.of('dns-answer').filter((p) => p.facts.dns!.answers.some((a) => a.type === 'A' || a.type === 'AAAA'))
      return spread(rs, 1)
        .map((p) =>
          pick(
            ctx,
            `pick.dns-answer:${p.no}`,
            'Recruit',
            'dns',
            `Find the DNS server's answer that tells the client where ${p.facts.dns!.qname} lives.`,
            'Responses say "Standard query response" and carry A/AAAA records.',
            [p.no],
          ),
        )
        .filter(notNull)
    },
  },
  {
    id: 'pick.dns-nxdomain',
    mode: 'pick',
    needs: 'an NXDOMAIN response',
    generate(ctx) {
      const p = ctx.of('dns-nxdomain')[0]
      if (!p) return []
      return [
        pick(
          ctx,
          `pick.dns-nxdomain:${p.no}`,
          'Analyst',
          'dns',
          'Click the DNS reply telling the client that the name it asked for does not exist.',
          'Look for "No such name" in the Info column (RCODE 3).',
          ctx.of('dns-nxdomain').map((x) => x.no),
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.tcp-syn',
    mode: 'pick',
    needs: 'a TCP connection attempt',
    generate(ctx) {
      const convs = ctx.index.conversations.filter((c) => c.handshake?.syn !== undefined && c.handshake.synAck !== undefined)
      return spread(convs, 2)
        .map((c) =>
          pick(
            ctx,
            `pick.tcp-syn:${c.id}`,
            'Recruit',
            'tcp-handshake',
            `Click the packet where ${c.a.addr} first asks to open a TCP connection to ${c.b.addr} on port ${c.b.port}.`,
            'The very first packet of a TCP connection has only the SYN flag set.',
            [c.handshake!.syn!],
          ),
        )
        .filter(notNull)
    },
  },
  {
    id: 'pick.tcp-synack',
    mode: 'pick',
    needs: 'a TCP SYN-ACK',
    generate(ctx) {
      const convs = ctx.index.conversations.filter((c) => c.handshake?.synAck !== undefined && c.handshake.ack !== undefined)
      return spread(convs, 1)
        .map((c) =>
          pick(
            ctx,
            `pick.tcp-synack:${c.id}`,
            'Analyst',
            'tcp-handshake',
            `Find the packet where ${c.b.addr} agrees to open the connection on port ${c.b.port}.`,
            'The server answers a SYN with both SYN and ACK set.',
            [c.handshake!.synAck!],
          ),
        )
        .filter(notNull)
    },
  },
  {
    id: 'pick.handshake',
    mode: 'pick',
    needs: 'a complete TCP three-way handshake',
    generate(ctx) {
      const c = ctx.index.conversations.find((c) => c.handshake?.syn && c.handshake.synAck && c.handshake.ack)
      if (!c) return []
      const hs = c.handshake!
      return [
        pick(
          ctx,
          `pick.handshake:${c.id}`,
          'Analyst',
          'tcp-handshake',
          `Select all three packets of the TCP handshake between ${c.a.addr} and ${c.b.addr}:${c.b.port}.`,
          'SYN → SYN, ACK → ACK. Click each one, then submit.',
          [hs.syn!, hs.synAck!, hs.ack!],
          hs.synAck!,
          true,
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.http-request',
    mode: 'pick',
    needs: 'an HTTP request',
    generate(ctx) {
      return spread(ctx.of('http-request'), 2)
        .map((p) => {
          const h = p.facts.http!
          return pick(
            ctx,
            `pick.http-request:${p.no}`,
            'Recruit',
            'http',
            `Click the packet where the client requests ${short(h.uri ?? '/', 30)} from ${h.host ?? p.facts.ip?.dst}.`,
            'HTTP requests start with a method such as GET or POST.',
            [p.no],
          )
        })
        .filter(notNull)
    },
  },
  {
    id: 'pick.http-error',
    mode: 'pick',
    needs: 'an HTTP 4xx response',
    generate(ctx) {
      const errs = ctx.packets.filter((p) => (p.facts.http?.status ?? 0) >= 400)
      if (!errs.length) return []
      const p = errs[0]
      const is404 = p.facts.http!.status === 404
      return [
        pick(
          ctx,
          `pick.http-error:${p.no}`,
          'Analyst',
          'http',
          is404
            ? "Find the response where the server says the requested file doesn't exist."
            : 'Find the response where the server refuses or fails the client’s request.',
          'Status codes in the 400s are client errors. Try the filter http.response.code >= 400.',
          errs.filter((e) => e.facts.http!.status === p.facts.http!.status).map((e) => e.no),
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.tls-ch',
    mode: 'pick',
    needs: 'a TLS ClientHello',
    generate(ctx) {
      const p = ctx.of('tls-ch')[0]
      if (!p) return []
      return [
        pick(
          ctx,
          `pick.tls-ch:${p.no}`,
          'Analyst',
          'tls',
          'Click the packet where the client starts the TLS handshake and names the website it wants.',
          'It comes right after the TCP handshake and says "Client Hello".',
          [p.no],
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.tls-sh',
    mode: 'pick',
    needs: 'a TLS ServerHello',
    generate(ctx) {
      const p = ctx.of('tls-sh')[0]
      if (!p) return []
      return [
        pick(
          ctx,
          `pick.tls-sh:${p.no}`,
          'Analyst',
          'tls',
          'Find the packet where the server picks the cipher suite that will protect the session.',
          'The server answers the Client Hello with its own Hello.',
          [p.no],
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.fin',
    mode: 'pick',
    needs: 'a TCP connection closed with FIN',
    generate(ctx) {
      const c = ctx.index.conversations.find((c) => c.closedBy === 'fin' && c.handshake?.ack)
      if (!c) return []
      const fin = c.packets.find((n) => ctx.pkt(n).facts.tcp?.flags.fin)
      if (!fin) return []
      const who = ctx.pkt(fin).facts.ip!.src
      return [
        pick(
          ctx,
          `pick.fin:${c.id}`,
          'Analyst',
          'tcp-teardown',
          `Find the packet where ${who} first says it is finished sending on the port-${c.b.port} connection.`,
          'A graceful close starts with the FIN flag.',
          [fin],
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.dhcp',
    mode: 'pick',
    needs: 'DHCP messages',
    generate(ctx) {
      const prompts = [
        ['dhcp-offer', 'Click the packet where the DHCP server offers an IP address to the new client.', 'Recruit'],
        ['dhcp-request', 'Find the packet where the client formally asks to keep the offered address.', 'Analyst'],
        ['dhcp-ack', 'Click the packet where the DHCP server confirms the lease is granted.', 'Analyst'],
        ['dhcp-discover', 'Find the packet where a client with no IP address looks for a DHCP server.', 'Recruit'],
      ] as const
      return prompts
        .map(([k, prompt, tier]) => {
          const ps = ctx.of(k)
          if (!ps.length) return null
          return pick(ctx, `pick.${k}:${ps[0].no}`, tier, 'dhcp', prompt, 'DHCP runs in four steps: Discover, Offer, Request, ACK.', ps.map((p) => p.no))
        })
        .filter(notNull)
        .slice(0, 2)
    },
  },
  {
    id: 'pick.arp-reply',
    mode: 'pick',
    needs: 'an ARP request that is answered',
    generate(ctx) {
      for (const req of ctx.of('arp-request')) {
        const t = req.facts.arp!.targetIp
        const reply = ctx.of('arp-reply').find((r) => r.no > req.no && r.facts.arp!.senderIp === t)
        if (reply)
          return [
            pick(
              ctx,
              `pick.arp-reply:${reply.no}`,
              'Recruit',
              'arp',
              `Find the packet that answers the question "Who has ${t}?"`,
              'The answer is an ARP reply saying "<IP> is at <MAC>".',
              [reply.no],
            ),
          ].filter(notNull)
      }
      return []
    },
  },
  {
    id: 'pick.icmp-reply',
    mode: 'pick',
    needs: 'a ping that got a reply',
    generate(ctx) {
      const r = ctx.of('icmp-echo-reply')[0]
      if (!r) return []
      const from = r.facts.ip!.src
      return [
        pick(
          ctx,
          `pick.icmp-reply:${r.no}`,
          'Recruit',
          'icmp',
          `Click a packet where ${from} answers a ping.`,
          'Ping answers are ICMP "Echo (ping) reply" messages.',
          ctx.of('icmp-echo-reply').filter((p) => p.facts.ip!.src === from).map((p) => p.no),
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.creds',
    mode: 'pick',
    needs: 'a cleartext password',
    generate(ctx) {
      const ps = ctx.packets.filter((p) => p.facts.creds?.secret)
      if (!ps.length) return []
      return [
        pick(
          ctx,
          `pick.creds:${ps[0].no}`,
          'Analyst',
          'cleartext',
          'Click a packet in which a password crosses the network in cleartext.',
          'Look for PASS commands, Authorization headers or LOGIN lines.',
          ps.map((p) => p.no),
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.ftp-success',
    mode: 'pick',
    needs: 'a successful FTP login',
    generate(ctx) {
      const p = ctx.of('ftp-230')[0]
      if (!p) return []
      return [
        pick(
          ctx,
          `pick.ftp-success:${p.no}`,
          'Analyst',
          'cleartext',
          "Find the server's reply confirming that a login attempt succeeded.",
          'FTP replies starting with 2 mean success.',
          [p.no],
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.scan-closed',
    mode: 'pick',
    needs: 'SYNs refused by closed ports',
    generate(ctx) {
      const rs = ctx.of('tcp-rst-closed')
      if (rs.length < 3) return []
      return [
        pick(
          ctx,
          `pick.scan-closed:${rs[0].no}`,
          'Analyst',
          'recon',
          'Click a packet showing a closed port refusing a connection attempt.',
          'A closed port answers a SYN with RST, ACK.',
          rs.map((p) => p.no),
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.scan-open',
    mode: 'pick',
    needs: 'a port scan that found open ports',
    generate(ctx) {
      if (!ctx.index.anomalies.some((a) => a.kind === 'port-scan')) return []
      const sa = ctx.of('tcp-synack')
      if (!sa.length) return []
      return [
        pick(
          ctx,
          `pick.scan-open:${sa[0].no}`,
          'Hunter',
          'recon',
          'The target is being port-scanned. Click a packet that proves one of the scanned ports is open.',
          'Open ports answer the scanner’s SYN with SYN, ACK.',
          sa.map((p) => p.no),
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.arp-spoof',
    mode: 'pick',
    needs: 'an IP claimed by two MACs',
    generate(ctx) {
      const a = ctx.index.anomalies.find((x) => x.kind === 'arp-spoof')
      if (!a) return []
      const ip = String(a.evidence.ip)
      const attacker = String(a.evidence.attackerMac)
      const first = ctx.packets.find((p) => p.facts.arp?.senderIp === ip && p.facts.arp.senderMac === attacker)
      if (!first) return []
      return [
        pick(
          ctx,
          `pick.arp-spoof:${first.no}`,
          'Hunter',
          'mitm',
          `Click the first ARP message in which a second, different MAC address claims to be ${ip}.`,
          `Compare the MAC in each "${ip} is at …" line.`,
          [first.no],
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.flood-synack',
    mode: 'pick',
    needs: 'a SYN flood',
    generate(ctx) {
      const a = ctx.index.anomalies.find((x) => x.kind === 'syn-flood')
      if (!a) return []
      const orphan = ctx.of('tcp-synack').filter((p) => {
        const c = ctx.kb.conv(p)
        return c && c.handshake?.ack === undefined
      })
      if (!orphan.length) return []
      return [
        pick(
          ctx,
          `pick.flood-synack:${orphan[0].no}`,
          'Hunter',
          'dos',
          'Find a SYN-ACK the server sends to a (spoofed) address that never completes the handshake.',
          'Look for SYN, ACK packets from the server whose connection never gets a final ACK.',
          orphan.map((p) => p.no),
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'pick.dns-tunnel',
    mode: 'pick',
    needs: 'DNS tunneling',
    generate(ctx) {
      const a = ctx.index.anomalies.find((x) => x.kind === 'dns-tunnel')
      if (!a) return []
      const dom = String(a.evidence.domain)
      const qs = ctx.of('dns-query').filter((p) => p.facts.dns!.qname.endsWith(dom))
      return [
        pick(
          ctx,
          `pick.dns-tunnel:${qs[0]?.no}`,
          'Hunter',
          'exfil',
          'Click a DNS query whose name looks like encoded data rather than a real website.',
          'Real hostnames are short and readable; tunnels use long random-looking labels.',
          qs.map((p) => p.no),
        ),
      ].filter(notNull)
    },
  },
]
