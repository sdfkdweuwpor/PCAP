// Mode I — "Filter Forge": write a display filter; graded by the frames it matches.
// Each challenge's target set is computed from packet facts independently of the reference filter,
// and the reference is compiled at generation time to prove it matches the target exactly.

import { compileFilter, FilterError } from '../../core/filter/filter'
import type { CaptureIndex, PacketSummary } from '../../core/types'
import type { Concept, FilterQuestion, Tier } from '../types'
import { GenCtx, notNull, type Generator } from './context'

interface Challenge {
  id: string
  tier: Tier
  concept: Concept
  prompt: string
  hint: string
  select: (p: PacketSummary) => boolean
  reference: string
  means: string
  /** Require at least this many matches, and not the whole capture. */
  min?: number
}

function challenges(ctx: GenCtx): Challenge[] {
  const idx = ctx.index
  const out: Challenge[] = []
  const has = (f: (p: PacketSummary) => boolean) => idx.packets.some(f)
  const conv = idx.conversations.find((c) => c.proto === 'TCP' && c.handshake?.ack) ?? idx.conversations.find((c) => c.proto === 'TCP')

  out.push({
    id: 'dns',
    tier: 'Recruit',
    concept: 'dns',
    prompt: 'Show only DNS traffic.',
    hint: 'Protocol names work as filters on their own.',
    select: (p) => !!p.facts.dns,
    reference: 'dns',
    means: 'A bare protocol name keeps every packet that contains that protocol.',
  })
  out.push({
    id: 'dns-responses',
    tier: 'Analyst',
    concept: 'dns',
    prompt: 'Show only the DNS responses (not the queries).',
    hint: 'The DNS header has a response flag: dns.flags.response.',
    select: (p) => !!p.facts.dns?.isResponse,
    reference: 'dns.flags.response == 1',
    means: 'The QR bit in the DNS flags is 0 for a query and 1 for a response.',
  })
  out.push({
    id: 'syn',
    tier: 'Analyst',
    concept: 'tcp-handshake',
    prompt: 'Show every connection attempt: packets with SYN set but ACK not set.',
    hint: 'Combine tcp.flags.syn and tcp.flags.ack with &&.',
    select: (p) => !!p.facts.tcp && p.facts.tcp.flags.syn && !p.facts.tcp.flags.ack,
    reference: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
    means: 'The first packet of every TCP connection has only SYN; this is the go-to filter for spotting scans and floods.',
  })
  out.push({
    id: 'synack',
    tier: 'Analyst',
    concept: 'tcp-handshake',
    prompt: 'Show only the SYN-ACKs — servers agreeing to connect.',
    hint: 'Both tcp.flags.syn and tcp.flags.ack are 1.',
    select: (p) => !!p.facts.tcp && p.facts.tcp.flags.syn && p.facts.tcp.flags.ack,
    reference: 'tcp.flags.syn == 1 && tcp.flags.ack == 1',
    means: 'Every SYN-ACK marks a listening (open) port.',
  })
  out.push({
    id: 'rst',
    tier: 'Analyst',
    concept: 'tcp-flags',
    prompt: 'Show all TCP resets.',
    hint: 'The flag is called reset in filter syntax: tcp.flags.reset.',
    select: (p) => !!p.facts.tcp?.flags.rst,
    reference: 'tcp.flags.reset == 1',
    means: 'Resets abort connections — closed ports, crashed services or scanners.',
  })
  out.push({
    id: 'fin',
    tier: 'Analyst',
    concept: 'tcp-teardown',
    prompt: 'Show every packet where one side says it has finished sending (a graceful close).',
    hint: 'Graceful closes use the FIN flag.',
    select: (p) => !!p.facts.tcp?.flags.fin,
    reference: 'tcp.flags.fin == 1',
    means: 'FIN says "I have no more data"; each side sends one.',
  })
  if (conv) {
    out.push({
      id: `host:${conv.b.addr}`,
      tier: 'Recruit',
      concept: 'addressing',
      prompt: `Show all traffic to or from ${conv.b.addr}.`,
      hint: 'ip.addr matches either the source or the destination.',
      select: (p) => p.facts.ip?.version === 4 && (p.facts.ip.src === conv.b.addr || p.facts.ip.dst === conv.b.addr),
      reference: `ip.addr == ${conv.b.addr}`,
      means: 'ip.addr is the quickest way to isolate one host; ip.src / ip.dst narrow the direction.',
    })
    const client = conv.a.addr
    out.push({
      id: `from:${client}`,
      tier: 'Recruit',
      concept: 'addressing',
      prompt: `Show only packets sent by ${client} (it is the source).`,
      hint: 'Use ip.src rather than ip.addr.',
      select: (p) => p.facts.ip?.version === 4 && p.facts.ip.src === client,
      reference: `ip.src == ${client}`,
      means: 'ip.src restricts to one direction of the conversation.',
    })
    if (conv.b.port !== undefined)
      out.push({
        id: `port:${conv.b.port}`,
        tier: 'Recruit',
        concept: 'addressing',
        prompt: `Show all TCP traffic on port ${conv.b.port}.`,
        hint: 'tcp.port matches the source or destination port.',
        select: (p) => !!p.facts.tcp && (p.facts.tcp.srcPort === conv.b.port || p.facts.tcp.dstPort === conv.b.port),
        reference: `tcp.port == ${conv.b.port}`,
        means: 'Port filters isolate a service, whatever direction the packet travels.',
      })
  }
  out.push({
    id: 'http-req',
    tier: 'Recruit',
    concept: 'http',
    prompt: 'Show only HTTP GET requests.',
    hint: 'http.request.method holds the method; strings go in double quotes.',
    select: (p) => p.facts.http?.method === 'GET',
    reference: 'http.request.method == "GET"',
    means: 'Filtering on the method is how analysts pull every URL a client fetched.',
  })
  out.push({
    id: 'http-err',
    tier: 'Analyst',
    concept: 'http',
    prompt: 'Show every HTTP response with an error status (400 or higher).',
    hint: 'Numeric comparisons work: http.response.code >= …',
    select: (p) => (p.facts.http?.status ?? 0) >= 400,
    reference: 'http.response.code >= 400',
    means: '4xx/5xx spikes point at scanning, brute force or broken apps.',
  })
  out.push({
    id: 'client-hello',
    tier: 'Analyst',
    concept: 'tls',
    prompt: 'Show only TLS ClientHello messages.',
    hint: 'The handshake type of a ClientHello is 1: tls.handshake.type.',
    select: (p) => !!p.facts.tls?.handshakeTypes.includes('Client Hello'),
    reference: 'tls.handshake.type == 1',
    means: 'ClientHellos carry the SNI, so this filter lists every site a client connected to over TLS.',
  })
  out.push({
    id: 'arp-reply',
    tier: 'Analyst',
    concept: 'arp',
    prompt: 'Show only ARP replies ("… is at …").',
    hint: 'ARP opcode 1 is a request, 2 is a reply: arp.opcode.',
    select: (p) => p.facts.arp?.op === 2,
    reference: 'arp.opcode == 2',
    means: 'Watching replies is how you catch two MACs claiming the same IP.',
  })
  out.push({
    id: 'dhcp',
    tier: 'Recruit',
    concept: 'dhcp',
    prompt: 'Show only the DHCP messages.',
    hint: 'The protocol name is dhcp (older Wireshark: bootp).',
    select: (p) => !!p.facts.dhcp,
    reference: 'dhcp',
    means: 'DHCP traffic shows which device got which IP, and when.',
  })
  out.push({
    id: 'ping',
    tier: 'Recruit',
    concept: 'icmp',
    prompt: 'Show only ping requests (ICMP echo requests), not the replies.',
    hint: 'icmp.type is 8 for a request and 0 for a reply.',
    select: (p) => !!p.facts.icmp && !p.facts.icmp.v6 && p.facts.icmp.type === 8,
    reference: 'icmp.type == 8',
    means: 'Echo requests from one host to many is a ping sweep.',
  })
  if (has((p) => !!p.facts.arp) && has((p) => !p.facts.arp))
    out.push({
      id: 'not-arp',
      tier: 'Recruit',
      concept: 'protocols',
      prompt: 'Hide the ARP noise: show everything except ARP.',
      hint: 'Negate with ! (or not).',
      select: (p) => !p.facts.arp,
      reference: '!arp',
      means: 'Excluding background chatter is often the first step in a real investigation.',
    })
  out.push({
    id: 'ftp-cmd',
    tier: 'Analyst',
    concept: 'cleartext',
    prompt: 'Show only the commands the FTP client sent (not the server replies).',
    hint: 'A field name on its own tests that the field exists: ftp.request.command.',
    select: (p) => p.facts.app?.proto === 'FTP' && p.facts.app.isRequest && !!p.facts.app.command,
    reference: 'ftp.request.command',
    means: 'Listing client commands reveals USER, PASS and every file action — in cleartext.',
  })
  const tunnel = idx.anomalies.find((a) => a.kind === 'dns-tunnel')
  if (tunnel) {
    const dom = String(tunnel.evidence.domain)
    const word = dom.split('.')[0]
    out.push({
      id: 'tunnel',
      tier: 'Hunter',
      concept: 'exfil',
      prompt: `Show all DNS packets for the suspicious domain ${dom}.`,
      hint: 'dns.qry.name contains "…" matches part of the name.',
      select: (p) => !!p.facts.dns?.qname.includes(word),
      reference: `dns.qry.name contains "${word}"`,
      means: '"contains" lets you pull every subdomain of a suspect domain in one go.',
    })
  }
  const scan = idx.anomalies.find((a) => a.kind === 'port-scan')
  if (scan)
    out.push({
      id: 'scan-open',
      tier: 'Hunter',
      concept: 'recon',
      prompt: `Show only the replies proving that ports on ${scan.evidence.target} are open.`,
      hint: 'Open ports answer with SYN and ACK; the target is the source.',
      select: (p) => p.facts.ip?.src === String(scan.evidence.target) && !!p.facts.tcp?.flags.syn && !!p.facts.tcp.flags.ack,
      reference: `ip.src == ${scan.evidence.target} && tcp.flags.syn == 1 && tcp.flags.ack == 1`,
      means: 'This single filter turns a noisy scan into the list of exposed services.',
    })
  out.push({
    id: 'big',
    tier: 'Analyst',
    concept: 'protocols',
    prompt: 'Show only frames larger than 300 bytes.',
    hint: 'frame.len is the frame length; use >.',
    select: (p) => p.origLen > 300,
    reference: 'frame.len > 300',
    means: 'Size filters find the frames that actually carry data (downloads, uploads, exfiltration).',
  })
  return out
}

export function matchSet(index: CaptureIndex, filter: string): number[] {
  const pred = compileFilter(filter)
  return index.packets.filter(pred).map((p) => p.no)
}

export const filterGenerators: Generator[] = [
  {
    id: 'filter.forge',
    mode: 'filter',
    needs: 'traffic that a display filter can isolate',
    generate(ctx) {
      const total = ctx.index.packets.length
      return challenges(ctx)
        .map((c): FilterQuestion | null => {
          const target = ctx.index.packets.filter(c.select).map((p) => p.no)
          if (target.length < (c.min ?? 1) || target.length === total) return null
          // Prove the reference filter matches exactly the target.
          let ref: number[]
          try {
            ref = matchSet(ctx.index, c.reference)
          } catch (e) {
            if (e instanceof FilterError) return null
            throw e
          }
          if (ref.length !== target.length || ref.some((n, i) => n !== target[i])) return null
          return {
            id: `filter.${c.id}`,
            mode: 'filter',
            kind: 'filter',
            tier: c.tier,
            concept: c.concept,
            prompt: c.prompt,
            hint: c.hint,
            target,
            reference: c.reference,
            explanation: {
              says: `Reference filter: ${c.reference}  →  ${target.length} of ${total} frames`,
              means: c.means,
              matters: 'Writing precise filters is the core Wireshark skill — it turns thousands of packets into the handful that answer your question.',
              deeper: 'Wireshark display filters test protocol fields (proto.field) with ==, !=, >, <, contains and matches, combined with && || ! and parentheses. A field name alone tests that it is present.',
            },
            highlight: target.slice(0, 12).map((packet) => ({ packet })),
          }
        })
        .filter(notNull)
    },
  },
]

export function gradeFilter(q: FilterQuestion, index: CaptureIndex, text: string): { score: number; note: string; matched: number[] } {
  const matched = matchSet(index, text)
  const want = new Set(q.target)
  const got = new Set(matched)
  const hit = matched.filter((n) => want.has(n)).length
  const extra = matched.length - hit
  const missing = q.target.filter((n) => !got.has(n)).length
  const precision = matched.length ? hit / matched.length : 0
  const recall = want.size ? hit / want.size : 0
  const summary = `Matched ${matched.length} frame${matched.length === 1 ? '' : 's'}: ${hit} right, ${extra} extra, ${missing} missing.`
  if (extra === 0 && missing === 0) return { score: 1, note: `Exact match — ${summary}`, matched }
  if (precision >= 0.8 && recall >= 0.8) return { score: 0.5, note: `Close — ${summary}`, matched }
  return { score: 0, note: matched.length ? summary : summary + caseHint(index, text), matched }
}

/** When a filter matches nothing only because of the case of a quoted value, say so. */
function caseHint(index: CaptureIndex, text: string): string {
  if (!/"[^"]*[a-z][^"]*"|"[^"]*[A-Z][^"]*"/.test(text)) return ''
  for (const change of [(v: string) => v.toUpperCase(), (v: string) => v.toLowerCase()]) {
    const variant = text.replace(/"([^"]*)"/g, (_, v: string) => `"${change(v)}"`)
    try {
      if (variant !== text && matchSet(index, variant).length) return ' Text comparisons are case-sensitive, as in Wireshark: check the capitalisation of your quoted value.'
    } catch {
      return ''
    }
  }
  return ''
}
