// Groups packets into conversations (Wireshark Statistics → Conversations / Follow Stream).

import type { Conversation, PacketSummary } from '../types'

const APP_PRIORITY = ['http', 'tls', 'dns', 'dhcp', 'ftp', 'ftp-data', 'smtp', 'pop', 'imap', 'telnet', 'ssh', 'ntp', 'snmp']
const APP_LABEL: Record<string, string> = {
  http: 'HTTP',
  tls: 'TLS',
  dns: 'DNS',
  dhcp: 'DHCP',
  ftp: 'FTP',
  'ftp-data': 'FTP-DATA',
  smtp: 'SMTP',
  pop: 'POP3',
  imap: 'IMAP',
  telnet: 'Telnet',
  ssh: 'SSH',
  ntp: 'NTP',
  snmp: 'SNMP',
}

interface Tuple {
  proto: Conversation['proto']
  src: string
  dst: string
  sport?: number
  dport?: number
}

function tupleOf(p: PacketSummary): Tuple | null {
  const f = p.facts
  if (f.arp) return { proto: 'ARP', src: f.arp.senderIp, dst: f.arp.targetIp }
  if (!f.ip) return null
  if (f.tcp) return { proto: 'TCP', src: f.ip.src, dst: f.ip.dst, sport: f.tcp.srcPort, dport: f.tcp.dstPort }
  if (f.udp) return { proto: 'UDP', src: f.ip.src, dst: f.ip.dst, sport: f.udp.srcPort, dport: f.udp.dstPort }
  if (f.icmp) return { proto: 'ICMP', src: f.ip.src, dst: f.ip.dst }
  return { proto: 'Other', src: f.ip.src, dst: f.ip.dst }
}

const ep = (addr: string, port?: number) => (port === undefined ? addr : `${addr}:${port}`)

export function conversationKey(t: Tuple): string {
  const a = ep(t.src, t.sport)
  const b = ep(t.dst, t.dport)
  return `${t.proto}|${a < b ? a + '|' + b : b + '|' + a}`
}

/** Assigns streamId on every summary and returns the conversation list. */
export function buildConversations(packets: PacketSummary[]): Conversation[] {
  const convs: Conversation[] = []
  const open = new Map<string, Conversation>()
  for (const p of packets) {
    const t = tupleOf(p)
    if (!t) {
      p.streamId = -1
      continue
    }
    const key = conversationKey(t)
    let c = open.get(key)
    const tcp = p.facts.tcp
    // A fresh SYN on a closed 5-tuple starts a new stream (port reuse).
    if (c && tcp && tcp.flags.syn && !tcp.flags.ack && c.closedBy && c.packets.length > 1) c = undefined
    if (!c) {
      let a = { addr: t.src, port: t.sport }
      let b = { addr: t.dst, port: t.dport }
      // If the first packet we see is a SYN-ACK, the sender is the server.
      if (tcp && tcp.flags.syn && tcp.flags.ack) [a, b] = [b, a]
      c = {
        id: convs.length,
        proto: t.proto,
        app: '',
        a,
        b,
        packets: [],
        bytes: 0,
        bytesAtoB: 0,
        bytesBtoA: 0,
        start: p.relTime,
        end: p.relTime,
      }
      if (t.proto === 'TCP') c.handshake = {}
      convs.push(c)
      open.set(key, c)
    }
    p.streamId = c.id
    c.packets.push(p.no)
    c.bytes += p.origLen
    const fromA = t.src === c.a.addr && t.sport === c.a.port
    if (fromA) c.bytesAtoB += p.origLen
    else c.bytesBtoA += p.origLen
    c.end = p.relTime
    for (const pr of p.facts.protos) {
      if (!APP_LABEL[pr]) continue
      if (!c.app || APP_PRIORITY.indexOf(pr) < APP_PRIORITY.indexOf(appKey(c.app))) c.app = APP_LABEL[pr]
    }
    if (tcp && c.handshake) {
      const hs = c.handshake
      if (tcp.flags.syn && !tcp.flags.ack && hs.syn === undefined && fromA) hs.syn = p.no
      else if (tcp.flags.syn && tcp.flags.ack && hs.synAck === undefined && !fromA) hs.synAck = p.no
      else if (
        tcp.flags.ack &&
        !tcp.flags.syn &&
        !tcp.flags.rst &&
        fromA &&
        hs.synAck !== undefined &&
        hs.ack === undefined
      )
        hs.ack = p.no
      if (tcp.flags.rst) c.closedBy = 'rst'
      else if (tcp.flags.fin && c.closedBy !== 'rst') c.closedBy = 'fin'
    }
  }
  for (const c of convs) if (!c.app) c.app = c.proto
  return convs
}

function appKey(label: string): string {
  return Object.entries(APP_LABEL).find(([, v]) => v === label)?.[0] ?? ''
}

export function isFromA(c: Conversation, p: PacketSummary): boolean {
  const f = p.facts
  if (f.arp) return f.arp.senderIp === c.a.addr
  const src = f.ip?.src
  const sport = f.tcp?.srcPort ?? f.udp?.srcPort
  return src === c.a.addr && sport === c.a.port
}

export interface StreamSegment {
  frame: number
  fromA: boolean
  bytes: Uint8Array
}

/**
 * Reassembles the payload of a TCP or UDP conversation ("Follow Stream"). For TCP, segments are
 * ordered by sequence number per direction and retransmitted bytes are dropped.
 */
export function followStream(
  c: Conversation,
  byNo: (no: number) => PacketSummary,
  frameBytes: (p: PacketSummary) => Uint8Array,
): StreamSegment[] {
  const out: StreamSegment[] = []
  const nextSeq = new Map<boolean, number>()
  for (const no of c.packets) {
    const p = byNo(no)
    const fromA = isFromA(c, p)
    const t = p.facts.tcp
    const u = p.facts.udp
    const off = t?.payloadOffset ?? u?.payloadOffset
    let len = t?.payloadLen ?? u?.payloadLen ?? 0
    if (off === undefined || len <= 0) continue
    let start = off
    if (t) {
      const expected = nextSeq.get(fromA)
      if (expected !== undefined) {
        const diff = (t.seq - expected) | 0
        if (diff < 0) {
          // Overlaps data already seen: trim or drop the retransmission.
          if (-diff >= len) continue
          start += -diff
          len -= -diff
        }
      }
      nextSeq.set(fromA, (t.seq + (start - off) + len) >>> 0)
    }
    const fb = frameBytes(p)
    out.push({ frame: no, fromA, bytes: fb.subarray(start, Math.min(fb.length, start + len)) })
  }
  return out
}
