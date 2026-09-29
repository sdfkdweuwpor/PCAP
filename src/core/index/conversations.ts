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
  const protoCount = new Map<string, number>()
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
      c.protoIndex = protoCount.get(t.proto) ?? 0
      protoCount.set(t.proto, c.protoIndex + 1)
      convs.push(c)
      open.set(key, c)
    }
    p.streamId = c.id
    p.protoStream = c.protoIndex
    c.packets.push(p.no)
    c.bytes += p.origLen
    const fromA = t.src === c.a.addr && t.sport === c.a.port
    if (fromA) c.bytesAtoB += p.origLen
    else c.bytesBtoA += p.origLen
    c.end = p.relTime
    for (const pr of p.facts.protos) {
      if (!APP_LABEL[pr]) continue
      if (!c.app || APP_PRIORITY.indexOf(pr) < APP_RANK.get(c.app)!) c.app = APP_LABEL[pr]
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

const APP_RANK = new Map(APP_PRIORITY.map((k, i) => [APP_LABEL[k], i]))

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
 * Reassembles the payload of a TCP or UDP conversation ("Follow Stream"). TCP data is emitted per direction in
 * sequence order: segments that arrive early are held until the gap before them is filled, bytes already delivered
 * (retransmissions, overlaps) are trimmed, and anything still waiting at the end is flushed across its gap.
 */
export function followStream(
  c: Conversation,
  byNo: (no: number) => PacketSummary,
  frameBytes: (p: PacketSummary) => Uint8Array,
): StreamSegment[] {
  const out: StreamSegment[] = []
  interface Seg {
    frame: number
    seq: number
    bytes: Uint8Array
  }
  const state = new Map<boolean, { next: number | undefined; held: Seg[] }>([
    [true, { next: undefined, held: [] }],
    [false, { next: undefined, held: [] }],
  ])
  // A SYN tells us where each direction's data starts, so an early out-of-order first segment isn't mistaken for it.
  for (const no of c.packets) {
    const p = byNo(no)
    const t = p.facts.tcp
    if (t?.flags.syn) state.get(isFromA(c, p))!.next ??= (t.seq + 1) >>> 0
  }

  const deliver = (fromA: boolean, seg: Seg) => {
    const st = state.get(fromA)!
    st.next ??= seg.seq
    const behind = (st.next - seg.seq) | 0
    if (behind >= seg.bytes.length) return // entirely old data
    const bytes = behind > 0 ? seg.bytes.subarray(behind) : seg.bytes
    out.push({ frame: seg.frame, fromA, bytes })
    st.next = (seg.seq + Math.max(behind, 0) + bytes.length) >>> 0
  }
  const drain = (fromA: boolean) => {
    const st = state.get(fromA)!
    for (let i = 0; i < st.held.length; ) {
      if (((st.held[i].seq - st.next!) | 0) <= 0) {
        deliver(fromA, st.held.splice(i, 1)[0])
        i = 0
      } else i++
    }
  }

  for (const no of c.packets) {
    const p = byNo(no)
    const fromA = isFromA(c, p)
    const t = p.facts.tcp
    const u = p.facts.udp
    const off = t?.payloadOffset ?? u?.payloadOffset
    const len = t?.payloadLen ?? u?.payloadLen ?? 0
    if (off === undefined || len <= 0) continue
    const fb = frameBytes(p)
    const bytes = fb.subarray(off, Math.min(fb.length, off + len))
    if (!t) {
      out.push({ frame: no, fromA, bytes })
      continue
    }
    const st = state.get(fromA)!
    if (st.next !== undefined && ((t.seq - st.next) | 0) > 0) {
      st.held.push({ frame: no, seq: t.seq, bytes }) // arrived early: wait for the gap to fill
      continue
    }
    deliver(fromA, { frame: no, seq: t.seq, bytes })
    drain(fromA)
  }
  // Flush whatever is still waiting (real loss in the capture): lowest sequence first, skipping the gap.
  for (const fromA of [true, false]) {
    const st = state.get(fromA)!
    while (st.held.length) {
      st.held.sort((x, y) => ((x.seq - st.next!) | 0) - ((y.seq - st.next!) | 0))
      st.next = st.held[0].seq
      drain(fromA)
    }
  }
  return out
}
