// Packet-crafting helpers used to synthesize the built-in sample captures (and tests).
// Everything produces real, well-formed bytes with valid IPv4 checksums.

import { concatBytes } from '../core/bytes'
import type { FrameToWrite } from '../core/pcap/writer'

const enc = new TextEncoder()
export const text = (s: string) => enc.encode(s)

export function macBytes(m: string): Uint8Array {
  return Uint8Array.from(m.split(':').map((x) => parseInt(x, 16)))
}
export function ip4Bytes(ip: string): Uint8Array {
  return Uint8Array.from(ip.split('.').map(Number))
}
export function ip6Bytes(ip: string): Uint8Array {
  const [head, tail] = ip.split('::')
  const h = head ? head.split(':') : []
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : []
  const groups = tail !== undefined ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h
  const out = new Uint8Array(16)
  groups.forEach((g, i) => {
    const v = parseInt(g, 16)
    out[i * 2] = v >> 8
    out[i * 2 + 1] = v & 0xff
  })
  return out
}

function be16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff]
}
function be32(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
}

export function ethernet(src: string, dst: string, etherType: number, payload: Uint8Array, vlan?: number): Uint8Array {
  const hdr = [...macBytes(dst), ...macBytes(src)]
  if (vlan !== undefined) hdr.push(...be16(0x8100), ...be16(vlan & 0xfff))
  hdr.push(...be16(etherType))
  return concatBytes([Uint8Array.from(hdr), payload])
}

function checksum(bytes: Uint8Array): number {
  let sum = 0
  for (let i = 0; i < bytes.length; i += 2) sum += (bytes[i] << 8) | (bytes[i + 1] ?? 0)
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16)
  return ~sum & 0xffff
}

export interface Ip4Opts {
  ttl?: number
  id?: number
  df?: boolean
  mf?: boolean
  fragOffset?: number
}

export function ipv4(src: string, dst: string, proto: number, payload: Uint8Array, o: Ip4Opts = {}): Uint8Array {
  const total = 20 + payload.length
  const ff = (o.df ?? true ? 0x4000 : 0) | (o.mf ? 0x2000 : 0) | ((o.fragOffset ?? 0) >> 3)
  const h = Uint8Array.from([
    0x45,
    0,
    ...be16(total),
    ...be16(o.id ?? 0),
    ...be16(ff),
    o.ttl ?? 64,
    proto,
    0,
    0,
    ...ip4Bytes(src),
    ...ip4Bytes(dst),
  ])
  const c = checksum(h)
  h[10] = c >> 8
  h[11] = c & 0xff
  const out = concatBytes([h, payload])
  // Transport checksum (TCP/UDP) over the IPv4 pseudo-header.
  if (proto === 6 || proto === 17) {
    const pseudo = concatBytes([ip4Bytes(src), ip4Bytes(dst), Uint8Array.from([0, proto, ...be16(payload.length)]), payload])
    const off = proto === 6 ? 16 : 6
    const tc = checksum(pseudo) || (proto === 17 ? 0xffff : 0)
    out[20 + off] = tc >> 8
    out[20 + off + 1] = tc & 0xff
  }
  return out
}

export function ipv6(src: string, dst: string, next: number, payload: Uint8Array, hop = 64): Uint8Array {
  return concatBytes([
    Uint8Array.from([0x60, 0, 0, 0, ...be16(payload.length), next, hop]),
    ip6Bytes(src),
    ip6Bytes(dst),
    payload,
  ])
}

export interface TcpFlagsIn {
  syn?: boolean
  ack?: boolean
  fin?: boolean
  rst?: boolean
  psh?: boolean
}

export interface TcpOpts {
  window?: number
  mss?: number
  wscale?: number
  sackPerm?: boolean
  timestamps?: [number, number]
}

export function tcp(
  sport: number,
  dport: number,
  seq: number,
  ack: number,
  flags: TcpFlagsIn,
  payload: Uint8Array = new Uint8Array(),
  o: TcpOpts = {},
): Uint8Array {
  const opts: number[] = []
  if (o.mss !== undefined) opts.push(2, 4, ...be16(o.mss))
  if (o.sackPerm) opts.push(4, 2)
  if (o.timestamps) opts.push(8, 10, ...be32(o.timestamps[0]), ...be32(o.timestamps[1]))
  if (o.wscale !== undefined) opts.push(1, 3, 3, o.wscale)
  while (opts.length % 4) opts.push(1)
  const hlen = 20 + opts.length
  const fl =
    (flags.fin ? 1 : 0) | (flags.syn ? 2 : 0) | (flags.rst ? 4 : 0) | (flags.psh ? 8 : 0) | (flags.ack ? 16 : 0)
  const h = Uint8Array.from([
    ...be16(sport),
    ...be16(dport),
    ...be32(seq >>> 0),
    ...be32(ack >>> 0),
    (hlen / 4) << 4,
    fl,
    ...be16(o.window ?? 64240),
    0,
    0,
    0,
    0,
    ...opts,
  ])
  return concatBytes([h, payload])
}

export function udp(sport: number, dport: number, payload: Uint8Array): Uint8Array {
  return concatBytes([Uint8Array.from([...be16(sport), ...be16(dport), ...be16(8 + payload.length), 0, 0]), payload])
}

export function icmpEcho(request: boolean, id: number, seq: number, data = 32): Uint8Array {
  const body = new Uint8Array(8 + data)
  body[0] = request ? 8 : 0
  body.set(be16(id), 4)
  body.set(be16(seq), 6)
  for (let i = 0; i < data; i++) body[8 + i] = 0x61 + (i % 23)
  const c = checksum(body)
  body[2] = c >> 8
  body[3] = c & 0xff
  return body
}

export function icmpUnreachable(code: number, original: Uint8Array): Uint8Array {
  const body = concatBytes([Uint8Array.from([3, code, 0, 0, 0, 0, 0, 0]), original.subarray(0, 28)])
  const c = checksum(body)
  body[2] = c >> 8
  body[3] = c & 0xff
  return body
}

export function arp(op: 1 | 2, senderMac: string, senderIp: string, targetMac: string, targetIp: string): Uint8Array {
  return Uint8Array.from([
    0,
    1,
    0x08,
    0,
    6,
    4,
    ...be16(op),
    ...macBytes(senderMac),
    ...ip4Bytes(senderIp),
    ...macBytes(targetMac),
    ...ip4Bytes(targetIp),
  ])
}

// ---------------------------------------------------------------- DNS

const DNS_TYPE_CODES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28 }

function dnsName(name: string): number[] {
  const out: number[] = []
  for (const label of name.split('.')) {
    if (!label) continue
    out.push(label.length, ...enc.encode(label))
  }
  out.push(0)
  return out
}

export interface DnsAnswerIn {
  type: keyof typeof DNS_TYPE_CODES
  data: string
  ttl?: number
  name?: string
}

export function dnsQuery(id: number, name: string, type: keyof typeof DNS_TYPE_CODES = 'A'): Uint8Array {
  return Uint8Array.from([...be16(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...dnsName(name), ...be16(DNS_TYPE_CODES[type]), 0, 1])
}

export function dnsResponse(
  id: number,
  name: string,
  type: keyof typeof DNS_TYPE_CODES,
  answers: DnsAnswerIn[],
  rcode = 0,
): Uint8Array {
  const out: number[] = [...be16(id), 0x81, 0x80 | rcode, 0, 1, ...be16(answers.length), 0, 0, 0, 0]
  out.push(...dnsName(name), ...be16(DNS_TYPE_CODES[type]), 0, 1)
  for (const a of answers) {
    // Answers for the query name use a compression pointer to offset 12.
    if (!a.name || a.name === name) out.push(0xc0, 0x0c)
    else out.push(...dnsName(a.name))
    let rdata: number[]
    if (a.type === 'A') rdata = [...ip4Bytes(a.data)]
    else if (a.type === 'AAAA') rdata = [...ip6Bytes(a.data)]
    else if (a.type === 'CNAME' || a.type === 'NS' || a.type === 'PTR') rdata = dnsName(a.data)
    else if (a.type === 'TXT') {
      rdata = []
      for (let i = 0; i < a.data.length; i += 255) {
        const chunk = a.data.slice(i, i + 255)
        rdata.push(chunk.length, ...enc.encode(chunk))
      }
    } else rdata = [...enc.encode(a.data)]
    out.push(...be16(DNS_TYPE_CODES[a.type]), 0, 1, ...be32(a.ttl ?? 300), ...be16(rdata.length), ...rdata)
  }
  return Uint8Array.from(out)
}

// ---------------------------------------------------------------- DHCP

export function dhcp(
  op: 1 | 2,
  msgType: number,
  xid: number,
  clientMac: string,
  o: { yiaddr?: string; ciaddr?: string; siaddr?: string; options?: [number, number[]][] } = {},
): Uint8Array {
  const b = new Uint8Array(240)
  b[0] = op
  b[1] = 1
  b[2] = 6
  b.set(be32(xid), 4)
  b.set(be16(op === 1 ? 0x8000 : 0), 10)
  b.set(ip4Bytes(o.ciaddr ?? '0.0.0.0'), 12)
  b.set(ip4Bytes(o.yiaddr ?? '0.0.0.0'), 16)
  b.set(ip4Bytes(o.siaddr ?? '0.0.0.0'), 20)
  b.set(macBytes(clientMac), 28)
  b.set([0x63, 0x82, 0x53, 0x63], 236)
  const opts: number[] = [53, 1, msgType]
  for (const [code, data] of o.options ?? []) opts.push(code, data.length, ...data)
  opts.push(255)
  return concatBytes([b, Uint8Array.from(opts)])
}
export const ipOpt = (ip: string) => [...ip4Bytes(ip)]
export const u32Opt = (n: number) => be32(n)
export const strOpt = (s: string) => [...enc.encode(s)]

// ---------------------------------------------------------------- TLS

function tlsRecord(ct: number, body: number[], version = 0x0303): number[] {
  return [ct, ...be16(version), ...be16(body.length), ...body]
}
function handshake(type: number, body: number[]): number[] {
  return [type, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body]
}
function ext(type: number, data: number[]): number[] {
  return [...be16(type), ...be16(data.length), ...data]
}

export function tlsClientHello(sni: string, rng: () => number, suites = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c, 0x002f]): Uint8Array {
  const random = Array.from({ length: 32 }, () => Math.floor(rng() * 256))
  const sid = Array.from({ length: 32 }, () => Math.floor(rng() * 256))
  const sniBytes = [...enc.encode(sni)]
  const exts = [
    ...ext(0, [...be16(sniBytes.length + 3), 0, ...be16(sniBytes.length), ...sniBytes]),
    ...ext(23, []),
    ...ext(65281, [0]),
    ...ext(10, [0, 6, 0, 0x1d, 0, 0x17, 0, 0x18]),
    ...ext(11, [1, 0]),
    ...ext(16, [0, 12, 2, ...enc.encode('h2'), 8, ...enc.encode('http/1.1')]),
    ...ext(13, [0, 8, 4, 3, 8, 4, 4, 1, 5, 3]),
    ...ext(51, [0, 38, 0, 0x1d, 0, 32, ...Array.from({ length: 32 }, () => Math.floor(rng() * 256))]),
    ...ext(45, [1, 1]),
    ...ext(43, [4, 3, 4, 3, 3]),
  ]
  const body = [
    3,
    3,
    ...random,
    sid.length,
    ...sid,
    ...be16(suites.length * 2),
    ...suites.flatMap(be16),
    1,
    0,
    ...be16(exts.length),
    ...exts,
  ]
  return Uint8Array.from(tlsRecord(22, handshake(1, body), 0x0301))
}

export function tlsServerHello(rng: () => number, suite = 0x1301, tls13 = true): Uint8Array {
  const random = Array.from({ length: 32 }, () => Math.floor(rng() * 256))
  const sid = Array.from({ length: 32 }, () => Math.floor(rng() * 256))
  const exts = tls13
    ? [...ext(43, [3, 4]), ...ext(51, [0, 0x1d, 0, 32, ...Array.from({ length: 32 }, () => Math.floor(rng() * 256))])]
    : [...ext(65281, [0]), ...ext(23, [])]
  const body = [3, 3, ...random, sid.length, ...sid, ...be16(suite), 0, ...be16(exts.length), ...exts]
  const out = [...tlsRecord(22, handshake(2, body))]
  if (tls13) out.push(...tlsRecord(20, [1]))
  return Uint8Array.from(out)
}

export function tlsAppData(len: number, rng: () => number): Uint8Array {
  return Uint8Array.from(tlsRecord(23, Array.from({ length: len }, () => Math.floor(rng() * 256))))
}

export function tlsChangeCipherSpec(): Uint8Array {
  return Uint8Array.from(tlsRecord(20, [1]))
}

export function tlsAlert(level: number, desc: number): Uint8Array {
  return Uint8Array.from(tlsRecord(21, [level, desc]))
}

// ---------------------------------------------------------------- Deterministic RNG

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// ---------------------------------------------------------------- Scenario timeline

export interface Host {
  mac: string
  ip: string
}

/** Collects frames with a monotonically increasing clock. */
export class Timeline {
  frames: FrameToWrite[] = []
  t: number
  constructor(start: number) {
    this.t = start
  }
  wait(sec: number): this {
    this.t += sec
    return this
  }
  push(data: Uint8Array, gap = 0.0005): this {
    this.t += gap
    this.frames.push({ ts: this.t, data })
    return this
  }
  ip(from: Host, to: Host, proto: number, payload: Uint8Array, gap?: number, o?: Ip4Opts, l2to?: string): this {
    return this.push(ethernet(from.mac, l2to ?? to.mac, 0x0800, ipv4(from.ip, to.ip, proto, payload, o)), gap)
  }
}

/** Simulates a TCP connection with correct seq/ack bookkeeping. */
export interface TcpSessionOpts {
  client: Host
  server: Host
  cport: number
  sport: number
  rtt?: number
  ttl?: { c: number; s: number }
  /** MAC of the router on the client's LAN when the server is remote (capture taken at the client). */
  gwMac?: string
}

export class TcpSession {
  cseq: number
  sseq: number
  client: Host
  server: Host
  cport: number
  sport: number
  private id = 0x1000
  private tl: Timeline
  private rtt: number
  private ttl: { c: number; s: number }
  private gwMac?: string
  constructor(tl: Timeline, o: TcpSessionOpts, rng: () => number) {
    this.tl = tl
    this.client = o.client
    this.server = o.server
    this.cport = o.cport
    this.sport = o.sport
    this.rtt = o.rtt ?? 0.02
    this.ttl = o.ttl ?? { c: 64, s: 56 }
    this.gwMac = o.gwMac
    this.cseq = Math.floor(rng() * 0xffffffff) >>> 0
    this.sseq = Math.floor(rng() * 0xffffffff) >>> 0
  }
  private emit(fromClient: boolean, flags: TcpFlagsIn, payload?: Uint8Array, opts?: TcpOpts, gap?: number) {
    const [a, b] = fromClient ? [this.client, this.server] : [this.server, this.client]
    const [sp, dp] = fromClient ? [this.cport, this.sport] : [this.sport, this.cport]
    const seq = fromClient ? this.cseq : this.sseq
    const ack = flags.ack ? (fromClient ? this.sseq : this.cseq) : 0
    const seg = tcp(sp, dp, seq, ack, flags, payload, { window: fromClient ? 64240 : 65160, ...opts })
    const srcMac = fromClient ? a.mac : (this.gwMac ?? a.mac)
    const dstMac = fromClient ? (this.gwMac ?? b.mac) : b.mac
    const frame = ethernet(srcMac, dstMac, 0x0800, ipv4(a.ip, b.ip, 6, seg, { ttl: fromClient ? this.ttl.c : this.ttl.s, id: this.id++ }))
    this.tl.push(frame, gap ?? this.rtt / 2)
    const adv = (payload?.length ?? 0) + (flags.syn ? 1 : 0) + (flags.fin ? 1 : 0)
    if (fromClient) this.cseq = (this.cseq + adv) >>> 0
    else this.sseq = (this.sseq + adv) >>> 0
  }
  handshake(): this {
    this.emit(true, { syn: true }, undefined, { mss: 1460, sackPerm: true, wscale: 7 }, 0.001)
    this.emit(false, { syn: true, ack: true }, undefined, { mss: 1460, sackPerm: true, wscale: 7 })
    this.emit(true, { ack: true })
    return this
  }
  send(fromClient: boolean, data: Uint8Array | string, gap?: number): this {
    const bytes = typeof data === 'string' ? text(data) : data
    const mss = 1448
    for (let i = 0; i < bytes.length; i += mss) {
      this.emit(fromClient, { ack: true, psh: i + mss >= bytes.length }, bytes.subarray(i, i + mss), undefined, i === 0 ? gap : 0.0002)
    }
    return this
  }
  ack(fromClient: boolean, gap?: number): this {
    this.emit(fromClient, { ack: true }, undefined, undefined, gap)
    return this
  }
  /** Request/response exchange with ACKs. */
  exchange(req: string | Uint8Array, resp: string | Uint8Array, think = 0.01): this {
    this.send(true, req)
    this.send(false, resp, think)
    this.ack(true)
    return this
  }
  close(clientFirst = true): this {
    this.emit(clientFirst, { fin: true, ack: true })
    this.emit(!clientFirst, { fin: true, ack: true })
    this.emit(clientFirst, { ack: true })
    return this
  }
  reset(fromClient: boolean): this {
    this.emit(fromClient, { rst: true, ack: true })
    return this
  }
}
