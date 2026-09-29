// Frame dissection entry point: link layer → network → transport → application.

import type { Dissection, LinkType } from '../types'
import { dissectDhcp, dissectNtp, dissectSnmp, dissectSsh, dissectTextProto } from './app'
import { dissectDns } from './dns'
import { dissectHttp, looksLikeHttp } from './http'
import { dissectIpv4, dissectIpv6 } from './ip'
import { dissectArp, dissectEthernet, dissectNull, dissectSll, dissectSll2, rawIpType, type NextLayer } from './link'
import { dissectTls, looksLikeTls } from './tls'
import { dissectIcmp, dissectTcp, dissectUdp, type Payload } from './transport'
import { add, dataLayer, layer, type DissectCtx } from './tree'

export interface FrameMeta {
  no: number
  ts: number
  relTime: number
  origLen: number
  linkType: LinkType
  interfaceId?: number
}

export interface DissectOptions {
  tcpIsn?: Map<string, number>
}

const LINK_NAMES: Record<number, string> = {
  0: 'Null/Loopback',
  1: 'Ethernet',
  101: 'Raw IP',
  113: 'Linux cooked-mode capture v1',
  228: 'Raw IPv4',
  229: 'Raw IPv6',
  276: 'Linux cooked-mode capture v2',
}

export function dissectFrame(b: Uint8Array, meta: FrameMeta, opts: DissectOptions = {}): Dissection {
  const ctx: DissectCtx = {
    b,
    layers: [],
    facts: { protos: [] },
    src: '',
    dst: '',
    protocol: 'Data',
    info: '',
    color: 'other',
    tcpIsn: opts.tcpIsn,
    missing: Math.max(0, meta.origLen - b.length),
  }
  const frame = layer(
    ctx,
    `Frame ${meta.no}: ${meta.origLen} bytes on wire (${meta.origLen * 8} bits), ${b.length} bytes captured (${b.length * 8} bits)`,
    'frame',
    0,
    b.length,
  )
  const d = new Date(meta.ts * 1000)
  add(frame, 'Encapsulation type', 'frame.encap_type', `${LINK_NAMES[meta.linkType] ?? 'Unknown'} (${meta.linkType})`, 0, 0)
  if (meta.interfaceId !== undefined) add(frame, 'Interface id', 'frame.interface_id', meta.interfaceId, 0, 0)
  add(frame, 'Arrival Time', 'frame.time', isNaN(d.getTime()) ? String(meta.ts) : d.toISOString(), 0, 0)
  add(frame, 'Epoch Arrival Time', 'frame.time_epoch', meta.ts.toFixed(6), 0, 0)
  add(frame, 'Time since reference or first frame', 'frame.time_relative', `${meta.relTime.toFixed(6)} seconds`, 0, 0)
  add(frame, 'Frame Number', 'frame.number', meta.no, 0, 0)
  add(frame, 'Frame Length', 'frame.len', `${meta.origLen} bytes`, 0, 0)
  add(frame, 'Capture Length', 'frame.cap_len', `${b.length} bytes`, 0, 0)
  const protosNode = add(frame, '[Protocols in frame]', 'frame.protocols', '', 0, 0)

  try {
    let next: NextLayer | null = null
    switch (meta.linkType) {
      case 1:
        next = dissectEthernet(ctx, 0)
        break
      case 113:
        next = dissectSll(ctx, 0)
        break
      case 276:
        next = dissectSll2(ctx, 0)
        break
      case 0:
        next = dissectNull(ctx, 0)
        break
      case 101:
        next = { etherType: rawIpType(b, 0), offset: 0 }
        break
      case 228:
        next = { etherType: 0x0800, offset: 0 }
        break
      case 229:
        next = { etherType: 0x86dd, offset: 0 }
        break
      default:
        dataLayer(ctx, 0, b.length)
    }
    if (next) dissectNetwork(ctx, next)
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    ctx.facts.malformed = msg
    const l = layer(ctx, `[Malformed Packet: ${ctx.protocol}]`, '_ws.malformed', 0, 0)
    add(l, '[Expert Info (Error/Malformed)]', '_ws.malformed.expert', msg, 0, 0, { warn: true })
    ctx.color = 'error'
    if (!ctx.info) ctx.info = `[Malformed Packet] ${msg}`
    else ctx.info += ' [Malformed Packet]'
  }
  protosNode.value = ctx.facts.protos.join(':')
  if (!ctx.info) ctx.info = `${b.length} bytes`
  return {
    layers: ctx.layers,
    facts: ctx.facts,
    src: ctx.src,
    dst: ctx.dst,
    protocol: ctx.protocol,
    info: ctx.info,
    color: ctx.color,
  }
}

function dissectNetwork(ctx: DissectCtx, next: NextLayer): void {
  const b = ctx.b
  const o = next.offset
  if (o >= b.length) return
  switch (next.etherType) {
    case 0x0806:
      dissectArp(ctx, o)
      return
    case 0x0800:
    case 0x86dd: {
      const t = next.etherType === 0x0800 ? dissectIpv4(ctx, o) : dissectIpv6(ctx, o)
      if (t.fragmentOnly) {
        dataLayer(ctx, t.offset, t.length, 'IP fragment data')
        return
      }
      dissectTransport(ctx, t.proto, t.offset, t.length, t.declared)
      return
    }
    default:
      dataLayer(ctx, o, b.length - o)
  }
}

function dissectTransport(ctx: DissectCtx, proto: number, o: number, len: number, declared?: number): void {
  if (len <= 0) return
  switch (proto) {
    case 6: {
      const p = dissectTcp(ctx, o, len, declared)
      if (p.length > 0) dissectTcpApp(ctx, p)
      return
    }
    case 17: {
      const p = dissectUdp(ctx, o, len)
      if (p.length > 0) dissectUdpApp(ctx, p)
      return
    }
    case 1:
      dissectIcmp(ctx, o, len, false)
      return
    case 58:
      dissectIcmp(ctx, o, len, true)
      return
    default:
      dataLayer(ctx, o, len)
  }
}

const has = (p: Payload, ...ports: number[]) => ports.includes(p.srcPort) || ports.includes(p.dstPort)

function dissectTcpApp(ctx: DissectCtx, p: Payload): void {
  const b = ctx.b
  const { offset: o, length: len } = p
  const toServer = (port: number) => p.dstPort === port
  // TLS is often run on the HTTP-alt ports, so sniff for a TLS record before trusting the port number.
  if (!looksLikeHttp(b, o, len) && looksLikeTls(b, o, len) && !has(p, 80)) return dissectTls(ctx, o, len)
  if (has(p, 80, 8080, 8000, 8008) || looksLikeHttp(b, o, len)) return dissectHttp(ctx, o, len)
  if (has(p, 443, 8443, 993, 995, 465, 636) || looksLikeTls(b, o, len)) return dissectTls(ctx, o, len)
  if (has(p, 21)) return dissectTextProto(ctx, 'FTP', o, len, toServer(21))
  if (has(p, 25, 587)) return dissectTextProto(ctx, 'SMTP', o, len, toServer(25) || toServer(587))
  if (has(p, 110)) return dissectTextProto(ctx, 'POP', o, len, toServer(110))
  if (has(p, 143)) return dissectTextProto(ctx, 'IMAP', o, len, toServer(143))
  if (has(p, 23)) return dissectTextProto(ctx, 'Telnet', o, len, toServer(23))
  if (has(p, 22)) return dissectSsh(ctx, o, len)
  if (has(p, 53)) return dissectDns(ctx, o, len, true)
  if (has(p, 20)) {
    const l = layer(ctx, 'FTP Data', 'ftp-data', o, len)
    add(l, 'FTP Data', 'ftp-data.data', `${len} bytes`, o, len)
    ctx.protocol = 'FTP-DATA'
    ctx.info = `FTP Data: ${len} bytes`
    return
  }
  dataLayer(ctx, o, len)
}

function dissectUdpApp(ctx: DissectCtx, p: Payload): void {
  const { offset: o, length: len } = p
  if (has(p, 53, 5353, 5355)) return dissectDns(ctx, o, len)
  if (has(p, 67, 68)) return dissectDhcp(ctx, o, len)
  if (has(p, 123)) return dissectNtp(ctx, o, len)
  if (has(p, 161, 162) && dissectSnmp(ctx, o, len)) return
  dataLayer(ctx, o, len)
}
