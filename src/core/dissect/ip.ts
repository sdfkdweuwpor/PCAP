// Layer 3: IPv4 and IPv6 (with extension-header walking).

import { hex, ipv4, ipv6, u16, u32, u8 } from '../bytes'
import { add, layer, type DissectCtx } from './tree'

export const IP_PROTOS: Record<number, string> = {
  0: 'IPv6 Hop-by-Hop',
  1: 'ICMP',
  2: 'IGMP',
  6: 'TCP',
  17: 'UDP',
  41: 'IPv6',
  43: 'IPv6 Routing',
  44: 'IPv6 Fragment',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPv6',
  59: 'No Next Header',
  60: 'IPv6 Destination Options',
  89: 'OSPF',
  132: 'SCTP',
}
export const ipProtoName = (p: number) => IP_PROTOS[p] ?? `Unknown`

export interface Transport {
  proto: number
  offset: number
  length: number
  /** Only the first fragment carries a transport header. */
  fragmentOnly: boolean
}

export function ipv4Checksum(b: Uint8Array, o: number, len: number): number {
  let sum = 0
  for (let i = 0; i < len; i += 2) {
    if (i === 10) continue
    sum += (b[o + i] << 8) | (b[o + i + 1] ?? 0)
  }
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16)
  return ~sum & 0xffff
}

export function dissectIpv4(ctx: DissectCtx, o: number): Transport {
  const b = ctx.b
  const vihl = u8(b, o)
  const ihl = (vihl & 0x0f) * 4
  if ((vihl >> 4) !== 4 || ihl < 20) throw new Error(`Invalid IPv4 header (version ${vihl >> 4}, header length ${ihl} bytes)`)
  const tos = u8(b, o + 1)
  const totalLen = u16(b, o + 2)
  const id = u16(b, o + 4)
  const ff = u16(b, o + 6)
  const ttl = u8(b, o + 8)
  const proto = u8(b, o + 9)
  const csum = u16(b, o + 10)
  const src = ipv4(b, o + 12)
  const dst = ipv4(b, o + 16)
  const df = !!(ff & 0x4000)
  const mf = !!(ff & 0x2000)
  const fragOffset = (ff & 0x1fff) * 8
  const l = layer(ctx, `Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`, 'ip', o, ihl)
  add(l, '0100 .... = Version', 'ip.version', 4, o, 1)
  add(l, `.... ${((vihl & 0xf) >>> 0).toString(2).padStart(4, '0')} = Header Length`, 'ip.hdr_len', `${ihl} bytes (${vihl & 0xf})`, o, 1)
  const ds = add(l, 'Differentiated Services Field', 'ip.dsfield', hex(tos, 2), o + 1, 1)
  add(ds, 'DSCP', 'ip.dsfield.dscp', tos >> 2, o + 1, 1)
  add(ds, 'ECN', 'ip.dsfield.ecn', tos & 3, o + 1, 1)
  add(l, 'Total Length', 'ip.len', totalLen, o + 2, 2)
  add(l, 'Identification', 'ip.id', `${hex(id)} (${id})`, o + 4, 2)
  const flags = add(l, 'Flags', 'ip.flags', `${hex(ff >> 13, 1)}${df ? ", Don't fragment" : ''}${mf ? ', More fragments' : ''}`, o + 6, 1)
  add(flags, '0... .... = Reserved bit', 'ip.flags.rb', ff & 0x8000 ? 'Set' : 'Not set', o + 6, 1)
  add(flags, `.${df ? 1 : 0}.. .... = Don't fragment`, 'ip.flags.df', df ? 'Set' : 'Not set', o + 6, 1)
  add(flags, `..${mf ? 1 : 0}. .... = More fragments`, 'ip.flags.mf', mf ? 'Set' : 'Not set', o + 6, 1)
  add(l, 'Fragment Offset', 'ip.frag_offset', fragOffset, o + 6, 2)
  add(l, 'Time to Live', 'ip.ttl', ttl, o + 8, 1)
  add(l, 'Protocol', 'ip.proto', `${ipProtoName(proto)} (${proto})`, o + 9, 1)
  const calc = ipv4Checksum(b, o, ihl)
  add(l, 'Header Checksum', 'ip.checksum', `${hex(csum)} [${calc === csum ? 'correct' : `incorrect, should be ${hex(calc)}`}]`, o + 10, 2, calc === csum ? {} : { warn: true })
  add(l, 'Source Address', 'ip.src', src, o + 12, 4)
  add(l, 'Destination Address', 'ip.dst', dst, o + 16, 4)
  if (ihl > 20) add(l, 'Options', 'ip.options', `${ihl - 20} bytes`, o + 20, ihl - 20)
  ctx.facts.ip = { version: 4, src, dst, ttl, proto, len: totalLen, id, df, mf, fragOffset }
  ctx.src = src
  ctx.dst = dst
  ctx.protocol = 'IPv4'
  const end = Math.min(b.length, o + (totalLen || b.length - o))
  const fragmentOnly = fragOffset > 0
  if (fragmentOnly || mf) {
    ctx.info = `Fragmented IP protocol (proto=${ipProtoName(proto)} ${proto}, off=${fragOffset}, ID=${hex(id)})${mf ? ' [More fragments]' : ''}`
  } else {
    ctx.info = `${ipProtoName(proto)} ${src} → ${dst}`
  }
  return { proto, offset: o + ihl, length: Math.max(0, end - (o + ihl)), fragmentOnly }
}

export function dissectIpv6(ctx: DissectCtx, o: number): Transport {
  const b = ctx.b
  const w = u32(b, o)
  const tc = (w >>> 20) & 0xff
  const flow = w & 0xfffff
  const payLen = u16(b, o + 4)
  let next = u8(b, o + 6)
  const hop = u8(b, o + 7)
  const src = ipv6(b, o + 8)
  const dst = ipv6(b, o + 24)
  const l = layer(ctx, `Internet Protocol Version 6, Src: ${src}, Dst: ${dst}`, 'ipv6', o, 40)
  add(l, '0110 .... = Version', 'ipv6.version', 6, o, 1)
  add(l, 'Traffic Class', 'ipv6.tclass', hex(tc, 2), o, 2)
  add(l, 'Flow Label', 'ipv6.flow', hex(flow, 5), o + 1, 3)
  add(l, 'Payload Length', 'ipv6.plen', payLen, o + 4, 2)
  add(l, 'Next Header', 'ipv6.nxt', `${ipProtoName(next)} (${next})`, o + 6, 1)
  add(l, 'Hop Limit', 'ipv6.hlim', hop, o + 7, 1)
  add(l, 'Source Address', 'ipv6.src', src, o + 8, 16)
  add(l, 'Destination Address', 'ipv6.dst', dst, o + 24, 16)
  let p = o + 40
  // Payload length 0 means a jumbogram (or a capture tool that zeroed it): use the rest of the frame.
  const end = payLen ? Math.min(b.length, p + payLen) : b.length
  let fragmentOnly = false
  // Walk extension headers.
  while (next === 0 || next === 43 || next === 60 || next === 44) {
    if (p + 2 > end) break
    const hn = u8(b, p)
    if (next === 44) {
      const fo = u16(b, p + 2)
      const off = fo & 0xfff8
      const ext = add(l, 'Fragment Header', 'ipv6.fraghdr', `offset=${off}${fo & 1 ? ', more' : ''}`, p, 8)
      add(ext, 'Next Header', 'ipv6.fraghdr.nxt', `${ipProtoName(hn)} (${hn})`, p, 1)
      add(ext, 'Offset', 'ipv6.fraghdr.offset', off, p + 2, 2)
      if (off > 0) fragmentOnly = true
      p += 8
    } else {
      const len = (u8(b, p + 1) + 1) * 8
      add(l, ipProtoName(next), `ipv6.ext.${next}`, `${len} bytes`, p, len)
      p += len
    }
    next = hn
  }
  l.length = p - o
  ctx.facts.ip = { version: 6, src, dst, ttl: hop, proto: next, len: payLen + 40 }
  ctx.src = src
  ctx.dst = dst
  ctx.protocol = 'IPv6'
  ctx.info = `${ipProtoName(next)} ${src} → ${dst}`
  return { proto: next, offset: p, length: Math.max(0, end - p), fragmentOnly }
}
