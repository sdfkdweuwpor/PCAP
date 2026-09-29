// Layer 4: TCP, UDP, ICMP, ICMPv6.

import { hex, u16, u32, u8 } from '../bytes'
import type { TcpFlags } from '../types'
import { add, flowKey, layer, type DissectCtx } from './tree'

const ICMP_TYPES: Record<number, string> = {
  0: 'Echo (ping) reply',
  3: 'Destination unreachable',
  4: 'Source quench',
  5: 'Redirect',
  8: 'Echo (ping) request',
  9: 'Router advertisement',
  10: 'Router solicitation',
  11: 'Time-to-live exceeded',
  12: 'Parameter problem',
  13: 'Timestamp request',
  14: 'Timestamp reply',
}
const ICMP_UNREACH: Record<number, string> = {
  0: 'Network unreachable',
  1: 'Host unreachable',
  2: 'Protocol unreachable',
  3: 'Port unreachable',
  4: 'Fragmentation needed',
  9: 'Network administratively prohibited',
  10: 'Host administratively prohibited',
  13: 'Communication administratively filtered',
}
const ICMP6_TYPES: Record<number, string> = {
  1: 'Destination Unreachable',
  2: 'Packet Too Big',
  3: 'Time Exceeded',
  4: 'Parameter Problem',
  128: 'Echo (ping) request',
  129: 'Echo (ping) reply',
  133: 'Router Solicitation',
  134: 'Router Advertisement',
  135: 'Neighbor Solicitation',
  136: 'Neighbor Advertisement',
  137: 'Redirect',
}

export function dissectIcmp(ctx: DissectCtx, o: number, len: number, v6: boolean): void {
  const b = ctx.b
  const type = u8(b, o)
  const code = u8(b, o + 1)
  const csum = u16(b, o + 2)
  const typeName = (v6 ? ICMP6_TYPES[type] : ICMP_TYPES[type]) ?? `Type ${type}`
  const name = v6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol'
  const l = layer(ctx, name, v6 ? 'icmpv6' : 'icmp', o, len)
  add(l, 'Type', v6 ? 'icmpv6.type' : 'icmp.type', `${type} (${typeName})`, o, 1)
  const codeName = !v6 && type === 3 ? ICMP_UNREACH[code] : undefined
  add(l, 'Code', v6 ? 'icmpv6.code' : 'icmp.code', codeName ? `${code} (${codeName})` : code, o + 1, 1)
  add(l, 'Checksum', v6 ? 'icmpv6.checksum' : 'icmp.checksum', hex(csum), o + 2, 2)
  ctx.facts.icmp = { v6, type, code, typeName }
  ctx.protocol = v6 ? 'ICMPv6' : 'ICMP'
  const isEcho = v6 ? type === 128 || type === 129 : type === 0 || type === 8
  const isError = v6 ? type < 128 : type === 3 || type === 11 || type === 12 || type === 5
  ctx.color = isError ? 'icmp-error' : 'icmp'
  if (isEcho && len >= 8) {
    const id = u16(b, o + 4)
    const seq = u16(b, o + 6)
    add(l, 'Identifier', v6 ? 'icmpv6.echo.identifier' : 'icmp.ident', `${id} (${hex(id)})`, o + 4, 2)
    add(l, 'Sequence Number', v6 ? 'icmpv6.echo.sequence_number' : 'icmp.seq', seq, o + 6, 2)
    if (len > 8) add(l, 'Data', 'data.data', `${len - 8} bytes`, o + 8, len - 8)
    const req = v6 ? type === 128 : type === 8
    ctx.info = `Echo (ping) ${req ? 'request' : 'reply'}  id=${hex(id)}, seq=${seq}, ttl=${ctx.facts.ip?.ttl ?? '?'}`
  } else {
    ctx.info = codeName ? `${typeName} (${codeName})` : typeName
    if (len > 8) add(l, isError ? 'Original datagram' : 'Data', 'icmp.data', `${len - 8} bytes`, o + 8, len - 8)
  }
}

export function tcpFlagString(f: TcpFlags): string {
  const names: string[] = []
  if (f.cwr) names.push('CWR')
  if (f.ece) names.push('ECE')
  if (f.urg) names.push('URG')
  if (f.fin) names.push('FIN')
  if (f.syn) names.push('SYN')
  if (f.rst) names.push('RST')
  if (f.psh) names.push('PSH')
  if (f.ack) names.push('ACK')
  return names.join(', ')
}

export interface Payload {
  offset: number
  length: number
  srcPort: number
  dstPort: number
}

/** `declared` is the payload length the IP header claims, when the capture may have cut the frame short. */
export function dissectTcp(ctx: DissectCtx, o: number, len: number, declared?: number): Payload {
  const b = ctx.b
  const sp = u16(b, o)
  const dp = u16(b, o + 2)
  const seq = u32(b, o + 4)
  const ack = u32(b, o + 8)
  const offFlags = u16(b, o + 12)
  const hlen = ((offFlags >> 12) & 0xf) * 4
  if (hlen < 20) throw new Error(`Invalid TCP data offset (${hlen} bytes, minimum 20)`)
  const fl = offFlags & 0x1ff
  const win = u16(b, o + 14)
  const csum = u16(b, o + 16)
  const urgPtr = u16(b, o + 18)
  const flags: TcpFlags = {
    fin: !!(fl & 0x01),
    syn: !!(fl & 0x02),
    rst: !!(fl & 0x04),
    psh: !!(fl & 0x08),
    ack: !!(fl & 0x10),
    urg: !!(fl & 0x20),
    ece: !!(fl & 0x40),
    cwr: !!(fl & 0x80),
  }
  const flagStr = tcpFlagString(flags)
  const payloadOffset = o + hlen
  const payloadLen = Math.max(0, Math.min(len, b.length - o) - hlen)
  // Sequence space actually sent: more than was captured only if the capture cut the frame, and never by more
  // than the bytes it cut (a corrupt IP length must not make Follow Stream skip real data).
  const segLen = payloadLen + Math.min(ctx.missing ?? 0, Math.max(0, (declared ?? len) - hlen - payloadLen))

  const src = ctx.src
  const dst = ctx.dst
  const isnFwd = ctx.tcpIsn?.get(flowKey(src, sp, dst, dp))
  const isnRev = ctx.tcpIsn?.get(flowKey(dst, dp, src, sp))
  const relSeq = isnFwd !== undefined ? (seq - isnFwd + 0x100000000) % 0x100000000 : undefined
  const relAck = isnRev !== undefined && flags.ack ? (ack - isnRev + 0x100000000) % 0x100000000 : undefined

  const l = layer(
    ctx,
    `Transmission Control Protocol, Src Port: ${sp}, Dst Port: ${dp}, Seq: ${relSeq ?? seq}${flags.ack ? `, Ack: ${relAck ?? ack}` : ''}, Len: ${payloadLen}`,
    'tcp',
    o,
    hlen,
  )
  add(l, 'Source Port', 'tcp.srcport', sp, o, 2)
  add(l, 'Destination Port', 'tcp.dstport', dp, o + 2, 2)
  add(l, '[TCP Segment Len]', 'tcp.len', payloadLen, o + 12, 0)
  if (relSeq !== undefined) {
    add(l, 'Sequence Number', 'tcp.seq', `${relSeq}    (relative sequence number)`, o + 4, 4)
    add(l, 'Sequence Number (raw)', 'tcp.seq_raw', seq, o + 4, 4)
  } else add(l, 'Sequence Number', 'tcp.seq', seq, o + 4, 4)
  if (flags.ack && relAck !== undefined) {
    add(l, 'Acknowledgment Number', 'tcp.ack', `${relAck}    (relative ack number)`, o + 8, 4)
    add(l, 'Acknowledgment Number (raw)', 'tcp.ack_raw', ack, o + 8, 4)
  } else add(l, 'Acknowledgment Number', 'tcp.ack', flags.ack ? ack : `${ack} (not used: ACK flag not set)`, o + 8, 4)
  add(l, `${((offFlags >> 12) & 0xf).toString(2).padStart(4, '0')} .... = Header Length`, 'tcp.hdr_len', `${hlen} bytes (${hlen / 4})`, o + 12, 1)
  const fnode = add(l, 'Flags', 'tcp.flags', `${hex(fl, 3)} (${flagStr || 'none'})`, o + 12, 2)
  const bit = (mask: number, label: string, key: string, on: boolean) => {
    let s = ''
    for (let i = 11; i >= 0; i--) {
      s += 1 << i === mask ? (on ? '1' : '0') : '.'
      if (i % 4 === 0 && i) s += ' '
    }
    add(fnode, `${s} = ${label}`, `tcp.flags.${key}`, on ? 'Set' : 'Not set', o + 12, 2)
  }
  bit(0x80, 'Congestion Window Reduced', 'cwr', flags.cwr)
  bit(0x40, 'ECN-Echo', 'ece', flags.ece)
  bit(0x20, 'Urgent', 'urg', flags.urg)
  bit(0x10, 'Acknowledgment', 'ack', flags.ack)
  bit(0x08, 'Push', 'push', flags.psh)
  bit(0x04, 'Reset', 'reset', flags.rst)
  bit(0x02, 'Syn', 'syn', flags.syn)
  bit(0x01, 'Fin', 'fin', flags.fin)
  add(l, 'Window', 'tcp.window_size_value', win, o + 14, 2)
  add(l, 'Checksum', 'tcp.checksum', `${hex(csum)} [unverified]`, o + 16, 2)
  add(l, 'Urgent Pointer', 'tcp.urgent_pointer', urgPtr, o + 18, 2)

  const opts: string[] = []
  let mss: number | undefined
  let wscale: number | undefined
  let sackPerm = false
  if (hlen > 20) {
    const onode = add(l, 'Options', 'tcp.options', `(${hlen - 20} bytes)`, o + 20, hlen - 20)
    let p = o + 20
    const end = Math.min(o + hlen, b.length)
    while (p < end) {
      const kind = b[p]
      if (kind === 0) {
        add(onode, 'End of Option List (EOL)', 'tcp.option_kind', 0, p, 1)
        break
      }
      if (kind === 1) {
        add(onode, 'No-Operation (NOP)', 'tcp.options.nop', 1, p, 1)
        p++
        continue
      }
      const olen = p + 1 < end ? b[p + 1] : 0
      if (olen < 2 || p + olen > end) break
      if (kind === 2 && olen === 4) {
        mss = u16(b, p + 2)
        const m = add(onode, 'Maximum segment size', 'tcp.options.mss', `${mss} bytes`, p, 4)
        add(m, 'MSS Value', 'tcp.options.mss_val', mss, p + 2, 2)
        opts.push(`MSS=${mss}`)
      } else if (kind === 3 && olen === 3) {
        wscale = b[p + 2]
        const w = add(onode, 'Window scale', 'tcp.options.wscale', `${wscale} (multiply by ${2 ** wscale})`, p, 3)
        add(w, 'Shift count', 'tcp.options.wscale.shift', wscale, p + 2, 1)
        opts.push(`WS=${2 ** wscale}`)
      } else if (kind === 4) {
        sackPerm = true
        add(onode, 'SACK permitted', 'tcp.options.sack_perm', 'Set', p, olen)
        opts.push('SACK_PERM')
      } else if (kind === 5) {
        add(onode, 'SACK', 'tcp.options.sack', `${(olen - 2) / 8} block(s)`, p, olen)
      } else if (kind === 8 && olen === 10) {
        const tsv = u32(b, p + 2)
        const tse = u32(b, p + 6)
        add(onode, 'Timestamps', 'tcp.options.timestamp', `TSval ${tsv}, TSecr ${tse}`, p, 10)
        opts.push(`TSval=${tsv}`, `TSecr=${tse}`)
      } else add(onode, `Option kind ${kind}`, 'tcp.option_kind', kind, p, olen)
      p += olen
    }
  }

  ctx.facts.tcp = {
    srcPort: sp,
    dstPort: dp,
    seq,
    ack,
    relSeq,
    relAck,
    flags,
    flagStr,
    window: win,
    payloadLen,
    ...(segLen > payloadLen ? { segLen } : {}),
    payloadOffset,
    options: opts,
    mss,
    wscale,
    sackPerm,
  }
  ctx.protocol = 'TCP'
  ctx.color = flags.rst ? 'tcp-rst' : flags.syn ? 'tcp-syn' : flags.fin ? 'tcp-fin' : 'tcp'
  const parts = [`${sp} → ${dp} [${flagStr}]`, `Seq=${relSeq ?? seq}`]
  if (flags.ack) parts.push(`Ack=${relAck ?? ack}`)
  parts.push(`Win=${win}`, `Len=${payloadLen}`)
  if (flags.syn) parts.push(...opts.filter((x) => !x.startsWith('TS')))
  ctx.info = parts.join(' ')
  if (payloadLen > 0) add(l, '[TCP payload]', 'tcp.payload', `${payloadLen} bytes`, payloadOffset, payloadLen)
  return { offset: payloadOffset, length: payloadLen, srcPort: sp, dstPort: dp }
}

export function dissectUdp(ctx: DissectCtx, o: number, len: number): Payload {
  const b = ctx.b
  const sp = u16(b, o)
  const dp = u16(b, o + 2)
  const ulen = u16(b, o + 4)
  const csum = u16(b, o + 6)
  const l = layer(ctx, `User Datagram Protocol, Src Port: ${sp}, Dst Port: ${dp}`, 'udp', o, 8)
  add(l, 'Source Port', 'udp.srcport', sp, o, 2)
  add(l, 'Destination Port', 'udp.dstport', dp, o + 2, 2)
  add(l, 'Length', 'udp.length', ulen, o + 4, 2)
  add(l, 'Checksum', 'udp.checksum', `${hex(csum)} [unverified]`, o + 6, 2)
  const payloadLen = Math.max(0, Math.min(ulen || len, len, b.length - o) - 8)
  if (payloadLen > 0) add(l, 'UDP payload', 'udp.payload', `${payloadLen} bytes`, o + 8, payloadLen)
  ctx.facts.udp = { srcPort: sp, dstPort: dp, len: ulen, payloadOffset: o + 8, payloadLen }
  ctx.protocol = 'UDP'
  ctx.color = 'udp'
  ctx.info = `${sp} → ${dp} Len=${payloadLen}`
  return { offset: o + 8, length: payloadLen, srcPort: sp, dstPort: dp }
}
