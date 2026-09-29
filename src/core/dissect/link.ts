// Layer 2: Ethernet II, 802.1Q, Linux cooked (SLL/SLL2), BSD loopback, raw IP; plus ARP.

import { hex, ipv4, mac, u16, u32, u32le, u8 } from '../bytes'
import { add, layer, type DissectCtx } from './tree'

export const ETHERTYPES: Record<number, string> = {
  0x0800: 'IPv4',
  0x0806: 'ARP',
  0x86dd: 'IPv6',
  0x8100: '802.1Q Virtual LAN',
  0x88a8: '802.1ad (QinQ)',
  0x88cc: 'LLDP',
  0x8863: 'PPPoE Discovery',
  0x8864: 'PPPoE Session',
}

export const etherTypeName = (t: number) => ETHERTYPES[t] ?? 'Unknown'

export interface NextLayer {
  etherType: number
  offset: number
}

export function dissectEthernet(ctx: DissectCtx, o: number): NextLayer {
  const b = ctx.b
  const dst = mac(b, o)
  const src = mac(b, o + 6)
  let type = u16(b, o + 12)
  const l = layer(ctx, `Ethernet II, Src: ${src}, Dst: ${dst}`, 'eth', o, 14)
  const d = add(l, 'Destination', 'eth.dst', dst, o, 6)
  if (dst === 'ff:ff:ff:ff:ff:ff') add(d, '[Broadcast]', 'eth.dst.bcast', 'This frame goes to every host on the LAN', o, 6)
  else if (b[o] & 1) add(d, '[Multicast]', 'eth.dst.ig', 'Group address', o, 1)
  add(l, 'Source', 'eth.src', src, o + 6, 6)
  add(l, 'Type', 'eth.type', `${etherTypeName(type)} (${hex(type)})`, o + 12, 2)
  ctx.facts.eth = { src, dst, type }
  ctx.src = src
  ctx.dst = dst
  ctx.protocol = 'Ethernet'
  let off = o + 14
  while (type === 0x8100 || type === 0x88a8) {
    const tci = u16(b, off)
    const inner = u16(b, off + 2)
    const id = tci & 0x0fff
    const pri = tci >> 13
    const v = layer(ctx, `802.1Q Virtual LAN, PRI: ${pri}, DEI: ${(tci >> 12) & 1}, ID: ${id}`, 'vlan', off, 4)
    add(v, 'Priority', 'vlan.priority', pri, off, 2)
    add(v, 'DEI', 'vlan.dei', (tci >> 12) & 1, off, 2)
    add(v, 'ID', 'vlan.id', id, off, 2)
    add(v, 'Type', 'vlan.etype', `${etherTypeName(inner)} (${hex(inner)})`, off + 2, 2)
    ctx.facts.vlan = { id, priority: pri }
    type = inner
    off += 4
  }
  ctx.facts.eth.type = type
  return { etherType: type, offset: off }
}

const SLL_PKTTYPE: Record<number, string> = {
  0: 'Unicast to us',
  1: 'Broadcast',
  2: 'Multicast',
  3: 'Unicast to another host',
  4: 'Sent by us',
}

function linkAddr(b: Uint8Array, o: number, len: number): string {
  if (len === 6) return mac(b, o)
  const parts: string[] = []
  for (let i = 0; i < Math.min(len, 8); i++) parts.push(b[o + i].toString(16).padStart(2, '0'))
  return parts.join(':')
}

export function dissectSll(ctx: DissectCtx, o: number): NextLayer {
  const b = ctx.b
  const pktType = u16(b, o)
  const hatype = u16(b, o + 2)
  const alen = u16(b, o + 4)
  const addr = linkAddr(b, o + 6, alen)
  const proto = u16(b, o + 14)
  const l = layer(ctx, `Linux cooked capture v1`, 'sll', o, 16)
  add(l, 'Packet type', 'sll.pkttype', `${SLL_PKTTYPE[pktType] ?? 'Unknown'} (${pktType})`, o, 2)
  add(l, 'Link-layer address type', 'sll.hatype', hatype, o + 2, 2)
  add(l, 'Link-layer address length', 'sll.halen', alen, o + 4, 2)
  add(l, 'Source', 'sll.src.eth', addr, o + 6, 8)
  add(l, 'Protocol', 'sll.etype', `${etherTypeName(proto)} (${hex(proto)})`, o + 14, 2)
  ctx.src = addr
  ctx.dst = ''
  ctx.protocol = 'SLL'
  return { etherType: proto, offset: o + 16 }
}

export function dissectSll2(ctx: DissectCtx, o: number): NextLayer {
  const b = ctx.b
  const proto = u16(b, o)
  const ifindex = u32(b, o + 4)
  const hatype = u16(b, o + 8)
  const pktType = u8(b, o + 10)
  const alen = u8(b, o + 11)
  const addr = linkAddr(b, o + 12, alen)
  const l = layer(ctx, `Linux cooked capture v2`, 'sll', o, 20)
  add(l, 'Protocol', 'sll.etype', `${etherTypeName(proto)} (${hex(proto)})`, o, 2)
  add(l, 'Reserved', 'sll.reserved', 0, o + 2, 2)
  add(l, 'Interface index', 'sll.ifindex', ifindex, o + 4, 4)
  add(l, 'Link-layer address type', 'sll.hatype', hatype, o + 8, 2)
  add(l, 'Packet type', 'sll.pkttype', `${SLL_PKTTYPE[pktType] ?? 'Unknown'} (${pktType})`, o + 10, 1)
  add(l, 'Link-layer address length', 'sll.halen', alen, o + 11, 1)
  add(l, 'Source', 'sll.src.eth', addr, o + 12, 8)
  ctx.src = addr
  ctx.dst = ''
  ctx.protocol = 'SLL'
  return { etherType: proto, offset: o + 20 }
}

export function dissectNull(ctx: DissectCtx, o: number): NextLayer {
  const b = ctx.b
  // The family is in the capturing host's byte order; accept either.
  let fam = u32le(b, o)
  if (fam > 0xffff) fam = u32(b, o)
  const l = layer(ctx, 'Null/Loopback', 'null', o, 4)
  // AF_INET6 differs by OS: 24/28/30 on the BSDs and macOS, 10 on Linux, 23 on Windows (Npcap).
  const famName = fam === 2 ? 'IP' : [10, 23, 24, 28, 30].includes(fam) ? 'IPv6' : 'Unknown'
  add(l, 'Family', 'null.family', `${famName} (${fam})`, o, 4)
  ctx.protocol = 'Loopback'
  const etherType = fam === 2 ? 0x0800 : famName === 'IPv6' ? 0x86dd : 0
  return { etherType, offset: o + 4 }
}

export function rawIpType(b: Uint8Array, o: number): number {
  const v = o < b.length ? b[o] >> 4 : 0
  return v === 4 ? 0x0800 : v === 6 ? 0x86dd : 0
}

const ARP_OPS: Record<number, string> = { 1: 'request', 2: 'reply', 3: 'RARP request', 4: 'RARP reply' }

export function dissectArp(ctx: DissectCtx, o: number): void {
  const b = ctx.b
  const htype = u16(b, o)
  const ptype = u16(b, o + 2)
  const hlen = u8(b, o + 4)
  const plen = u8(b, o + 5)
  const op = u16(b, o + 6)
  if (hlen !== 6 || plen !== 4) {
    const l = layer(ctx, 'Address Resolution Protocol (unsupported sizes)', 'arp', o, 8)
    add(l, 'Opcode', 'arp.opcode', op, o + 6, 2)
    ctx.protocol = 'ARP'
    ctx.info = 'ARP with non-Ethernet/IPv4 addresses'
    ctx.color = 'arp'
    return
  }
  const sm = mac(b, o + 8)
  const sip = ipv4(b, o + 14)
  const tm = mac(b, o + 18)
  const tip = ipv4(b, o + 24)
  const opName = ARP_OPS[op] ?? 'unknown'
  const gratuitous = sip === tip
  const l = layer(ctx, `Address Resolution Protocol (${opName}${gratuitous ? ', gratuitous' : ''})`, 'arp', o, 28)
  add(l, 'Hardware type', 'arp.hw.type', htype === 1 ? 'Ethernet (1)' : htype, o, 2)
  add(l, 'Protocol type', 'arp.proto.type', `${etherTypeName(ptype)} (${hex(ptype)})`, o + 2, 2)
  add(l, 'Hardware size', 'arp.hw.size', hlen, o + 4, 1)
  add(l, 'Protocol size', 'arp.proto.size', plen, o + 5, 1)
  add(l, 'Opcode', 'arp.opcode', `${opName} (${op})`, o + 6, 2)
  add(l, 'Sender MAC address', 'arp.src.hw_mac', sm, o + 8, 6)
  add(l, 'Sender IP address', 'arp.src.proto_ipv4', sip, o + 14, 4)
  add(l, 'Target MAC address', 'arp.dst.hw_mac', tm, o + 18, 6)
  add(l, 'Target IP address', 'arp.dst.proto_ipv4', tip, o + 24, 4)
  ctx.facts.arp = { op, senderMac: sm, senderIp: sip, targetMac: tm, targetIp: tip }
  ctx.protocol = 'ARP'
  ctx.color = 'arp'
  if (op === 1) ctx.info = gratuitous ? `Gratuitous ARP for ${sip} (Request)` : `Who has ${tip}? Tell ${sip}`
  else if (op === 2) ctx.info = gratuitous ? `Gratuitous ARP for ${sip} (Reply)` : `${sip} is at ${sm}`
  else ctx.info = `ARP ${opName}`
}
