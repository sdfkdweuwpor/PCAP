// DNS (RFC 1035) with name compression, common RR types and response codes.

import { hex, ipv4, ipv6, TruncatedError, u16, u32 } from '../bytes'
import type { DnsRecordFact } from '../types'
import { add, layer, type DissectCtx } from './tree'

export const DNS_TYPES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  41: 'OPT',
  64: 'SVCB',
  65: 'HTTPS',
  255: 'ANY',
}
export const DNS_RCODES: Record<number, string> = {
  0: 'No error',
  1: 'Format error',
  2: 'Server failure',
  3: 'No such name',
  4: 'Not implemented',
  5: 'Refused',
}
export const dnsTypeName = (t: number) => DNS_TYPES[t] ?? `TYPE${t}`

/** Reads a (possibly compressed) domain name. `base` is the start of the DNS message. */
export function readName(b: Uint8Array, base: number, o: number): { name: string; next: number } {
  const labels: string[] = []
  let p = o
  let next = -1
  let jumps = 0
  for (;;) {
    if (p >= b.length) throw new TruncatedError('DNS name')
    const len = b[p]
    if (len === 0) {
      p++
      break
    }
    if ((len & 0xc0) === 0xc0) {
      if (p + 1 >= b.length) throw new TruncatedError('DNS pointer')
      if (next < 0) next = p + 2
      p = base + (((len & 0x3f) << 8) | b[p + 1])
      if (++jumps > 32) throw new Error('DNS compression loop')
      continue
    }
    if (p + 1 + len > b.length) throw new TruncatedError('DNS label')
    let s = ''
    for (let i = 0; i < len; i++) s += String.fromCharCode(b[p + 1 + i])
    labels.push(s)
    p += 1 + len
    if (labels.length > 128) throw new Error('DNS name too long')
  }
  return { name: labels.length ? labels.join('.') : '<Root>', next: next >= 0 ? next : p }
}

export function dissectDns(ctx: DissectCtx, o: number, len: number, overTcp = false): void {
  const b = ctx.b
  let base = o
  let l
  if (overTcp) {
    const mlen = u16(b, o)
    l = layer(ctx, 'Domain Name System', 'dns', o, len)
    add(l, 'Length', 'dns.length', mlen, o, 2)
    base = o + 2
  } else l = layer(ctx, 'Domain Name System', 'dns', o, len)
  const id = u16(b, base)
  const flags = u16(b, base + 2)
  const qd = u16(b, base + 4)
  const an = u16(b, base + 6)
  const ns = u16(b, base + 8)
  const ar = u16(b, base + 10)
  const qr = !!(flags & 0x8000)
  const opcode = (flags >> 11) & 0xf
  const rcode = flags & 0xf
  const rcodeName = DNS_RCODES[rcode] ?? `RCODE ${rcode}`
  l.name = `Domain Name System (${qr ? 'response' : 'query'})`
  add(l, 'Transaction ID', 'dns.id', hex(id), base, 2)
  const fl = add(l, 'Flags', 'dns.flags', `${hex(flags)} Standard query${qr ? ` response, ${rcodeName}` : ''}`, base + 2, 2)
  add(fl, `${qr ? 1 : 0}... .... .... .... = Response`, 'dns.flags.response', qr ? 'Message is a response' : 'Message is a query', base + 2, 2)
  add(fl, `.${opcode.toString(2).padStart(4, '0').replace(/(...)(.)/, '$1 $2')}... .... .... = Opcode`, 'dns.flags.opcode', opcode === 0 ? 'Standard query (0)' : opcode, base + 2, 2)
  if (qr) add(fl, `.... .${flags & 0x400 ? 1 : 0}.. .... .... = Authoritative`, 'dns.flags.authoritative', flags & 0x400 ? 'Server is an authority for domain' : 'Server is not an authority for domain', base + 2, 2)
  add(fl, `.... ...${flags & 0x100 ? 1 : 0} .... .... = Recursion desired`, 'dns.flags.recdesired', flags & 0x100 ? 'Do query recursively' : 'No', base + 2, 2)
  if (qr) {
    add(fl, `.... .... ${flags & 0x80 ? 1 : 0}... .... = Recursion available`, 'dns.flags.recavail', flags & 0x80 ? 'Server can do recursive queries' : 'No', base + 2, 2)
    add(fl, `.... .... .... ${rcode.toString(2).padStart(4, '0')} = Reply code`, 'dns.flags.rcode', `${rcodeName} (${rcode})`, base + 2, 2, rcode ? { warn: true } : {})
  }
  add(l, 'Questions', 'dns.count.queries', qd, base + 4, 2)
  add(l, 'Answer RRs', 'dns.count.answers', an, base + 6, 2)
  add(l, 'Authority RRs', 'dns.count.auth_rr', ns, base + 8, 2)
  add(l, 'Additional RRs', 'dns.count.add_rr', ar, base + 10, 2)

  let p = base + 12
  let qname = ''
  let qtype = ''
  if (qd > 0) {
    const qs = add(l, 'Queries', 'dns.queries', undefined, p, 0)
    for (let i = 0; i < qd; i++) {
      const start = p
      const { name, next } = readName(b, base, p)
      const t = u16(b, next)
      const c = u16(b, next + 2)
      const q = add(qs, `${name}: type ${dnsTypeName(t)}, class ${c === 1 ? 'IN' : c}`, 'dns.qry', undefined, start, next + 4 - start)
      add(q, 'Name', 'dns.qry.name', name, start, next - start)
      add(q, '[Name Length]', 'dns.qry.name.len', name.length, start, 0)
      add(q, 'Type', 'dns.qry.type', `${dnsTypeName(t)} (${t})`, next, 2)
      add(q, 'Class', 'dns.qry.class', c === 1 ? 'IN (0x0001)' : hex(c), next + 2, 2)
      if (i === 0) {
        qname = name
        qtype = dnsTypeName(t)
      }
      p = next + 4
    }
    qs.length = p - qs.offset
  }

  const answers: DnsRecordFact[] = []
  const sections: [string, number, string][] = [
    ['Answers', an, 'dns.answers'],
    ['Authoritative nameservers', ns, 'dns.auth'],
    ['Additional records', ar, 'dns.additional'],
  ]
  for (const [title, count, key] of sections) {
    if (!count) continue
    const sec = add(l, title, key, undefined, p, 0)
    for (let i = 0; i < count; i++) {
      const start = p
      const { name, next } = readName(b, base, p)
      const t = u16(b, next)
      const cls = u16(b, next + 2)
      const ttl = u32(b, next + 4)
      const rdlen = u16(b, next + 8)
      const rd = next + 10
      if (rd + rdlen > b.length) throw new TruncatedError('DNS rdata')
      let data = ''
      let dataKey = 'dns.data'
      const tn = dnsTypeName(t)
      if (t === 1 && rdlen === 4) {
        data = ipv4(b, rd)
        dataKey = 'dns.a'
      } else if (t === 28 && rdlen === 16) {
        data = ipv6(b, rd)
        dataKey = 'dns.aaaa'
      } else if (t === 5 || t === 2 || t === 12) {
        data = readName(b, base, rd).name
        dataKey = t === 5 ? 'dns.cname' : t === 2 ? 'dns.ns' : 'dns.ptr.domain_name'
      } else if (t === 15) {
        data = `${u16(b, rd)} ${readName(b, base, rd + 2).name}`
        dataKey = 'dns.mx.mail_exchange'
      } else if (t === 16) {
        const parts: string[] = []
        let q = rd
        while (q < rd + rdlen) {
          const sl = b[q]
          let s = ''
          for (let k = 0; k < sl && q + 1 + k < rd + rdlen; k++) s += String.fromCharCode(b[q + 1 + k])
          parts.push(s)
          q += 1 + sl
        }
        data = parts.join('')
        dataKey = 'dns.txt'
      } else if (t === 6) {
        data = readName(b, base, rd).name
        dataKey = 'dns.soa.mname'
      } else if (t === 41) {
        data = `UDP payload size ${cls}`
      } else data = `${rdlen} bytes`
      const rr = add(sec, `${name}: type ${tn}, class ${cls === 1 ? 'IN' : cls}${t === 41 ? '' : `, ${dataKey.split('.').pop()} ${data}`}`, 'dns.resp', undefined, start, rd + rdlen - start)
      add(rr, 'Name', 'dns.resp.name', name, start, next - start)
      add(rr, 'Type', 'dns.resp.type', `${tn} (${t})`, next, 2)
      add(rr, 'Class', 'dns.resp.class', cls === 1 ? 'IN (0x0001)' : cls, next + 2, 2)
      add(rr, 'Time to live', 'dns.resp.ttl', `${ttl} (${fmtTtl(ttl)})`, next + 4, 4)
      add(rr, 'Data length', 'dns.resp.len', rdlen, next + 8, 2)
      if (rdlen) add(rr, dataKey === 'dns.a' ? 'Address' : dataKey === 'dns.cname' ? 'CNAME' : dataKey === 'dns.txt' ? 'TXT' : 'Data', dataKey, data, rd, rdlen)
      if (key === 'dns.answers') answers.push({ name, type: tn, data, ttl })
      p = rd + rdlen
    }
    sec.length = p - sec.offset
  }

  ctx.facts.dns = { id, isResponse: qr, opcode, rcode, rcodeName, qname, qtype, answers }
  ctx.protocol = 'DNS'
  ctx.color = rcode ? 'error' : 'dns'
  if (!qr) ctx.info = `Standard query ${hex(id)} ${qtype} ${qname}`
  else {
    const ans = answers.map((a) => `${a.type} ${a.data.length > 40 ? a.data.slice(0, 40) + '…' : a.data}`).join(' ')
    ctx.info = `Standard query response ${hex(id)}${rcode ? ` ${rcodeName}` : ''} ${qtype} ${qname}${ans ? ' ' + ans : ''}`
  }
}

function fmtTtl(s: number): string {
  if (s < 60) return `${s} seconds`
  if (s < 3600) return `${Math.floor(s / 60)} minutes`
  if (s < 86400) return `${Math.floor(s / 3600)} hours`
  return `${Math.floor(s / 86400)} days`
}
