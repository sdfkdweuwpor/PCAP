// A small subset of Wireshark display-filter syntax, compiled to a predicate over PacketSummary.
//
//   expr    := or
//   or      := and (('||' | 'or') and)*
//   and     := not (('&&' | 'and') not)*
//   not     := ('!' | 'not') not | primary
//   primary := '(' expr ')' | FIELD [op VALUE]
//   op      := == eq != ne > gt < lt >= ge <= le contains

import { DNS_TYPES } from '../dissect/dns'
import type { PacketSummary } from '../types'

export class FilterError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FilterError'
  }
}

type Val = string | number | boolean
type Getter = (p: PacketSummary) => Val[] | Val | undefined

const proto = (name: string): Getter => (p) => p.facts.protos.includes(name)
const flag = (k: keyof NonNullable<PacketSummary['facts']['tcp']>['flags']): Getter => (p) =>
  p.facts.tcp ? p.facts.tcp.flags[k] : undefined
const v4 = (p: PacketSummary) => (p.facts.ip?.version === 4 ? p.facts.ip : undefined)
const FLAG_BITS = { fin: 0x01, syn: 0x02, rst: 0x04, psh: 0x08, ack: 0x10, urg: 0x20, ece: 0x40, cwr: 0x80 } as const
const DNS_TYPE_CODES: Record<string, number> = Object.fromEntries(Object.entries(DNS_TYPES).map(([n, name]) => [name.toUpperCase(), Number(n)]))

export const FIELDS: Record<string, Getter> = {
  // Protocol presence
  frame: () => true,
  eth: proto('eth'),
  vlan: proto('vlan'),
  arp: proto('arp'),
  ip: (p) => p.facts.ip?.version === 4,
  ipv6: (p) => p.facts.ip?.version === 6,
  icmp: proto('icmp'),
  icmpv6: proto('icmpv6'),
  tcp: proto('tcp'),
  udp: proto('udp'),
  dns: proto('dns'),
  http: proto('http'),
  tls: proto('tls'),
  ssl: proto('tls'),
  dhcp: proto('dhcp'),
  bootp: proto('dhcp'),
  ftp: proto('ftp'),
  'ftp-data': proto('ftp-data'),
  smtp: proto('smtp'),
  pop: proto('pop'),
  imap: proto('imap'),
  telnet: proto('telnet'),
  ssh: proto('ssh'),
  ntp: proto('ntp'),
  snmp: proto('snmp'),
  data: proto('data'),
  // Frame
  'frame.number': (p) => p.no,
  'frame.len': (p) => p.origLen,
  'frame.time_relative': (p) => p.relTime,
  // Ethernet
  'eth.addr': (p) => (p.facts.eth ? [p.facts.eth.src, p.facts.eth.dst] : undefined),
  'eth.src': (p) => p.facts.eth?.src,
  'eth.dst': (p) => p.facts.eth?.dst,
  'eth.type': (p) => p.facts.eth?.type,
  'vlan.id': (p) => p.facts.vlan?.id,
  // ARP
  'arp.opcode': (p) => p.facts.arp?.op,
  'arp.src.hw_mac': (p) => p.facts.arp?.senderMac,
  'arp.src.proto_ipv4': (p) => p.facts.arp?.senderIp,
  'arp.dst.hw_mac': (p) => p.facts.arp?.targetMac,
  'arp.dst.proto_ipv4': (p) => p.facts.arp?.targetIp,
  // IP
  'ip.addr': (p) => (p.facts.ip?.version === 4 ? [p.facts.ip.src, p.facts.ip.dst] : undefined),
  'ip.src': (p) => (p.facts.ip?.version === 4 ? p.facts.ip.src : undefined),
  'ip.dst': (p) => (p.facts.ip?.version === 4 ? p.facts.ip.dst : undefined),
  'ip.ttl': (p) => v4(p)?.ttl,
  'ip.proto': (p) => v4(p)?.proto,
  'ip.len': (p) => v4(p)?.len,
  'ip.id': (p) => v4(p)?.id,
  'ip.flags.df': (p) => v4(p)?.df,
  'ip.flags.mf': (p) => v4(p)?.mf,
  'ip.frag_offset': (p) => v4(p)?.fragOffset,
  'ipv6.addr': (p) => (p.facts.ip?.version === 6 ? [p.facts.ip.src, p.facts.ip.dst] : undefined),
  'ipv6.src': (p) => (p.facts.ip?.version === 6 ? p.facts.ip.src : undefined),
  'ipv6.dst': (p) => (p.facts.ip?.version === 6 ? p.facts.ip.dst : undefined),
  'ipv6.hlim': (p) => (p.facts.ip?.version === 6 ? p.facts.ip.ttl : undefined),
  'ipv6.nxt': (p) => (p.facts.ip?.version === 6 ? p.facts.ip.proto : undefined),
  // ICMP
  'icmp.type': (p) => (p.facts.icmp && !p.facts.icmp.v6 ? p.facts.icmp.type : undefined),
  'icmp.code': (p) => (p.facts.icmp && !p.facts.icmp.v6 ? p.facts.icmp.code : undefined),
  'icmpv6.type': (p) => (p.facts.icmp?.v6 ? p.facts.icmp.type : undefined),
  // TCP
  'tcp.port': (p) => (p.facts.tcp ? [p.facts.tcp.srcPort, p.facts.tcp.dstPort] : undefined),
  'tcp.srcport': (p) => p.facts.tcp?.srcPort,
  'tcp.dstport': (p) => p.facts.tcp?.dstPort,
  'tcp.seq': (p) => p.facts.tcp?.relSeq ?? p.facts.tcp?.seq,
  'tcp.ack': (p) => p.facts.tcp?.relAck ?? p.facts.tcp?.ack,
  'tcp.len': (p) => p.facts.tcp?.payloadLen,
  'tcp.window_size_value': (p) => p.facts.tcp?.window,
  'tcp.stream': (p) => (p.facts.tcp ? p.protoStream : undefined),
  'tcp.flags': (p) => {
    const t = p.facts.tcp
    if (!t) return undefined
    let n = 0
    for (const k of Object.keys(FLAG_BITS) as (keyof typeof FLAG_BITS)[]) if (t.flags[k]) n |= FLAG_BITS[k]
    return n
  },
  'tcp.flags.syn': flag('syn'),
  'tcp.flags.ack': flag('ack'),
  'tcp.flags.fin': flag('fin'),
  'tcp.flags.reset': flag('rst'),
  'tcp.flags.rst': flag('rst'),
  'tcp.flags.push': flag('psh'),
  'tcp.flags.urg': flag('urg'),
  // UDP
  'udp.port': (p) => (p.facts.udp ? [p.facts.udp.srcPort, p.facts.udp.dstPort] : undefined),
  'udp.srcport': (p) => p.facts.udp?.srcPort,
  'udp.dstport': (p) => p.facts.udp?.dstPort,
  'udp.length': (p) => p.facts.udp?.len,
  'udp.stream': (p) => (p.facts.udp ? p.protoStream : undefined),
  // DNS
  'dns.qry.name': (p) => p.facts.dns?.qname,
  'dns.qry.type': (p) => {
    const t = p.facts.dns?.qtype
    if (!t) return undefined
    return DNS_TYPE_CODES[t.toUpperCase()] ?? (/^TYPE(\d+)$/.exec(t) ? Number(t.slice(4)) : undefined)
  },
  'dns.flags.response': (p) => p.facts.dns?.isResponse,
  'dns.flags.rcode': (p) => p.facts.dns?.rcode,
  'dns.id': (p) => p.facts.dns?.id,
  'dns.a': (p) => p.facts.dns?.answers.filter((a) => a.type === 'A').map((a) => a.data),
  'dns.aaaa': (p) => p.facts.dns?.answers.filter((a) => a.type === 'AAAA').map((a) => a.data),
  'dns.cname': (p) => p.facts.dns?.answers.filter((a) => a.type === 'CNAME').map((a) => a.data),
  'dns.txt': (p) => p.facts.dns?.answers.filter((a) => a.type === 'TXT').map((a) => a.data),
  // HTTP
  'http.request': (p) => (p.facts.http ? p.facts.http.isRequest : undefined) || undefined,
  'http.response': (p) => (p.facts.http?.status !== undefined ? true : undefined),
  'http.request.method': (p) => p.facts.http?.method,
  'http.request.uri': (p) => p.facts.http?.uri,
  'http.response.code': (p) => p.facts.http?.status,
  'http.host': (p) => p.facts.http?.host,
  'http.user_agent': (p) => p.facts.http?.userAgent,
  'http.authorization': (p) => p.facts.http?.authorization,
  // TLS
  'tls.handshake': (p) => (p.facts.tls?.handshakeTypes.length ? true : undefined),
  'tls.handshake.type': (p) => p.facts.tls?.handshakeTypes.map(handshakeCode),
  'tls.handshake.extensions_server_name': (p) => p.facts.tls?.sni,
  'tls.record.content_type': (p) => p.facts.tls?.contentTypes.map(contentCode),
  'tls.alert_message': (p) => (p.facts.tls?.alert ? true : undefined),
  // DHCP
  'dhcp.option.dhcp': (p) => (p.facts.dhcp ? DHCP_CODES[p.facts.dhcp.msgType] : undefined),
  'dhcp.hw.mac_addr': (p) => p.facts.dhcp?.clientMac,
  'dhcp.ip.your': (p) => p.facts.dhcp?.yiaddr,
  // Text protocols
  'ftp.request.command': (p) => (p.facts.app?.proto === 'FTP' ? p.facts.app.command : undefined),
  'ftp.request.arg': (p) => (p.facts.app?.proto === 'FTP' ? p.facts.app.arg : undefined),
  'ftp.response.code': (p) => (p.facts.app?.proto === 'FTP' ? p.facts.app.code : undefined),
  'smtp.response.code': (p) => (p.facts.app?.proto === 'SMTP' ? p.facts.app.code : undefined),
}

const DHCP_CODES: Record<string, number> = { Discover: 1, Offer: 2, Request: 3, Decline: 4, ACK: 5, NAK: 6, Release: 7, Inform: 8 }
const HS: Record<string, number> = {
  'Client Hello': 1,
  'Server Hello': 2,
  'New Session Ticket': 4,
  'Encrypted Extensions': 8,
  Certificate: 11,
  'Server Key Exchange': 12,
  'Server Hello Done': 14,
  'Client Key Exchange': 16,
  Finished: 20,
}
const handshakeCode = (n: string) => HS[n] ?? -1
const contentCode = (n: string) =>
  ({ 'Change Cipher Spec': 20, Alert: 21, Handshake: 22, 'Application Data': 23, Heartbeat: 24 })[n] ?? -1

// ---------------------------------------------------------------- tokenizer

type Tok = { t: 'op' | 'word' | 'str' | 'lp' | 'rp' | 'and' | 'or' | 'not'; v: string; pos: number }

const OPS: Record<string, string> = {
  '==': '==',
  eq: '==',
  '!=': '!=',
  ne: '!=',
  '>': '>',
  gt: '>',
  '<': '<',
  lt: '<',
  '>=': '>=',
  ge: '>=',
  '<=': '<=',
  le: '<=',
  contains: 'contains',
  matches: 'matches',
}

function tokenize(src: string): Tok[] {
  const toks: Tok[] = []
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (/\s/.test(c)) {
      i++
      continue
    }
    if (c === '(') toks.push({ t: 'lp', v: c, pos: i++ })
    else if (c === ')') toks.push({ t: 'rp', v: c, pos: i++ })
    else if (src.startsWith('&&', i) || src.startsWith('||', i)) {
      toks.push({ t: src[i] === '&' ? 'and' : 'or', v: src.slice(i, i + 2), pos: i })
      i += 2
    } else if (/^(==|!=|>=|<=)/.test(src.slice(i))) {
      toks.push({ t: 'op', v: src.slice(i, i + 2), pos: i })
      i += 2
    }
    else if (c === '!') toks.push({ t: 'not', v: '!', pos: i++ })
    else if (c === '>' || c === '<') toks.push({ t: 'op', v: c, pos: i++ })
    else if (c === '=') throw new FilterError(`Use "==" for comparisons (found a single "=" at position ${i + 1}).`)
    else if (c === '"') {
      const end = src.indexOf('"', i + 1)
      if (end < 0) throw new FilterError('Unterminated string: add a closing quote (").')
      toks.push({ t: 'str', v: src.slice(i + 1, end), pos: i })
      i = end + 1
    } else {
      const m = /^[A-Za-z0-9_.:/-]+/.exec(src.slice(i))
      if (!m) throw new FilterError(`Unexpected character "${c}" at position ${i + 1}.`)
      const w = m[0]
      const lw = w.toLowerCase()
      if (lw === 'and') toks.push({ t: 'and', v: w, pos: i })
      else if (lw === 'or') toks.push({ t: 'or', v: w, pos: i })
      else if (lw === 'not') toks.push({ t: 'not', v: w, pos: i })
      else if (OPS[lw]) toks.push({ t: 'op', v: lw, pos: i })
      else toks.push({ t: 'word', v: w, pos: i })
      i += w.length
    }
  }
  return toks
}

// ---------------------------------------------------------------- parser

type Pred = (p: PacketSummary) => boolean

export function compileFilter(src: string): Pred {
  const trimmed = src.trim()
  if (!trimmed) return () => true
  const toks = tokenize(trimmed)
  let i = 0
  const peek = () => toks[i]
  const expectEnd = () => {
    if (i < toks.length) throw new FilterError(`Unexpected "${toks[i].v}" at position ${toks[i].pos + 1}. Did you forget && or ||?`)
  }
  const parseOr = (): Pred => {
    let left = parseAnd()
    while (peek()?.t === 'or') {
      i++
      const l = left
      const r = parseAnd()
      left = (p) => l(p) || r(p)
    }
    return left
  }
  const parseAnd = (): Pred => {
    let left = parseNot()
    while (peek()?.t === 'and') {
      i++
      const l = left
      const r = parseNot()
      left = (p) => l(p) && r(p)
    }
    return left
  }
  const parseNot = (): Pred => {
    if (peek()?.t === 'not') {
      i++
      const inner = parseNot()
      return (p) => !inner(p)
    }
    return parsePrimary()
  }
  const parsePrimary = (): Pred => {
    const t = peek()
    if (!t) throw new FilterError('The filter ends too early — something is missing after the last operator.')
    if (t.t === 'lp') {
      i++
      const e = parseOr()
      if (peek()?.t !== 'rp') throw new FilterError('Missing closing parenthesis ")".')
      i++
      return e
    }
    if (t.t !== 'word') throw new FilterError(`Expected a field name at position ${t.pos + 1} but found "${t.v}".`)
    i++
    const name = t.v.toLowerCase()
    const getter = FIELDS[name]
    if (!getter) throw new FilterError(unknownFieldMessage(t.v))
    const opTok = peek()
    if (opTok?.t !== 'op') return (p) => truthy(getter(p))
    i++
    const op = OPS[opTok.v]
    const valTok = peek()
    if (!valTok || (valTok.t !== 'word' && valTok.t !== 'str'))
      throw new FilterError(`"${opTok.v}" needs a value after it, e.g. ${name} ${opTok.v} ${exampleValue(name)}.`)
    i++
    if (op === 'matches') throw new FilterError('The "matches" (regex) operator isn\'t supported here; try "contains".')
    return makeComparison(name, getter, op, valTok.v, valTok.t === 'str')
  }
  const pred = parseOr()
  expectEnd()
  return pred
}

function truthy(v: Val[] | Val | undefined): boolean {
  if (v === undefined) return false
  if (Array.isArray(v)) return v.length > 0
  return v !== false
}

function asArray(v: Val[] | Val | undefined): Val[] {
  if (v === undefined) return []
  return Array.isArray(v) ? v : [v]
}

function parseNumber(s: string): number | null {
  if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16)
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s)
  return null
}

function ipToInt(ip: string): number | null {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip)
  if (!m || m.slice(1).some((o) => +o > 255)) return null
  return ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4]
}

/** An IPv6 address as eight 16-bit groups, or null. Accepts :: compression and an embedded IPv4 tail. */
export function ipv6Groups(s: string): number[] | null {
  let text = s.toLowerCase()
  const v4tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(text)
  if (v4tail) {
    const n = ipToInt(v4tail[1])
    if (n === null) return null
    text = text.slice(0, -v4tail[1].length) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`
  }
  const halves = text.split('::')
  if (halves.length > 2) return null
  const part = (h: string) => (h ? h.split(':') : [])
  const head = part(halves[0])
  const tail = halves.length === 2 ? part(halves[1]) : []
  const fill = 8 - head.length - tail.length
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail]
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null
  return groups.map((g) => parseInt(g, 16))
}

/** Address-valued fields compare case-insensitively (MACs, IPv6); every other text field is case-sensitive. */
const ADDRESS_FIELD = /^(eth\.(addr|src|dst)|ipv6\.(addr|src|dst)|arp\.(src|dst)\.hw_mac|dhcp\.hw\.mac_addr|dns\.aaaa)$/

function makeComparison(name: string, getter: Getter, op: string, raw: string, quoted: boolean): Pred {
  // Booleans (flags): accept 1/0/true/false.
  if (/flags\.|^http\.request$|^http\.response$|dns\.flags\.response/.test(name) && !name.endsWith('rcode')) {
    const want = raw === '1' || raw.toLowerCase() === 'true'
    if (!['1', '0', 'true', 'false'].includes(raw.toLowerCase())) throw new FilterError(`${name} is a flag: compare it with 1 or 0.`)
    if (op !== '==' && op !== '!=') throw new FilterError(`Flags only support == and !=.`)
    return (p) => {
      const vals = asArray(getter(p))
      if (!vals.length) return false
      const eq = vals.some((x) => Boolean(x) === want)
      return op === '==' ? eq : !eq
    }
  }
  // CIDR on address fields (IPv4 a.b.c.d/n, IPv6 x::y/n).
  const cidr = quoted ? null : /^([0-9a-f:.]+)\/(\d+)$/i.exec(raw)
  if (cidr) {
    if (op !== '==' && op !== '!=') throw new FilterError('Subnets (CIDR) only support == and !=.')
    const bits = Number(cidr[2])
    let inNet: (v: Val) => boolean
    const base4 = ipToInt(cidr[1])
    if (base4 !== null) {
      if (bits > 32) throw new FilterError(`/${bits} is not a valid IPv4 prefix length (0–32).`)
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
      inNet = (v) => {
        const n = typeof v === 'string' ? ipToInt(v) : null
        return n !== null && ((n & mask) >>> 0) === ((base4 & mask) >>> 0)
      }
    } else {
      const base6 = ipv6Groups(cidr[1])
      if (!base6) throw new FilterError(`"${cidr[1]}" is not a valid IPv4 or IPv6 address.`)
      if (bits > 128) throw new FilterError(`/${bits} is not a valid IPv6 prefix length (0–128).`)
      inNet = (v) => {
        const g = typeof v === 'string' ? ipv6Groups(v) : null
        if (!g) return false
        for (let i = 0, left = bits; left > 0; i++, left -= 16) {
          const mask = left >= 16 ? 0xffff : (0xffff << (16 - left)) & 0xffff
          if ((g[i] & mask) !== (base6[i] & mask)) return false
        }
        return true
      }
    }
    return (p) => {
      const vals = asArray(getter(p))
      if (!vals.length) return false
      const any = vals.some(inNet)
      return op === '==' ? any : !any
    }
  }
  // Symbolic values for numeric fields: dns.qry.type == AAAA.
  const num = quoted ? null : (parseNumber(raw) ?? (name === 'dns.qry.type' ? (DNS_TYPE_CODES[raw.toUpperCase()] ?? null) : null))
  // Wireshark compares strings case-sensitively; addresses are the exception (they're normalised first).
  const fold = ADDRESS_FIELD.test(name)
  const norm = (x: string) => (fold ? x.toLowerCase() : x)
  const want = norm(raw)
  const want6 = name.startsWith('ipv6.') || name === 'dns.aaaa' ? ipv6Groups(raw)?.join(':') : undefined
  const cmp = (v: Val): boolean => {
    if (op === 'contains') return norm(String(v)).includes(want)
    if (typeof v === 'number') {
      if (num === null) return false
      switch (op) {
        case '==':
          return v === num
        case '!=':
          return v !== num
        case '>':
          return v > num
        case '<':
          return v < num
        case '>=':
          return v >= num
        case '<=':
          return v <= num
      }
    }
    if (typeof v === 'boolean') {
      const b = raw === '1' || raw.toLowerCase() === 'true'
      return op === '==' ? v === b : v !== b
    }
    const sv = norm(String(v))
    const same = sv === want || (want6 !== undefined && ipv6Groups(String(v))?.join(':') === want6)
    if (op === '==') return same
    if (op === '!=') return !same
    throw new FilterError(`"${op}" can't be used with text fields like ${name}; use == or contains.`)
  }
  if (op === '!=') {
    // Modern Wireshark semantics: a != b is !(a == b) for multi-valued fields.
    const eq = makeComparison(name, getter, '==', raw, quoted)
    return (p) => asArray(getter(p)).length > 0 && !eq(p)
  }
  return (p) => asArray(getter(p)).some(cmp)
}

function exampleValue(name: string): string {
  if (name.includes('addr') || name.endsWith('.src') || name.endsWith('.dst')) return '10.0.0.1'
  if (name.includes('port')) return '443'
  if (name.includes('flags')) return '1'
  if (name.includes('name')) return '"example.com"'
  return '1'
}

function unknownFieldMessage(field: string): string {
  const lf = field.toLowerCase()
  const close = Object.keys(FIELDS)
    .filter((k) => k.startsWith(lf.split('.')[0]) || levenshtein(k, lf) <= 2)
    .sort((a, b) => levenshtein(a, lf) - levenshtein(b, lf))
    .slice(0, 4)
  const hint = close.length ? ` Did you mean ${close.map((c) => `"${c}"`).join(', ')}?` : ' Try ip.addr, tcp.port, udp, dns, http, tls or tcp.flags.syn.'
  return `"${field}" isn't a field this filter understands.${hint}`
}

function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)])
  for (let j = 1; j <= b.length; j++) dp[0][j] = j
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
  return dp[a.length][b.length]
}

export const FILTER_EXAMPLES = [
  'dns',
  'http || tls',
  'tcp.flags.syn == 1 && tcp.flags.ack == 0',
  'ip.addr == 192.168.1.23',
  'tcp.port == 443',
  '!arp',
  'dns.qry.name contains "example"',
  'http.response.code >= 400',
]
