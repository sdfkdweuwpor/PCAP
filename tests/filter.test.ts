import { describe, expect, it } from 'vitest'
import { compileFilter, FIELDS, FilterError, ipv6Groups } from '../src/core/filter/filter'
import type { CaptureIndex } from '../src/core/types'
import { writePcap } from '../src/core/pcap/writer'
import { dnsQuery, ethernet, icmpEcho, ipv4, ipv6, tcp, udp } from '../src/samples/builder'
import { SAMPLES } from '../src/samples/samples'
import { indexOf } from './helpers'

const sampleIndex = (id: string) => indexOf(SAMPLES.find((s) => s.id === id)!.build()).index
const web = sampleIndex('web-basic')
const nosIn = (index: CaptureIndex, f: string) => index.packets.filter(compileFilter(f)).map((p) => p.no)
const nos = (f: string) => nosIn(web, f)
/** The message of the FilterError that compiling `f` throws. */
const errOf = (f: string): string => {
  try {
    compileFilter(f)
  } catch (e) {
    expect(e).toBeInstanceOf(FilterError)
    return (e as Error).message
  }
  throw new Error('expected a FilterError for ' + f)
}

describe('display filters', () => {
  it('protocol names', () => {
    expect(nos('dns')).toEqual([1, 2])
    expect(nos('http').length).toBe(4)
    expect(nos('udp')).toEqual([1, 2])
    expect(nos('tls')).toEqual([])
    expect(nos('')).toHaveLength(web.packets.length)
  })

  it('address and port comparisons', () => {
    expect(nos('ip.addr == 192.168.1.1')).toEqual([1, 2])
    expect(nos('ip.dst == 93.184.216.34').length).toBeGreaterThan(3)
    expect(nos('tcp.port == 80')).toEqual(nos('tcp'))
    expect(nos('ip.addr == 192.168.1.0/24')).toHaveLength(web.packets.length)
    expect(nos('ip.src == 93.184.216.0/24')).toEqual(nos('ip.src == 93.184.216.34'))
  })

  it('flags and boolean logic', () => {
    expect(nos('tcp.flags.syn == 1')).toEqual([3, 4])
    expect(nos('tcp.flags.syn == 1 && tcp.flags.ack == 0')).toEqual([3])
    expect(nos('tcp.flags.syn == 1 and !tcp.flags.ack == 1')).toEqual([3])
    expect(nos('dns || tcp.flags.fin == 1')).toEqual([1, 2, 13, 14])
    expect(nos('!(tcp || udp)')).toEqual([])
    expect(nos('not tcp')).toEqual([1, 2])
  })

  it('string and numeric operators', () => {
    expect(nos('http.response.code >= 400')).toEqual([11])
    expect(nos('http.request.method == "GET"')).toEqual([6, 10])
    expect(nos('dns.qry.name contains "example"')).toEqual([1, 2])
    expect(nos('frame.len > 300')).toEqual([8])
    expect(nos('tcp.dstport eq 80 && tcp.len gt 0')).toEqual([6, 10])
  })

  it('gives friendly errors for unsupported syntax', () => {
    const err = (f: string) => {
      try {
        compileFilter(f)
      } catch (e) {
        expect(e).toBeInstanceOf(FilterError)
        return (e as Error).message
      }
      throw new Error('expected an error for ' + f)
    }
    expect(err('ip.adr == 1.2.3.4')).toMatch(/ip\.addr/)
    expect(err('ip.addr = 1.2.3.4')).toMatch(/==/)
    expect(err('tcp.port ==')).toMatch(/needs a value/)
    expect(err('(dns')).toMatch(/parenthesis/)
    expect(err('dns http')).toMatch(/forget && or \|\|/)
    expect(err('tcp.flags.syn == 5')).toMatch(/1 or 0/)
    expect(err('http.host matches "x"')).toMatch(/isn't supported/)
  })
})

// ---------------------------------------------------------------- audit regressions

// A small capture mixing IPv6 and IPv4 so the "IPv4-only" and "IPv6-only" fields can be told apart.
const L2 = { a: '02:00:00:00:00:01', b: '02:00:00:00:00:02' }
const ECHO6 = Uint8Array.from([128, 0, 0, 0, 0, 1, 0, 1])
const v6frame = (src: string, dst: string) => ethernet(L2.a, L2.b, 0x86dd, ipv6(src, dst, 58, ECHO6))
const mixed = indexOf(
  writePcap([
    { ts: 1, data: v6frame('2001:db8::1', 'fe80::2') }, // 1
    { ts: 2, data: v6frame('2001:db9::1', '2001:db8:ffff::5') }, // 2
    { ts: 3, data: v6frame('2600::1', '2001:4860::1') }, // 3
    { ts: 4, data: ethernet(L2.a, L2.b, 0x0800, ipv4('10.0.0.2', '10.0.0.3', 1, icmpEcho(true, 1, 7), { ttl: 33, id: 0x0102 })) }, // 4
    { ts: 5, data: ethernet(L2.a, L2.b, 0x0800, ipv4('10.1.2.3', '192.0.2.7', 17, udp(4000, 53, dnsQuery(9, 'x.example')))) }, // 5
  ]),
).index
const inMixed = (f: string) => nosIn(mixed, f)

describe('dns.qry.type', () => {
  const https = sampleIndex('https-visit')
  it('getter returns the numeric type code', () => {
    expect(FIELDS['dns.qry.type'](web.packets[0])).toBe(1) // A
    expect(FIELDS['dns.qry.type'](https.packets[2])).toBe(28) // AAAA
    expect(FIELDS['dns.qry.type'](web.packets[2])).toBeUndefined() // TCP frame: field absent
  })

  it('accepts the numeric code or the symbolic name (any case)', () => {
    expect(nos('dns.qry.type == 1')).toEqual([1, 2])
    expect(nos('dns.qry.type == A')).toEqual([1, 2])
    expect(nos('dns.qry.type == a')).toEqual([1, 2])
    expect(nos('dns.qry.type == AAAA')).toEqual([])
    expect(nosIn(https, 'dns.qry.type == AAAA')).toEqual([3, 4])
    expect(nosIn(https, 'dns.qry.type == 28')).toEqual([3, 4])
    expect(nosIn(https, 'dns.qry.type == 1')).toEqual([1, 2])
    expect(nosIn(https, 'dns.qry.type != 1')).toEqual([3, 4])
    expect(nosIn(https, 'dns.qry.type > 1')).toEqual([3, 4])
  })
})

describe('case sensitivity', () => {
  it('string == and contains are case-sensitive', () => {
    expect(nos('http.request.method == "get"')).toEqual([])
    expect(nos('http.request.method == "GET"')).toEqual([6, 10])
    expect(nos('http.request.method contains "GE"')).toEqual([6, 10])
    expect(nos('http.request.method contains "ge"')).toEqual([])
    expect(nos('dns.qry.name == "WWW.EXAMPLE.COM"')).toEqual([])
    expect(nos('dns.qry.name == "www.example.com"')).toEqual([1, 2])
    expect(nos('dns.qry.name contains "EXAMPLE"')).toEqual([])
    expect(nos('dns.qry.name contains "example"')).toEqual([1, 2])
    // != is the negation of ==, so a wrong-case string is "not equal" for every frame that has the field.
    expect(nos('http.request.method != "get"')).toEqual([6, 10])
  })

  it('address fields (MACs, IPv6) are case-insensitive', () => {
    const clientFrames = [1, 3, 5, 6, 9, 10, 12, 13, 15] // eth.src 3c:22:fb:1a:2b:3c
    expect(nos('eth.src == 3c:22:fb:1a:2b:3c')).toEqual(clientFrames)
    expect(nos('eth.src == 3C:22:FB:1A:2B:3C')).toEqual(clientFrames)
    expect(nos('eth.addr == 00:1A:2B:3C:4D:5E')).toHaveLength(web.packets.length)
    expect(nos('eth.dst contains "3C:22"')).toEqual([2, 4, 7, 8, 11, 14])
    const spoof = sampleIndex('arp-spoof')
    expect(nosIn(spoof, 'arp.src.hw_mac == DE:AD:BE:EF:13:37')).toEqual(nosIn(spoof, 'arp.src.hw_mac == de:ad:be:ef:13:37'))
    expect(nosIn(spoof, 'arp.src.hw_mac == DE:AD:BE:EF:13:37')).toHaveLength(12)
    expect(inMixed('ipv6.src == 2001:DB8::1')).toEqual([1])
    expect(inMixed('ipv6.src == 2001:db8:0:0:0:0:0:1')).toEqual([1]) // uncompressed spelling of the same address
  })
})

describe('ipv6Groups', () => {
  it('parses full, :: compressed and IPv4-tailed addresses into eight 16-bit groups', () => {
    expect(ipv6Groups('1:2:3:4:5:6:7:8')).toEqual([1, 2, 3, 4, 5, 6, 7, 8])
    expect(ipv6Groups('::')).toEqual([0, 0, 0, 0, 0, 0, 0, 0])
    expect(ipv6Groups('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 1])
    expect(ipv6Groups('fe80::')).toEqual([0xfe80, 0, 0, 0, 0, 0, 0, 0])
    expect(ipv6Groups('2001:db8::1')).toEqual([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])
    expect(ipv6Groups('2001:DB8:0:0:8:800:200C:417A')).toEqual([0x2001, 0x0db8, 0, 0, 8, 0x800, 0x200c, 0x417a])
    expect(ipv6Groups('1:2:3:4:5:6:7::')).toEqual([1, 2, 3, 4, 5, 6, 7, 0])
    expect(ipv6Groups('::2:3:4:5:6:7:8')).toEqual([0, 2, 3, 4, 5, 6, 7, 8])
  })

  it('handles an embedded IPv4 tail', () => {
    expect(ipv6Groups('::ffff:192.0.2.128')).toEqual([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0280])
    expect(ipv6Groups('64:ff9b::192.0.2.33')).toEqual([0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0221])
    expect(ipv6Groups('::1.2.3.4')).toEqual([0, 0, 0, 0, 0, 0, 0x0102, 0x0304])
    expect(ipv6Groups('1:2:3:4:5:6:1.2.3.4')).toEqual([1, 2, 3, 4, 5, 6, 0x0102, 0x0304])
    expect(ipv6Groups('::256.1.1.1')).toBeNull() // bad octet
  })

  it('rejects malformed addresses', () => {
    expect(ipv6Groups('1::2::3')).toBeNull() // two "::"
    expect(ipv6Groups('12345::')).toBeNull() // group longer than 4 digits
    expect(ipv6Groups('1:2:3:4:5:6:7')).toBeNull() // too few groups, no "::"
    expect(ipv6Groups('1:2:3:4:5:6:7:8:9')).toBeNull() // too many
    expect(ipv6Groups('1:2:3:4:5:6:7::8')).toBeNull() // "::" must stand for at least one group
    expect(ipv6Groups('g::1')).toBeNull()
    expect(ipv6Groups('1.2.3.4')).toBeNull() // plain IPv4 is not IPv6
    expect(ipv6Groups('')).toBeNull()
    expect(ipv6Groups(':')).toBeNull()
    expect(ipv6Groups(':::')).toBeNull()
  })
})

describe('CIDR subnets', () => {
  it('IPv6 prefixes match on whole and partial 16-bit groups', () => {
    expect(inMixed('ipv6.addr == 2001:db8::/32')).toEqual([1, 2]) // src of #1, dst of #2
    expect(inMixed('ipv6.src == 2001:db8::/32')).toEqual([1])
    expect(inMixed('ipv6.dst == 2001:db8::/32')).toEqual([2])
    expect(inMixed('ipv6.addr == 2001:DB8::/32')).toEqual([1, 2])
    expect(inMixed('ipv6.addr != 2001:db8::/32')).toEqual([3])
    expect(inMixed('ipv6.addr == 2001::/16')).toEqual([1, 2, 3])
    expect(inMixed('ipv6.addr == ::/0')).toEqual([1, 2, 3])
    expect(inMixed('ipv6.src == 2001:db8::1/128')).toEqual([1])
    expect(inMixed('ipv6.src == 2001:db8::2/128')).toEqual([])
    expect(inMixed('ipv6.addr == 2001:db8:8000::/33')).toEqual([2]) // 2001:db8:ffff::5 has the 33rd bit set
    expect(inMixed('ipv6.addr == 2001:db8:fffe::/47')).toEqual([2]) // 47 bits: the low bit of group 3 is ignored
    expect(inMixed('ipv6.addr == 2001:db8:fffe::/48')).toEqual([])
  })

  it('IPv4 prefixes only look at IPv4 frames, and IPv4 fields never match IPv6 prefixes', () => {
    expect(inMixed('ip.addr == 10.0.0.0/8')).toEqual([4, 5])
    expect(inMixed('ip.addr == 10.0.0.0/16')).toEqual([4])
    expect(inMixed('ip.addr == 10.0.0.2/32')).toEqual([4])
    expect(inMixed('ip.addr == 0.0.0.0/0')).toEqual([4, 5])
    expect(inMixed('ip.addr == 2001:db8::/32')).toEqual([])
  })

  it('rejects an out-of-range prefix length or an invalid base address with a FilterError', () => {
    expect(errOf('ip.addr == 10.0.0.0/33')).toMatch(/\/33 is not a valid IPv4 prefix length/)
    expect(errOf('ip.addr == 300.1.1.1/8')).toMatch(/"300\.1\.1\.1" is not a valid IPv4 or IPv6 address/)
    expect(errOf('ipv6.addr == 2001:db8::/129')).toMatch(/\/129 is not a valid IPv6 prefix length/)
    expect(errOf('ipv6.addr == 12345::/16')).toMatch(/not a valid IPv4 or IPv6 address/)
    expect(errOf('ipv6.addr == 1::2::3/64')).toMatch(/not a valid IPv4 or IPv6 address/)
    expect(errOf('ip.addr >= 10.0.0.0/8')).toMatch(/only support == and !=/)
    // The largest legal prefixes compile fine.
    expect(() => compileFilter('ip.addr == 10.0.0.0/32')).not.toThrow()
    expect(() => compileFilter('ipv6.addr == 2001:db8::/128')).not.toThrow()
  })
})

describe('numeric tcp.flags', () => {
  it('compares the whole flags byte', () => {
    expect(nos('tcp.flags == 0x12')).toEqual([4]) // SYN+ACK
    expect(nos('tcp.flags == 0x02')).toEqual([3]) // bare SYN (not the SYN-ACK)
    expect(nos('tcp.flags == 0x10')).toEqual([5, 7, 9, 12, 15]) // ACK only
    expect(nos('tcp.flags == 0x18')).toEqual([6, 8, 10, 11]) // PSH+ACK
    expect(nos('tcp.flags == 0x11')).toEqual([13, 14]) // FIN+ACK
    expect(nos('tcp.flags == 18')).toEqual([4]) // decimal spelling of 0x12
    expect(nos('tcp.flags != 0x10 && tcp.flags != 0x18')).toEqual([3, 4, 13, 14])
    expect(nos('tcp.flags > 0x11')).toEqual([4, 6, 8, 10, 11])
  })

  it('is absent (never matches) on non-TCP frames, even for !=', () => {
    expect(nos('tcp.flags != 0x12').every((n) => n >= 3)).toBe(true)
    expect(nos('tcp.flags == 0')).toEqual([])
  })
})

describe('IPv4-only and IPv6-only fields', () => {
  it('ip.proto, ip.len, ip.id and ip.ttl only see IPv4 frames; ipv6.nxt and ipv6.hlim only IPv6', () => {
    expect(inMixed('ip.proto == 58')).toEqual([]) // the IPv6 frames carry ICMPv6 (58) but ip.proto is an IPv4 field
    expect(inMixed('ipv6.nxt == 58')).toEqual([1, 2, 3])
    expect(inMixed('ipv6.nxt == 1')).toEqual([])
    expect(inMixed('ip.proto == 1')).toEqual([4])
    expect(inMixed('ip.proto == 17')).toEqual([5])
    expect(inMixed('ip.len == 60')).toEqual([4]) // 20 IP + 8 ICMP + 32 data
    expect(inMixed('ip.len > 0')).toEqual([4, 5])
    expect(inMixed('ip.id == 0x0102')).toEqual([4])
    expect(inMixed('ip.id == 258')).toEqual([4])
    expect(inMixed('ip.ttl == 33')).toEqual([4])
    expect(inMixed('ip.ttl == 64')).toEqual([5]) // the IPv6 frames' hop limit (64) must not leak in
    expect(inMixed('ipv6.hlim == 64')).toEqual([1, 2, 3])
    expect(FIELDS['ip.proto'](mixed.packets[0])).toBeUndefined()
    expect(FIELDS['ipv6.nxt'](mixed.packets[0])).toBe(58)
    expect(FIELDS['ipv6.nxt'](mixed.packets[3])).toBeUndefined()
  })

  it('on the web-basic sample', () => {
    expect(nos('ip.proto == 17')).toEqual([1, 2])
    expect(nos('ip.proto == 6')).toEqual([3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    expect(nos('ip.len == 40')).toEqual([5, 7, 9, 12, 13, 14, 15]) // header-only segments
    expect(nos('ip.id == 4096')).toEqual([3]) // the first TcpSession frame
  })
})

describe('multi-valued fields that are absent', () => {
  it('!= never matches a frame that has no such value (an empty array means "field absent")', () => {
    // Frame 1 is a DNS query (no answers); frame 2 is the response with A 93.184.216.34.
    expect(nos('dns.a != 1.2.3.4')).toEqual([2])
    expect(nos('dns.a == 93.184.216.34')).toEqual([2])
    expect(nos('dns.a != 93.184.216.34')).toEqual([])
    expect(nos('dns.cname != nothing.example')).toEqual([2])
    expect(nos('dns.a')).toEqual([2]) // bare field name: present
    expect(nos('!dns.a')).toEqual([1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    const https = sampleIndex('https-visit')
    expect(nosIn(https, 'dns.aaaa != ::1')).toEqual([4]) // only the AAAA response, not the A response or the queries
    expect(nosIn(https, 'dns.aaaa == 2606:4700::6812:2007')).toEqual([4])
    expect(nosIn(https, 'dns.a != 104.18.32.7')).toEqual([])
    expect(nosIn(https, 'dns.a != 9.9.9.9')).toEqual([2])
  })

  it('an absent scalar field does not match != either', () => {
    expect(nos('http.host != "nope"')).toEqual([6, 10]) // only the two requests carry a Host header
    expect(nos('ip.src != 1.2.3.4')).toHaveLength(15) // every frame has an IPv4 source
    expect(inMixed('ip.src != 1.2.3.4')).toEqual([4, 5]) // IPv6 frames have none
  })
})

describe('tcp.stream / udp.stream use per-protocol indices', () => {
  it('web-basic: the DNS pair is udp.stream 0 and the first TCP connection is tcp.stream 0', () => {
    expect(nos('udp.stream == 0')).toEqual([1, 2])
    expect(nos('tcp.stream == 0')).toEqual([3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    expect(nos('tcp.stream == 1')).toEqual([])
    expect(nos('udp.stream == 1')).toEqual([])
    expect(nos('tcp.stream != 0')).toEqual([]) // absent on the UDP frames
    // The two conversations have conversation ids 0 and 1, but each protocol counts from 0.
    expect(web.conversations.map((c) => [c.proto, c.id, c.protoIndex])).toEqual([
      ['UDP', 0, 0],
      ['TCP', 1, 0],
    ])
    expect(web.packets.map((p) => p.protoStream)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  })

  it('https-visit: two UDP lookups then one TCP connection', () => {
    const https = sampleIndex('https-visit')
    expect(nosIn(https, 'udp.stream == 0')).toEqual([1, 2])
    expect(nosIn(https, 'udp.stream == 1')).toEqual([3, 4])
    expect(nosIn(https, 'tcp.stream == 0')).toHaveLength(20) // frames 5-24; conversation id would have been 2
    expect(nosIn(https, 'tcp.stream == 2')).toEqual([])
  })

  it('several TCP connections are numbered 0, 1, 2… in order of first packet, regardless of UDP traffic in between', () => {
    const c = '10.0.0.2'
    const s = '10.0.0.9'
    const frames = [
      { ts: 1, data: ethernet(L2.a, L2.b, 0x0800, ipv4(c, '10.0.0.53', 17, udp(5000, 53, dnsQuery(1, 'a.example')))) }, // udp 0
      { ts: 2, data: ethernet(L2.a, L2.b, 0x0800, ipv4(c, s, 6, tcp(40000, 80, 1, 0, { syn: true }))) }, // tcp 0
      { ts: 3, data: ethernet(L2.a, L2.b, 0x0800, ipv4(c, '10.0.0.53', 17, udp(5001, 53, dnsQuery(2, 'b.example')))) }, // udp 1
      { ts: 4, data: ethernet(L2.a, L2.b, 0x0800, ipv4(c, s, 6, tcp(40001, 80, 1, 0, { syn: true }))) }, // tcp 1
      { ts: 5, data: ethernet(L2.a, L2.b, 0x0800, ipv4(c, s, 6, tcp(40002, 443, 1, 0, { syn: true }))) }, // tcp 2
      { ts: 6, data: ethernet(L2.a, L2.b, 0x0800, ipv4(c, s, 6, tcp(40001, 80, 2, 0, { ack: true }))) }, // tcp 1 again
    ]
    const { index } = indexOf(writePcap(frames))
    expect(index.packets.map((p) => p.protoStream)).toEqual([0, 0, 1, 1, 2, 1])
    expect(nosIn(index, 'tcp.stream == 1')).toEqual([4, 6])
    expect(nosIn(index, 'tcp.stream == 2')).toEqual([5])
    expect(nosIn(index, 'udp.stream == 1')).toEqual([3])
    expect(nosIn(index, 'tcp.stream >= 1 && udp.stream == 1')).toEqual([]) // no frame is both
  })

  it('across every sample, protoStream equals the conversation protoIndex and each protocol counts 0..n-1 without gaps', () => {
    for (const s of SAMPLES) {
      const { index } = indexOf(s.build())
      const byProto = new Map<string, number[]>()
      for (const conv of index.conversations) {
        byProto.set(conv.proto, [...(byProto.get(conv.proto) ?? []), conv.protoIndex!])
        for (const no of conv.packets) expect(index.packets[no - 1].protoStream, `${s.id} #${no}`).toBe(conv.protoIndex)
      }
      for (const [proto, idx] of byProto) expect(idx, `${s.id} ${proto}`).toEqual(idx.map((_, i) => i))
    }
  })
})
