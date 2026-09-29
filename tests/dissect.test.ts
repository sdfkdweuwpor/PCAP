// Field offsets are verified against hand-assembled frames with known byte positions.

import { describe, expect, it } from 'vitest'
import { writePcap, writePcapng } from '../src/core/pcap/writer'
import { fieldAtOffset } from '../src/game/engine'
import {
  arp,
  dhcp,
  dnsQuery,
  dnsResponse,
  ethernet,
  icmpEcho,
  ipOpt,
  ipv4,
  ipv6,
  mulberry32,
  tcp,
  text,
  tlsClientHello,
  tlsServerHello,
  udp,
} from '../src/samples/builder'
import { all, find, indexOf, single, slice } from './helpers'

const hex = (s: string) => Uint8Array.from(s.replace(/\s+/g, '').match(/../g)!.map((b) => parseInt(b, 16)))

// A TCP SYN written out byte by byte (Ethernet 14 + IPv4 20 + TCP 24 with MSS option).
const SYN = hex(`
  00 1a 2b 3c 4d 5e  3c 22 fb 1a 2b 3c  08 00
  45 00 00 2c 12 34 40 00 40 06 00 00 c0 a8 01 17 5d b8 d8 22
  ca 0c 00 50 00 00 03 e8 00 00 00 00 60 02 fa f0 00 00 00 00
  02 04 05 b4`)

describe('Ethernet / IPv4 / TCP offsets', () => {
  const { d } = single(SYN)
  const at = (key: string) => find(d.layers, key)!

  it('places every header field on the right bytes', () => {
    expect([at('eth.dst').offset, at('eth.dst').length]).toEqual([0, 6])
    expect(at('eth.dst').value).toBe('00:1a:2b:3c:4d:5e')
    expect([at('eth.src').offset, at('eth.src').length]).toEqual([6, 6])
    expect([at('eth.type').offset, at('eth.type').length]).toEqual([12, 2])
    expect([at('ip.len').offset, at('ip.len').value]).toEqual([16, '44'])
    expect([at('ip.id').offset, at('ip.id').length]).toEqual([18, 2])
    expect([at('ip.ttl').offset, at('ip.ttl').length, at('ip.ttl').value]).toEqual([22, 1, '64'])
    expect([at('ip.proto').offset, at('ip.proto').value]).toEqual([23, 'TCP (6)'])
    expect([at('ip.checksum').offset, at('ip.checksum').length]).toEqual([24, 2])
    expect([at('ip.src').offset, at('ip.src').value]).toEqual([26, '192.168.1.23'])
    expect([at('ip.dst').offset, at('ip.dst').value]).toEqual([30, '93.184.216.34'])
    expect([at('tcp.srcport').offset, at('tcp.srcport').value]).toEqual([34, '51724'])
    expect([at('tcp.dstport').offset, at('tcp.dstport').length, at('tcp.dstport').value]).toEqual([36, 2, '80'])
    expect([at('tcp.seq').offset, at('tcp.seq').length]).toEqual([38, 4])
    expect([at('tcp.flags').offset, at('tcp.flags').length]).toEqual([46, 2])
    expect(at('tcp.flags.syn').value).toBe('Set')
    expect(at('tcp.flags.ack').value).toBe('Not set')
    expect([at('tcp.window_size_value').offset, at('tcp.window_size_value').value]).toEqual([48, '64240'])
    expect([at('tcp.options.mss_val').offset, at('tcp.options.mss_val').length, at('tcp.options.mss_val').value]).toEqual([56, 2, '1460'])
  })

  it('flags a wrong IPv4 header checksum (this frame has 0x0000)', () => {
    expect(at('ip.checksum').value).toMatch(/incorrect/)
    expect(at('ip.checksum').warn).toBe(true)
  })

  it('shows relative sequence number 0 for the SYN', () => {
    expect(d.facts.tcp!.relSeq).toBe(0)
    expect(d.info).toBe('51724 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460')
  })

  it('keeps every field inside the frame and maps each byte to its owning field', () => {
    for (const f of all(d.layers)) expect(f.offset + f.length).toBeLessThanOrEqual(SYN.length)
    expect(fieldAtOffset(d.layers, 22)!.key).toBe('ip.ttl')
    expect(fieldAtOffset(d.layers, 37)!.key).toBe('tcp.dstport')
    expect(fieldAtOffset(d.layers, 57)!.key).toBe('tcp.options.mss_val')
  })
})

describe('application protocols', () => {
  const eth = (payload: Uint8Array, type = 0x0800) => ethernet('02:00:00:00:00:01', '02:00:00:00:00:02', type, payload)

  it('DNS query name and answers', () => {
    const q = single(eth(ipv4('10.0.0.2', '10.0.0.1', 17, udp(5555, 53, dnsQuery(0xbeef, 'www.example.com')))))
    const name = find(q.d.layers, 'dns.qry.name')!
    // 14 eth + 20 ip + 8 udp + 12 dns header = 54
    expect(name.offset).toBe(54)
    expect(slice(q.frame, name)[0]).toBe(3) // length prefix of "www"
    expect(name.value).toBe('www.example.com')
    expect(q.d.info).toBe('Standard query 0xbeef A www.example.com')

    const r = single(
      eth(ipv4('10.0.0.1', '10.0.0.2', 17, udp(53, 5555, dnsResponse(0xbeef, 'www.example.com', 'A', [{ type: 'CNAME', data: 'edge.example.net' }, { type: 'A', data: '93.184.216.34', name: 'edge.example.net' }])))),
    )
    const a = find(r.d.layers, 'dns.a')!
    expect(slice(r.frame, a)).toEqual([93, 184, 216, 34])
    expect(r.d.facts.dns!.answers.map((x) => x.type)).toEqual(['CNAME', 'A'])
    const nx = single(eth(ipv4('10.0.0.1', '10.0.0.2', 17, udp(53, 5555, dnsResponse(7, 'nope.test', 'A', [], 3)))))
    expect(nx.d.facts.dns!.rcodeName).toBe('No such name')
    expect(nx.d.info).toContain('No such name')
  })

  it('TLS ClientHello SNI and ServerHello cipher', () => {
    const rng = mulberry32(1)
    const ch = single(eth(ipv4('10.0.0.2', '10.0.0.9', 6, tcp(50000, 443, 1, 1, { ack: true, psh: true }, tlsClientHello('bank.example', rng)))))
    const sni = find(ch.d.layers, 'tls.handshake.extensions_server_name')!
    expect(new TextDecoder().decode(ch.frame.subarray(sni.offset, sni.offset + sni.length))).toBe('bank.example')
    expect(ch.d.facts.tls!.cipherSuites).toContain('TLS_AES_128_GCM_SHA256')
    expect(ch.d.info).toBe('Client Hello (SNI=bank.example)')
    const sh = single(eth(ipv4('10.0.0.9', '10.0.0.2', 6, tcp(443, 50000, 1, 1, { ack: true }, tlsServerHello(rng, 0x1302)))))
    const cs = find(sh.d.layers, 'tls.handshake.ciphersuite')!
    expect(slice(sh.frame, cs)).toEqual([0x13, 0x02])
    expect(sh.d.facts.tls!.chosenCipher).toBe('TLS_AES_256_GCM_SHA384')
    expect(sh.d.protocol).toBe('TLSv1.3')
  })

  it('HTTP request line, headers and Basic auth (masked secret)', () => {
    const req = 'GET /admin HTTP/1.1\r\nHost: intranet.local\r\nAuthorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n'
    const h = single(eth(ipv4('10.0.0.2', '10.0.0.9', 6, tcp(50001, 80, 1, 1, { ack: true, psh: true }, text(req)))))
    const m = find(h.d.layers, 'http.request.method')!
    expect(m.offset).toBe(54)
    expect(new TextDecoder().decode(h.frame.subarray(m.offset, m.offset + m.length))).toBe('GET')
    expect(find(h.d.layers, 'http.host')!.offset).toBe(54 + 'GET /admin HTTP/1.1\r\n'.length)
    expect(h.d.facts.creds).toEqual({ proto: 'HTTP', kind: 'basic', user: 'alice', secret: 'hunter2' })
    expect(find(h.d.layers, 'http.authbasic')!.secret).toBe(true)
    expect(h.d.color).toBe('cleartext')
  })

  it('FTP commands and replies, with the password flagged secret', () => {
    const p = single(eth(ipv4('10.0.0.2', '10.0.0.9', 6, tcp(50002, 21, 1, 1, { ack: true, psh: true }, text('PASS s3cret\r\n')))))
    const arg = find(p.d.layers, 'ftp.request.arg')!
    expect(new TextDecoder().decode(p.frame.subarray(arg.offset, arg.offset + arg.length))).toBe('s3cret')
    expect(arg.secret).toBe(true)
    expect(p.d.facts.creds).toMatchObject({ proto: 'FTP', kind: 'pass', secret: 's3cret' })
    const r = single(eth(ipv4('10.0.0.9', '10.0.0.2', 6, tcp(21, 50002, 1, 1, { ack: true, psh: true }, text('530 Login incorrect.\r\n')))))
    expect(r.d.facts.app).toMatchObject({ proto: 'FTP', code: 530, isRequest: false })
  })

  it('DHCP message type and yiaddr', () => {
    const d = single(eth(ipv4('192.168.1.1', '255.255.255.255', 17, udp(67, 68, dhcp(2, 2, 0x1234, '02:00:00:00:00:02', { yiaddr: '192.168.1.50', options: [[54, ipOpt('192.168.1.1')]] })))))
    const y = find(d.d.layers, 'dhcp.ip.your')!
    expect(y.offset).toBe(42 + 16)
    expect(slice(d.frame, y)).toEqual([192, 168, 1, 50])
    expect(d.d.facts.dhcp!.msgType).toBe('Offer')
    expect(d.d.facts.dhcp!.serverId).toBe('192.168.1.1')
  })

  it('ARP and gratuitous ARP', () => {
    const a = single(eth(arp(2, 'de:ad:be:ef:00:01', '10.0.0.1', '02:00:00:00:00:02', '10.0.0.2'), 0x0806))
    expect(find(a.d.layers, 'arp.src.hw_mac')!.offset).toBe(22)
    expect(a.d.info).toBe('10.0.0.1 is at de:ad:be:ef:00:01')
    const g = single(eth(arp(1, 'de:ad:be:ef:00:01', '10.0.0.5', '00:00:00:00:00:00', '10.0.0.5'), 0x0806))
    expect(g.d.info).toContain('Gratuitous')
  })

  it('ICMP echo and IPv6 / ICMPv6', () => {
    const i = single(eth(ipv4('10.0.0.2', '10.0.0.1', 1, icmpEcho(true, 1, 7))))
    expect(find(i.d.layers, 'icmp.type')!.offset).toBe(34)
    expect(i.d.info).toMatch(/Echo \(ping\) request/)
    const icmp6 = Uint8Array.from([128, 0, 0, 0, 0, 1, 0, 1])
    const v6 = single(eth(ipv6('2001:db8::1', 'fe80::2', 58, icmp6), 0x86dd))
    expect(find(v6.d.layers, 'ipv6.src')!.value).toBe('2001:db8::1')
    expect(find(v6.d.layers, 'ipv6.dst')!.offset).toBe(14 + 24)
    expect(v6.d.protocol).toBe('ICMPv6')
  })

  it('unknown payloads become Data and never crash', () => {
    const d = single(eth(ipv4('10.0.0.2', '10.0.0.9', 17, udp(40000, 40001, Uint8Array.from([1, 2, 3, 4])))))
    expect(find(d.d.layers, 'data.data')).toBeTruthy()
    const junk = single(Uint8Array.from([1, 2, 3]))
    expect(junk.d.facts.malformed).toBeTruthy()
    // Truncated DNS: the frame still dissects up to the break.
    const full = eth(ipv4('10.0.0.1', '10.0.0.2', 17, udp(53, 5555, dnsResponse(1, 'a.example', 'A', [{ type: 'A', data: '1.2.3.4' }]))))
    const cut = single(full.subarray(0, full.length - 3))
    expect(cut.d.facts.malformed).toMatch(/Truncated/)
    expect(find(cut.d.layers, 'udp.srcport')).toBeTruthy()
  })
})

describe('link types', () => {
  const ipPayload = ipv4('10.1.1.1', '10.1.1.2', 17, udp(1234, 53, dnsQuery(1, 'x.example')))

  it('raw IP (101)', () => {
    const { d } = single(ipPayload, 101)
    expect(d.facts.ip!.src).toBe('10.1.1.1')
    expect(find(d.layers, 'ip.ttl')!.offset).toBe(8)
  })

  it('BSD loopback / null (0), either byte order', () => {
    const le = new Uint8Array([2, 0, 0, 0, ...ipPayload])
    expect(single(le, 0).d.facts.dns!.qname).toBe('x.example')
    const be = new Uint8Array([0, 0, 0, 2, ...ipPayload])
    expect(single(be, 0).d.facts.dns!.qname).toBe('x.example')
  })

  it('Linux cooked SLL (113)', () => {
    const hdr = [0, 4, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0x08, 0x00]
    const { d } = single(new Uint8Array([...hdr, ...ipPayload]), 113)
    expect(find(d.layers, 'sll.pkttype')!.value).toMatch(/Sent by us/)
    expect(find(d.layers, 'ip.src')!.offset).toBe(16 + 12)
  })

  it('Linux cooked SLL2 (276)', () => {
    const hdr = [0x08, 0x00, 0, 0, 0, 0, 0, 3, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0]
    const { d } = single(new Uint8Array([...hdr, ...ipPayload]), 276)
    expect(find(d.layers, 'sll.ifindex')!.value).toBe('3')
    expect(find(d.layers, 'ip.src')!.offset).toBe(20 + 12)
  })

  it('802.1Q VLAN tags', () => {
    const { d } = single(ethernet('02:00:00:00:00:01', '02:00:00:00:00:02', 0x0800, ipPayload, 42))
    expect(d.facts.vlan!.id).toBe(42)
    expect(find(d.layers, 'ip.src')!.offset).toBe(18 + 12)
  })

  it('a pcapng capture mixing link types dissects each frame correctly', () => {
    const buf = writePcapng(
      [
        { ts: 1, data: ipPayload, interfaceId: 1 },
        { ts: 2, data: ethernet('02:00:00:00:00:01', '02:00:00:00:00:02', 0x0800, ipPayload), interfaceId: 0 },
      ],
      [{ linkType: 1 }, { linkType: 101 }],
    )
    const { index } = indexOf(buf)
    expect(index.packets.map((p) => p.protocol)).toEqual(['DNS', 'DNS'])
  })

  it('IPv4 fragments are labelled and not dissected past the first fragment', () => {
    const frag = ethernet('02:00:00:00:00:01', '02:00:00:00:00:02', 0x0800, ipv4('10.0.0.1', '10.0.0.2', 17, new Uint8Array(40), { mf: false, df: false, fragOffset: 1480 }))
    const { index } = indexOf(writePcap([{ ts: 1, data: frag }]))
    expect(index.packets[0].info).toMatch(/Fragmented IP protocol/)
  })
})
