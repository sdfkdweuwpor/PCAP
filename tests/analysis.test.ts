import { describe, expect, it } from 'vitest'
import { baseDomain } from '../src/core/analysis/anomalies'
import { followStream } from '../src/core/index/conversations'
import { frameBytes } from '../src/core/index/indexer'
import { writePcap, type FrameToWrite } from '../src/core/pcap/writer'
import { TcpSession, Timeline, arp, dnsQuery, ethernet, icmpEcho, ipv4, mulberry32, tcp, text, udp, type Host } from '../src/samples/builder'
import { SAMPLES } from '../src/samples/samples'
import { indexOf } from './helpers'

const kindsFor = (id: string) => indexOf(SAMPLES.find((s) => s.id === id)!.build()).index.anomalies.map((a) => a.kind).sort()

describe('anomaly heuristics on the samples', () => {
  it('finds exactly the planted anomalies (no false positives on normal traffic)', () => {
    expect(kindsFor('web-basic')).toEqual([])
    expect(kindsFor('https-visit')).toEqual([])
    expect(kindsFor('dhcp-arp')).toEqual([])
    expect(kindsFor('ftp-login')).toEqual(['cleartext-creds'])
    expect(kindsFor('syn-scan')).toEqual(['port-scan', 'rst-storm'])
    expect(kindsFor('arp-spoof')).toEqual(['arp-spoof'])
    expect(kindsFor('dns-tunnel')).toEqual(['dns-tunnel'])
    expect(kindsFor('syn-flood')).toEqual(['syn-flood'])
  })

  it('port scan evidence reports the open ports', () => {
    const a = indexOf(SAMPLES.find((s) => s.id === 'syn-scan')!.build()).index.anomalies.find((x) => x.kind === 'port-scan')!
    expect(a.evidence.openPorts).toBe('22, 80, 443')
    expect(a.evidence.ports).toBe(30)
  })
})

describe('conversations', () => {
  it('tracks handshakes, teardown and per-direction bytes', () => {
    const { index } = indexOf(SAMPLES.find((s) => s.id === 'web-basic')!.build())
    const tcp = index.conversations.find((c) => c.proto === 'TCP')!
    expect(tcp.app).toBe('HTTP')
    expect(tcp.handshake).toEqual({ syn: 3, synAck: 4, ack: 5 })
    expect(tcp.closedBy).toBe('fin')
    expect(tcp.a).toEqual({ addr: '192.168.1.23', port: 51724 })
    expect(tcp.bytesAtoB + tcp.bytesBtoA).toBe(tcp.bytes)
  })
})

describe('Telnet credential detection across keystroke packets', () => {
  it('reassembles the username and password typed one character at a time', () => {
    const rng = mulberry32(3)
    const tl = new Timeline(1000)
    const c: Host = { mac: '02:00:00:00:00:01', ip: '10.0.0.2' }
    const s: Host = { mac: '02:00:00:00:00:02', ip: '10.0.0.3' }
    const t = new TcpSession(tl, { client: c, server: s, cport: 40000, sport: 23 }, rng)
    t.handshake()
    t.send(false, 'Ubuntu 22.04\r\nlogin: ')
    for (const ch of 'bob') {
      t.send(true, ch)
      t.send(false, ch) // echo
    }
    t.send(true, '\r\n')
    t.send(false, '\r\nPassword: ')
    for (const ch of 'pw1!') t.send(true, ch) // not echoed
    t.send(true, '\r\n')
    t.send(false, '\r\nWelcome bob\r\n$ ')
    const { index } = indexOf(writePcap(tl.frames))
    const creds = index.packets.filter((p) => p.facts.creds)
    const pass = creds.filter((p) => p.facts.creds!.kind === 'pass')
    expect(pass).toHaveLength(5)
    expect(pass[0].facts.creds).toEqual({ proto: 'Telnet', kind: 'pass', user: 'bob', secret: 'pw1!' })
    expect(creds.find((p) => p.facts.creds!.kind === 'user')!.facts.creds!.user).toBe('bob')
    expect(index.anomalies.map((a) => a.kind)).toContain('cleartext-creds')
  })
})

// ---------------------------------------------------------------- anomaly detector edge cases (synthetic captures)

const mac = (n: number) => `02:00:00:00:${(n >> 8).toString(16).padStart(2, '0')}:${(n & 0xff).toString(16).padStart(2, '0')}`
const host = (n: number, net = '10.0.0.'): Host => ({ mac: mac(n), ip: `${net}${n}` })
const analyse = (frames: FrameToWrite[]) => indexOf(writePcap(frames)).index.anomalies
const anomalyOf = (frames: FrameToWrite[], kind: string) => analyse(frames).find((a) => a.kind === kind)

/** One SYN probe answered by RST, all from one source port (like nmap -sS). */
function probe(tl: Timeline, c: Host, s: Host, port: number) {
  tl.ip(c, s, 6, tcp(40000, port, 1000, 0, { syn: true }, undefined, { mss: 1460 }))
  tl.ip(s, c, 6, tcp(port, 40000, 0, 1001, { rst: true, ack: true }))
}

/** A real, completed connection from `c` to `s` on `port`. */
function connect(tl: Timeline, c: Host, s: Host, port: number, cport: number, rng: () => number) {
  new TcpSession(tl, { client: c, server: s, cport, sport: port, rtt: 0.001 }, rng).handshake().exchange('hello', 'world').close()
}

describe('port scan', () => {
  const c = host(2)
  const s = host(9)

  it('fires for SYN-only probes of 15+ ports, and reports closed/open counts', () => {
    const tl = new Timeline(1000)
    for (let port = 1000; port < 1016; port++) probe(tl, c, s, port)
    const a = anomalyOf(tl.frames, 'port-scan')!
    expect(a).toBeTruthy()
    expect(a.evidence).toEqual({ scanner: '10.0.0.2', target: '10.0.0.9', ports: 16, rsts: 16, openPorts: 'none' })
    expect(a.packets).toHaveLength(16)
    expect(a.detail).toBe('10.0.0.2 sent SYNs to 16 different ports on 10.0.0.9; 16 were answered with RST (closed) and 0 with SYN-ACK (open).')
  })

  it('needs at least 15 distinct ports', () => {
    const tl = new Timeline(1000)
    for (let port = 1000; port < 1014; port++) probe(tl, c, s, port)
    expect(analyse(tl.frames).map((x) => x.kind)).not.toContain('port-scan')
  })

  it('does NOT fire for a client that opens 16 real connections to different ports on one server', () => {
    const tl = new Timeline(1000)
    const rng = mulberry32(5)
    for (let i = 0; i < 16; i++) connect(tl, c, s, 8000 + i, 41000 + i, rng)
    expect(analyse(tl.frames).map((x) => x.kind)).not.toContain('port-scan')
  })

  it('does NOT fire when most (16 of 20) probed ports complete the handshake, but does when only a few (3 of 20) do', () => {
    const rng = mulberry32(6)
    const build = (completed: number) => {
      const tl = new Timeline(1000)
      for (let i = 0; i < 20; i++) {
        if (i < completed) connect(tl, c, s, 9000 + i, 42000 + i, rng)
        else probe(tl, c, s, 9000 + i)
      }
      return tl.frames
    }
    expect(analyse(build(16)).map((x) => x.kind)).not.toContain('port-scan')
    const a = anomalyOf(build(3), 'port-scan')!
    expect(a).toBeTruthy()
    expect(a.evidence.ports).toBe(20)
    expect(a.evidence.openPorts).toBe('9000, 9001, 9002')
  })
})

describe('SYN flood', () => {
  const server = host(80)
  /** `n` SYNs to server:80 from `sources` distinct addresses, `spacing` seconds apart. */
  function flood(n: number, sources: number, spacing: number) {
    const tl = new Timeline(2000)
    for (let i = 0; i < n; i++) {
      const src: Host = { mac: mac(100 + (i % sources)), ip: `198.51.100.${1 + (i % sources)}` }
      tl.wait(spacing).ip(src, server, 6, tcp(30000 + i, 80, 5000 + i, 0, { syn: true }, undefined, { mss: 1460 }))
    }
    return tl.frames
  }

  it('fires for 40 SYNs from 40 addresses inside a second, and lists every SYN (not just 20)', () => {
    const a = anomalyOf(flood(60, 60, 0.01), 'syn-flood')!
    expect(a).toBeTruthy()
    expect(a.evidence).toEqual({ target: '10.0.0.80:80', syns: 60, sources: 60, completed: 0 })
    expect(a.detail).toBe('60 SYNs hit 10.0.0.80:80 from 60 different source addresses, but only 0 of 60 connections finished the handshake.')
    expect(a.packets).toHaveLength(60)
    expect(a.packets).toEqual(Array.from({ length: 60 }, (_, i) => i + 1))
  })

  it('needs at least 40 SYNs', () => {
    expect(anomalyOf(flood(40, 40, 0.01), 'syn-flood')).toBeTruthy()
    expect(anomalyOf(flood(39, 39, 0.01), 'syn-flood')).toBeUndefined()
  })

  it('needs sources >= 0.5 x SYNs: 40 SYNs from 2 sources is one busy client, not a flood', () => {
    expect(anomalyOf(flood(40, 2, 0.01), 'syn-flood')).toBeUndefined()
    expect(anomalyOf(flood(40, 19, 0.01), 'syn-flood')).toBeUndefined()
    expect(anomalyOf(flood(40, 20, 0.01), 'syn-flood')).toBeTruthy() // exactly half
  })

  it('needs the 40 SYNs to arrive within 10 seconds: 40 SYNs spread over 5 minutes is not a flood', () => {
    expect(anomalyOf(flood(40, 40, 7.5), 'syn-flood')).toBeUndefined()
    expect(anomalyOf(flood(40, 40, 0.3), 'syn-flood')).toBeUndefined() // ~11.7 s end to end: never 40 inside one 10 s window
    expect(anomalyOf(flood(40, 40, 0.2), 'syn-flood')).toBeTruthy() // ~7.8 s
  })

  it('does not fire when the connections complete (a flash crowd, not half-open floods)', () => {
    const tl = new Timeline(2000)
    const rng = mulberry32(9)
    for (let i = 0; i < 40; i++) {
      const src: Host = { mac: mac(100 + i), ip: `198.51.100.${1 + i}` }
      new TcpSession(tl, { client: src, server, cport: 30000 + i, sport: 80, rtt: 0.0002 }, rng).handshake()
    }
    expect(analyse(tl.frames).map((x) => x.kind)).not.toContain('syn-flood')
  })
})

describe('ARP spoof', () => {
  const GW = '192.168.1.1'
  const A = '00:1a:2b:3c:4d:5e' // the real gateway
  const B = 'de:ad:be:ef:13:37' // someone else
  const V = { mac: '3c:22:fb:1a:2b:3c', ip: '192.168.1.23' }
  const reply = (senderMac: string, senderIp: string, to = V) =>
    ethernet(senderMac, to.mac, 0x0806, arp(2, senderMac, senderIp, to.mac, to.ip))
  const request = (senderMac: string, senderIp: string, targetIp: string) =>
    ethernet(senderMac, 'ff:ff:ff:ff:ff:ff', 0x0806, arp(1, senderMac, senderIp, '00:00:00:00:00:00', targetIp))
  const seq = (...datas: Uint8Array[]): FrameToWrite[] => datas.map((data, i) => ({ ts: 100 + i, data }))

  it('does NOT fire for a single new MAC claiming an IP (a replaced NIC)', () => {
    const frames = seq(reply(A, GW), reply(A, GW), reply(B, GW))
    expect(analyse(frames).map((x) => x.kind)).not.toContain('arp-spoof')
  })

  it('fires when the new MAC claims the IP at least twice', () => {
    const a = anomalyOf(seq(reply(A, GW), reply(B, GW), reply(B, GW)), 'arp-spoof')!
    expect(a).toBeTruthy()
    expect(a.evidence).toEqual({ ip: GW, originalMac: A, originalFrame: 1, attackerMac: B, claims: 2 })
    expect(a.detail).toBe(`${GW} was first announced by ${A}, then claimed by ${B} (2 ARP messages). Two MACs for one IP is the signature of a man-in-the-middle.`)
  })

  it('fires when the original MAC comes back after a single claim (the two fight over the IP), with singular wording', () => {
    const a = anomalyOf(seq(reply(A, GW), reply(B, GW), reply(A, GW)), 'arp-spoof')!
    expect(a).toBeTruthy()
    expect(a.evidence.claims).toBe(1)
    expect(a.detail).toContain('(1 ARP message)')
    expect(a.detail).not.toContain('messages')
    expect(a.packets).toEqual([2])
  })

  it('does not count the original MAC coming back BEFORE the single claim as a fight', () => {
    expect(analyse(seq(reply(A, GW), reply(A, GW), reply(B, GW))).map((x) => x.kind)).not.toContain('arp-spoof')
  })

  it('lists ALL ARP frames sent from the attacker MAC (other IPs and requests too), and nothing else', () => {
    const icmpFromB = ethernet(B, A, 0x0800, ipv4('192.168.1.66', '8.8.8.8', 1, icmpEcho(true, 1, 1)))
    const frames = seq(
      reply(A, GW), //                              1 original owner
      reply(B, GW), //                              2 attacker claim #1
      icmpFromB, //                                 3 not ARP: excluded
      reply(B, V.ip, { mac: A, ip: GW }), //        4 attacker also claims the victim's IP (other direction)
      reply(A, GW), //                              5 real owner again: not from the attacker
      reply(B, GW), //                              6 attacker claim #2
      request(B, '192.168.1.66', GW), //            7 an ARP request from the attacker MAC
    )
    const a = anomalyOf(frames, 'arp-spoof')!
    expect(a).toBeTruthy()
    expect(a.evidence.ip).toBe(GW)
    expect(a.evidence.claims).toBe(2)
    expect(a.packets).toEqual([2, 4, 6, 7])
  })

  it('ignores ARP probes (sender IP 0.0.0.0)', () => {
    const probeFrom = (m: string) => ethernet(m, 'ff:ff:ff:ff:ff:ff', 0x0806, arp(1, m, '0.0.0.0', '00:00:00:00:00:00', '192.168.1.50'))
    expect(analyse(seq(probeFrom(A), probeFrom(B), probeFrom(B), probeFrom(A))).map((x) => x.kind)).not.toContain('arp-spoof')
  })

  it('the arp-spoof sample reports every ARP frame from the attacker MAC (12 of them)', () => {
    const { index } = indexOf(SAMPLES.find((x) => x.id === 'arp-spoof')!.build())
    const a = index.anomalies.find((x) => x.kind === 'arp-spoof')!
    const fromAttacker = index.packets.filter((p) => p.facts.arp?.senderMac === 'de:ad:be:ef:13:37').map((p) => p.no)
    expect(fromAttacker).toHaveLength(12)
    expect(a.packets).toEqual(fromAttacker)
    // The report is about 192.168.1.23 (first claimed by the victim's own request in frame 1): 6 of the 12 frames claim it.
    expect(a.evidence).toMatchObject({ ip: '192.168.1.23', originalMac: '3c:22:fb:1a:2b:3c', originalFrame: 1, attackerMac: 'de:ad:be:ef:13:37', claims: 6 })
    expect(a.detail).toContain('(6 ARP messages)')
  })
})

describe('cleartext credentials', () => {
  const c = host(2)
  const s = host(9)
  function ftp(tl: Timeline, cport: number, user: string, pass: string, rng = mulberry32(3)) {
    const t = new TcpSession(tl, { client: c, server: s, cport, sport: 21, rtt: 0.001 }, rng).handshake()
    t.send(false, '220 ready\r\n').send(true, `USER ${user}\r\n`).send(false, '331 Password required\r\n')
    t.send(true, `PASS ${pass}\r\n`).send(false, '230 Logged in\r\n').close()
  }

  it('ignores anonymous FTP (USER anonymous / PASS guest@) in any letter case', () => {
    for (const user of ['anonymous', 'Anonymous', 'ANONYMOUS', 'ftp']) {
      const tl = new Timeline(500)
      ftp(tl, 43000, user, 'guest@example.com')
      const { index } = indexOf(writePcap(tl.frames))
      // The dissector still sees the credentials (they are shown in the packet list)…
      expect(index.packets.filter((p) => p.facts.creds), user).toHaveLength(2)
      // …but the anomaly detector does not count them.
      expect(index.anomalies.map((x) => x.kind), user).not.toContain('cleartext-creds')
    }
  })

  it('still fires for a real login (USER alice), naming the user and counting the two credential packets', () => {
    const tl = new Timeline(500)
    ftp(tl, 43000, 'alice', 'hunter2')
    const a = anomalyOf(tl.frames, 'cleartext-creds')!
    expect(a).toBeTruthy()
    expect(a.detail).toBe('FTP sent a login for "alice" without encryption — anyone on the path can read it.')
    expect(a.evidence).toEqual({ protocols: 'FTP', user: 'alice', packets: 2 })
    expect(a.severity).toBe('high')
  })

  it('an anonymous session and a real login in one capture: only the real login is reported', () => {
    const tl = new Timeline(500)
    ftp(tl, 43000, 'anonymous', 'guest@')
    const mid = tl.frames.length
    ftp(tl, 43001, 'alice', 'hunter2')
    const { index } = indexOf(writePcap(tl.frames))
    const a = index.anomalies.find((x) => x.kind === 'cleartext-creds')!
    expect(a.evidence.user).toBe('alice')
    expect(a.packets).toHaveLength(2)
    expect(a.packets.every((no) => no > mid)).toBe(true)
  })

  it('anonymous FTP does not hide an HTTP Basic login in the same capture', () => {
    const tl = new Timeline(500)
    ftp(tl, 43000, 'anonymous', 'guest@')
    const web = host(80)
    new TcpSession(tl, { client: c, server: web, cport: 43100, sport: 80, rtt: 0.001 }, mulberry32(4))
      .handshake()
      .send(true, 'GET /admin HTTP/1.1\r\nHost: intranet.local\r\nAuthorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n')
    const a = anomalyOf(tl.frames, 'cleartext-creds')!
    expect(a.evidence).toEqual({ protocols: 'HTTP', user: 'alice', packets: 1 })
  })
})

describe('DNS tunnel', () => {
  const rng = mulberry32(11)
  const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
  const rand = (n: number, alphabet = B32) => Array.from({ length: n }, () => alphabet[Math.floor(rng() * alphabet.length)]).join('')
  const queries = (names: string[], type: 'A' | 'TXT' | 'PTR' = 'TXT'): FrameToWrite[] =>
    names.map((name, i) => ({ ts: 300 + i, data: ethernet(mac(2), mac(53), 0x0800, ipv4('10.0.0.2', '10.0.0.53', 17, udp(5000 + i, 53, dnsQuery(i + 1, name, type)))) }))

  it('baseDomain: the last two labels, or three under a country second level', () => {
    expect(baseDomain('www.example.com')).toBe('example.com')
    expect(baseDomain('example.com')).toBe('example.com')
    expect(baseDomain('example.com.')).toBe('example.com')
    expect(baseDomain('a.b.c.d.example.com')).toBe('example.com')
    expect(baseDomain('x.y.example.co.uk')).toBe('example.co.uk')
    expect(baseDomain('x.example.org.uk')).toBe('example.org.uk')
    expect(baseDomain('a.b.example.com.au')).toBe('example.com.au')
    expect(baseDomain('x.example.ne.jp')).toBe('example.ne.jp')
    expect(baseDomain('example.de')).toBe('example.de')
    expect(baseDomain('x.y.example.de')).toBe('example.de')
    expect(baseDomain('co.uk')).toBe('co.uk')
    expect(baseDomain('foo.co')).toBe('foo.co')
    expect(baseDomain('localhost')).toBe('localhost')
  })

  it('groups x.y.example.co.uk under example.co.uk, not under co.uk', () => {
    const names = Array.from({ length: 12 }, () => `${rand(30)}.${rand(20)}.example.co.uk`)
    const a = anomalyOf(queries(names), 'dns-tunnel')!
    expect(a).toBeTruthy()
    expect(a.evidence).toMatchObject({ domain: 'example.co.uk', queries: 12, txt: 12 })
    expect(a.detail).toContain('12 queries to *.example.co.uk')
    expect(a.packets).toHaveLength(12)
  })

  it('does not merge unrelated registrable domains that share a public suffix (5 + 5 under co.uk is not 10)', () => {
    const names = [
      ...Array.from({ length: 5 }, () => `${rand(30)}.alpha.co.uk`),
      ...Array.from({ length: 5 }, () => `${rand(30)}.beta.co.uk`),
    ]
    expect(analyse(queries(names)).map((x) => x.kind)).not.toContain('dns-tunnel')
    // …while 8 to one of them is enough.
    const eight = Array.from({ length: 8 }, () => `${rand(30)}.alpha.co.uk`)
    expect(anomalyOf(queries(eight), 'dns-tunnel')!.evidence.domain).toBe('alpha.co.uk')
  })

  it('ignores reverse-lookup names under .in-addr.arpa and .ip6.arpa', () => {
    const nibbles = () => Array.from({ length: 32 }, () => rand(1, '0123456789abcdef')).join('.')
    const ip6 = Array.from({ length: 12 }, () => `${nibbles()}.ip6.arpa`)
    expect(analyse(queries(ip6, 'PTR')).map((x) => x.kind)).not.toContain('dns-tunnel')
    // Control: the very same labels under an ordinary domain look exactly like a tunnel.
    const control = ip6.map((n) => n.replace(/ip6\.arpa$/, 'example.com'))
    expect(anomalyOf(queries(control, 'PTR'), 'dns-tunnel')!.evidence.domain).toBe('example.com')
    // A long random label under in-addr.arpa is excluded too (and would be a tunnel anywhere else).
    const v4 = Array.from({ length: 12 }, () => `${rand(30)}.in-addr.arpa`)
    expect(analyse(queries(v4, 'PTR')).map((x) => x.kind)).not.toContain('dns-tunnel')
    expect(anomalyOf(queries(v4.map((n) => n.replace('in-addr.arpa', 'example.net')), 'PTR'), 'dns-tunnel')).toBeTruthy()
  })

  it('needs 8 queries and ignores short, ordinary names', () => {
    expect(analyse(queries(Array.from({ length: 7 }, () => `${rand(30)}.example.net`))).map((x) => x.kind)).not.toContain('dns-tunnel')
    expect(anomalyOf(queries(Array.from({ length: 8 }, () => `${rand(30)}.example.net`)), 'dns-tunnel')).toBeTruthy()
    expect(analyse(queries(Array.from({ length: 30 }, (_, i) => `host${i}.example.net`))).map((x) => x.kind)).not.toContain('dns-tunnel')
  })
})

describe('failed logins', () => {
  const server = host(9)
  const client = (n: number) => host(n, '10.0.1.')
  /** A server reply (from `port`) to `to`, `gap` seconds after the previous frame. */
  const say = (tl: Timeline, to: Host, port: number, body: string, gap: number) =>
    tl.wait(gap).ip(server, to, 6, tcp(port, 50000, 1, 1, { ack: true, psh: true }, text(body)))
  const FTP530 = '530 Login incorrect.\r\n'
  const HTTP401 = 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="x"\r\nContent-Length: 0\r\n\r\n'
  const failed = (frames: FrameToWrite[]) => anomalyOf(frames, 'failed-logins')

  it('fires for 3 FTP 530s from one server to one client, with the server → client pair in the evidence', () => {
    const tl = new Timeline(700)
    for (let i = 0; i < 3; i++) say(tl, client(2), 21, FTP530, 20)
    const a = failed(tl.frames)!
    expect(a).toBeTruthy()
    expect(a.evidence).toEqual({ failures: 3, protocol: 'FTP', client: '10.0.1.2', server: '10.0.0.9' })
    expect(a.detail).toMatch(/^3 FTP authentication failures from 10\.0\.0\.9 to 10\.0\.1\.2 in 40\.0 s — consistent with password guessing\.$/)
    expect(a.packets).toEqual([1, 2, 3])
  })

  it('needs at least 3 FTP failures', () => {
    const tl = new Timeline(700)
    for (let i = 0; i < 2; i++) say(tl, client(2), 21, FTP530, 20)
    expect(failed(tl.frames)).toBeUndefined()
  })

  it('3 failures sent to three different clients do not fire', () => {
    const tl = new Timeline(700)
    for (let i = 0; i < 3; i++) say(tl, client(2 + i), 21, FTP530, 20)
    expect(failed(tl.frames)).toBeUndefined()
  })

  it('needs the failures inside a 5-minute window', () => {
    const slow = new Timeline(700)
    for (let i = 0; i < 3; i++) say(slow, client(2), 21, FTP530, 200) // 0, 200, 400 s: at most 2 in any 300 s
    expect(failed(slow.frames)).toBeUndefined()
    const ok = new Timeline(700)
    for (const gap of [0, 100, 150]) say(ok, client(2), 21, FTP530, gap) // 0, 100, 250 s
    expect(failed(ok.frames)!.evidence.failures).toBe(3)
  })

  it('an HTTP 401 is the normal first step of authentication, so it takes 5 of them', () => {
    const four = new Timeline(700)
    for (let i = 0; i < 4; i++) say(four, client(2), 80, HTTP401, 10)
    expect(failed(four.frames)).toBeUndefined()
    const five = new Timeline(700)
    for (let i = 0; i < 5; i++) say(five, client(2), 80, HTTP401, 10)
    const a = failed(five.frames)!
    expect(a.evidence).toEqual({ failures: 5, protocol: 'HTTP', client: '10.0.1.2', server: '10.0.0.9' })
    const slow = new Timeline(700)
    for (let i = 0; i < 5; i++) say(slow, client(2), 80, HTTP401, 100) // 5 failures over 400 s: at most 4 per 300 s
    expect(failed(slow.frames)).toBeUndefined()
  })

  it('counts protocols separately: 2 FTP + 4 HTTP failures do not add up', () => {
    const tl = new Timeline(700)
    for (let i = 0; i < 2; i++) say(tl, client(2), 21, FTP530, 5)
    for (let i = 0; i < 4; i++) say(tl, client(2), 80, HTTP401, 5)
    expect(failed(tl.frames)).toBeUndefined()
  })

  it('reports the client with the most failures, and lists every failure (25 > 20)', () => {
    const tl = new Timeline(700)
    for (let i = 0; i < 3; i++) say(tl, client(2), 21, FTP530, 5)
    for (let i = 0; i < 25; i++) say(tl, client(3), 21, FTP530, 5)
    const a = failed(tl.frames)!
    expect(a.evidence).toMatchObject({ failures: 25, client: '10.0.1.3' })
    expect(a.packets).toHaveLength(25)
    expect(a.packets[0]).toBe(4)
    expect(a.packets[24]).toBe(28)
  })

  it('reports only the burst that fired, not failures from hours earlier or later', () => {
    const tl = new Timeline(700)
    for (let i = 0; i < 3; i++) say(tl, client(2), 21, FTP530, 20) // frames 1-3: the burst
    say(tl, client(2), 21, FTP530, 36000) // frame 4: ten hours later
    const a = failed(tl.frames)!
    expect(a.packets).toEqual([1, 2, 3])
    expect(a.evidence.failures).toBe(3)
    expect(a.detail).toMatch(/^3 FTP authentication failures .* in 40\.0 s/)
  })
})

describe('anomaly evidence lists are not truncated', () => {
  const anomaly = (id: string, kind: string) => indexOf(SAMPLES.find((s) => s.id === id)!.build()).index.anomalies.find((a) => a.kind === kind)!

  it('syn-flood: every SYN to the target is listed (121, well above 20)', () => {
    const { index } = indexOf(SAMPLES.find((s) => s.id === 'syn-flood')!.build())
    const a = index.anomalies.find((x) => x.kind === 'syn-flood')!
    const syns = index.packets.filter((p) => p.facts.tcp?.flags.syn && !p.facts.tcp.flags.ack && p.facts.ip?.dst === '10.0.0.80' && p.facts.tcp.dstPort === 80).map((p) => p.no)
    expect(a.evidence.syns).toBe(121)
    expect(a.packets).toHaveLength(121)
    expect(a.packets).toEqual(syns)
  })

  it('port-scan, dns-tunnel and rst-storm list one entry per probe / query / reset', () => {
    expect(anomaly('syn-scan', 'port-scan').packets).toHaveLength(30)
    expect(anomaly('dns-tunnel', 'dns-tunnel').packets).toHaveLength(24)
    expect(anomaly('syn-scan', 'rst-storm').packets).toHaveLength(30)
    expect(anomaly('ftp-login', 'cleartext-creds').packets).toEqual([6, 9, 12, 15])
  })
})

// ---------------------------------------------------------------- follow stream

describe('followStream (TCP reassembly)', () => {
  const C = '10.0.0.2'
  const S = '10.0.0.9'
  const eth = (payload: Uint8Array) => ethernet(mac(2), mac(9), 0x0800, payload)
  const cli = (seq: number, ack: number, flags: Parameters<typeof tcp>[4], data = '') => eth(ipv4(C, S, 6, tcp(40000, 9000, seq, ack, flags, text(data))))
  const srv = (seq: number, ack: number, flags: Parameters<typeof tcp>[4], data = '') => eth(ipv4(S, C, 6, tcp(9000, 40000, seq, ack, flags, text(data))))
  /** SYN (client ISN 1000), SYN-ACK (server ISN 5000), ACK: the first data byte is 1001 from the client and 5001 from the server. */
  const HS = [cli(1000, 0, { syn: true }), srv(5000, 1001, { syn: true, ack: true }), cli(1001, 5001, { ack: true })]
  const dec = new TextDecoder()

  function follow(frames: Uint8Array[]) {
    const { index, bytes } = indexOf(writePcap(frames.map((data, i) => ({ ts: 1 + i, data }))))
    const conv = index.conversations.find((c) => c.proto === 'TCP')!
    const segs = followStream(conv, (no) => index.packets[no - 1], (p) => frameBytes(bytes, p))
    return segs.map((x) => ({ frame: x.frame, fromA: x.fromA, text: dec.decode(x.bytes) }))
  }
  const ack = { ack: true, psh: true }

  it('delivers in-order data as-is, one segment per data frame', () => {
    expect(follow([...HS, cli(1001, 5001, ack, 'AAAA'), srv(5001, 1005, ack, 'xy'), cli(1005, 5003, ack, 'BBBB')])).toEqual([
      { frame: 4, fromA: true, text: 'AAAA' },
      { frame: 5, fromA: false, text: 'xy' },
      { frame: 6, fromA: true, text: 'BBBB' },
    ])
  })

  it('holds out-of-order segments until the gap is filled, then delivers in sequence order', () => {
    // Wire order: seq 1009, 1001, 1005.
    const out = follow([...HS, cli(1009, 5001, ack, 'CCCC'), cli(1001, 5001, ack, 'AAAA'), cli(1005, 5001, ack, 'BBBB')])
    expect(out).toEqual([
      { frame: 5, fromA: true, text: 'AAAA' },
      { frame: 6, fromA: true, text: 'BBBB' },
      { frame: 4, fromA: true, text: 'CCCC' },
    ])
    expect(out.map((x) => x.text).join('')).toBe('AAAABBBBCCCC')
  })

  it('each direction is reordered independently', () => {
    const out = follow([...HS, cli(1001, 5001, ack, 'GET '), srv(5004, 1005, ack, '2'), srv(5001, 1005, ack, 'OK1')])
    expect(out).toEqual([
      { frame: 4, fromA: true, text: 'GET ' },
      { frame: 6, fromA: false, text: 'OK1' },
      { frame: 5, fromA: false, text: '2' },
    ])
  })

  it('keeps sequence order on a snaplen-truncated capture (advances by the IP-declared length, not the captured bytes)', () => {
    // Frame 4 carries 8 payload bytes on the wire but only the first 4 were captured.
    const cut = cli(1001, 5001, ack, 'AAAAaaaa')
    const frames = [...HS, cut, srv(5001, 1009, ack, 'xy'), cli(1009, 5003, ack, 'BBBB')]
    const { index, bytes } = indexOf(
      writePcap(frames.map((data, i) => (i === 3 ? { ts: 1 + i, data: data.subarray(0, data.length - 4), origLen: data.length } : { ts: 1 + i, data }))),
    )
    expect(index.packets[3].facts.tcp).toMatchObject({ payloadLen: 4, segLen: 8 })
    const conv = index.conversations.find((c) => c.proto === 'TCP')!
    const out = followStream(conv, (no) => index.packets[no - 1], (p) => frameBytes(bytes, p)).map((x) => ({ frame: x.frame, text: dec.decode(x.bytes) }))
    expect(out).toEqual([
      { frame: 4, text: 'AAAA' },
      { frame: 5, text: 'xy' },
      { frame: 6, text: 'BBBB' },
    ])
  })

  it('does not trust an IP length that overstates an untruncated frame', () => {
    const bad = cli(1001, 5001, ack, 'AAAA').slice()
    new DataView(bad.buffer).setUint16(14 + 2, 1400) // IPv4 total length far beyond the 58-byte frame
    const { index } = indexOf(writePcap([...HS, bad].map((data, i) => ({ ts: 1 + i, data }))))
    expect(index.packets[3].facts.tcp!.payloadLen).toBe(4)
    expect(index.packets[3].facts.tcp!.segLen).toBeUndefined()
  })

  it('drops retransmitted bytes and trims overlapping ones', () => {
    const out = follow([
      ...HS,
      cli(1001, 5001, ack, 'AAAA'), //   4: 1001-1004
      cli(1005, 5001, ack, 'BBBB'), //   5: 1005-1008
      cli(1005, 5001, ack, 'BBBB'), //   6: exact retransmission, dropped
      cli(1003, 5001, ack, 'AABB'), //   7: entirely inside bytes already delivered, dropped
      cli(1007, 5001, ack, 'BBCCCC'), // 8: first 2 bytes already delivered, only 'CCCC' is new
    ])
    expect(out).toEqual([
      { frame: 4, fromA: true, text: 'AAAA' },
      { frame: 5, fromA: true, text: 'BBBB' },
      { frame: 8, fromA: true, text: 'CCCC' },
    ])
  })

  it('a segment that overlaps the previous one from the front only contributes its new tail', () => {
    const out = follow([...HS, cli(1001, 5001, ack, 'AAAABB'), cli(1005, 5001, ack, 'BBCCCC')])
    expect(out.map((x) => x.text)).toEqual(['AAAABB', 'CCCC'])
    expect(out[1].frame).toBe(5)
  })

  it('flushes a gap at the end: what arrived is delivered lowest sequence first, without filler bytes', () => {
    // BBBB (1005-1008) is missing from the capture.
    const out = follow([...HS, cli(1001, 5001, ack, 'AAAA'), cli(1013, 5001, ack, 'DDDD'), cli(1009, 5001, ack, 'CCCC')])
    expect(out).toEqual([
      { frame: 4, fromA: true, text: 'AAAA' },
      { frame: 6, fromA: true, text: 'CCCC' },
      { frame: 5, fromA: true, text: 'DDDD' },
    ])
  })

  it('handles 32-bit sequence number wraparound', () => {
    const wrapHs = [cli(0xfffffffc, 0, { syn: true }), srv(5000, 0xfffffffd, { syn: true, ack: true }), cli(0xfffffffd, 5001, { ack: true })]
    // AAAA occupies 0xfffffffd..0x00000000; BBBB starts at seq 1. BBBB arrives first.
    const out = follow([...wrapHs, cli(1, 5001, ack, 'BBBB'), cli(0xfffffffd, 5001, ack, 'AAAA')])
    expect(out).toEqual([
      { frame: 5, fromA: true, text: 'AAAA' },
      { frame: 4, fromA: true, text: 'BBBB' },
    ])
  })

  it('reassembles the web-basic HTTP exchange in request/response order', () => {
    const { index, bytes } = indexOf(SAMPLES.find((s) => s.id === 'web-basic')!.build())
    const conv = index.conversations.find((c) => c.proto === 'TCP')!
    const segs = followStream(conv, (no) => index.packets[no - 1], (p) => frameBytes(bytes, p))
    expect(segs.map((x) => [x.frame, x.fromA])).toEqual([
      [6, true],
      [8, false],
      [10, true],
      [11, false],
    ])
    expect(dec.decode(segs[0].bytes)).toMatch(/^GET \/index\.html HTTP\/1\.1\r\n/)
    expect(dec.decode(segs[1].bytes)).toMatch(/^HTTP\/1\.1 200 OK\r\n/)
    expect(dec.decode(segs[2].bytes)).toMatch(/^GET \/favicon\.ico HTTP\/1\.1\r\n/)
    expect(dec.decode(segs[3].bytes)).toMatch(/^HTTP\/1\.1 404 Not Found\r\n/)
  })

  it('UDP conversations are returned per datagram, in capture order', () => {
    const { index, bytes } = indexOf(SAMPLES.find((s) => s.id === 'web-basic')!.build())
    const conv = index.conversations.find((c) => c.proto === 'UDP')!
    const segs = followStream(conv, (no) => index.packets[no - 1], (p) => frameBytes(bytes, p))
    expect(segs.map((x) => [x.frame, x.fromA, x.bytes.length])).toEqual([
      [1, true, 33], // 12-byte DNS header + 17-byte name + 4 (type, class)
      [2, false, 127],
    ])
  })
})
