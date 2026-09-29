import { describe, expect, it } from 'vitest'
import { writePcap } from '../src/core/pcap/writer'
import { TcpSession, Timeline, mulberry32, type Host } from '../src/samples/builder'
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
