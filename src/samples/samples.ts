// Built-in synthetic sample captures. Each is generated deterministically so the app works offline
// and so tests can assert on exact content. `npm run samples` writes them to /samples as files.

import { writePcap, writePcapng } from '../core/pcap/writer'
import {
  arp,
  dhcp,
  dnsQuery,
  dnsResponse,
  ethernet,
  icmpEcho,
  ipOpt,
  ipv4,
  mulberry32,
  strOpt,
  tcp,
  TcpSession,
  Timeline,
  tlsAppData,
  tlsAlert,
  tlsChangeCipherSpec,
  tlsClientHello,
  tlsServerHello,
  u32Opt,
  udp,
  type Host,
} from './builder'

export type Difficulty = 'Recruit' | 'Analyst' | 'Hunter'

export interface SampleCapture {
  id: string
  title: string
  difficulty: Difficulty
  learn: string
  fileName: string
  build: () => Uint8Array
}

const T0 = 1710410400 // 2024-03-14 10:00:00 UTC

const client: Host = { mac: '3c:22:fb:1a:2b:3c', ip: '192.168.1.23' }
const gateway: Host = { mac: '00:1a:2b:3c:4d:5e', ip: '192.168.1.1' }
const resolver: Host = { mac: gateway.mac, ip: '192.168.1.1' }

function dnsLookup(tl: Timeline, id: number, name: string, type: 'A' | 'AAAA' | 'TXT', answers: Parameters<typeof dnsResponse>[3], rcode = 0, cport = 53000 + (id % 1000)) {
  tl.ip(client, resolver, 17, udp(cport, 53, dnsQuery(id, name, type)), 0.001, { ttl: 64, id: id & 0xffff })
  tl.ip(resolver, client, 17, udp(53, cport, dnsResponse(id, name, type, answers, rcode)), 0.012, { ttl: 64, id: (id + 7) & 0xffff })
}

// ---------------------------------------------------------------- 1. Basic web visit

function webBasic(): Uint8Array {
  const rng = mulberry32(1)
  const tl = new Timeline(T0)
  const server: Host = { mac: gateway.mac, ip: '93.184.216.34' }
  dnsLookup(tl, 0x3b1f, 'www.example.com', 'A', [
    { type: 'CNAME', data: 'www.example.com-v4.edgesuite.net', ttl: 3600 },
    { type: 'A', data: '93.184.216.34', name: 'www.example.com-v4.edgesuite.net', ttl: 300 },
  ])
  const s = new TcpSession(tl, { client, server, cport: 51724, sport: 80, rtt: 0.024, gwMac: gateway.mac }, rng)
  s.handshake()
  const html =
    '<!doctype html>\n<html>\n<head><title>Example Domain</title></head>\n<body>\n<h1>Example Domain</h1>\n<p>This domain is for use in illustrative examples in documents.</p>\n</body>\n</html>\n'
  s.send(
    true,
    'GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/123.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n',
  )
  s.ack(false)
  s.send(
    false,
    `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ${html.length}\r\nServer: ECS (nyb/1D2A)\r\nCache-Control: max-age=604800\r\n\r\n${html}`,
    0.03,
  )
  s.ack(true)
  tl.wait(0.2)
  s.send(true, 'GET /favicon.ico HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/123.0\r\nAccept: image/*\r\n\r\n')
  s.send(false, 'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 9\r\n\r\nNot Found', 0.028)
  s.ack(true)
  tl.wait(1.5)
  s.close(true)
  return writePcap(tl.frames)
}

// ---------------------------------------------------------------- 2. HTTPS visit (PCAPNG)

function httpsVisit(): Uint8Array {
  const rng = mulberry32(2)
  const tl = new Timeline(T0 + 100)
  const server: Host = { mac: gateway.mac, ip: '104.18.32.7' }
  dnsLookup(tl, 0x8c21, 'secure.example.org', 'A', [{ type: 'A', data: '104.18.32.7', ttl: 120 }])
  dnsLookup(tl, 0x8c22, 'secure.example.org', 'AAAA', [{ type: 'AAAA', data: '2606:4700::6812:2007', ttl: 120 }])
  const s = new TcpSession(tl, { client, server, cport: 49822, sport: 443, rtt: 0.018, gwMac: gateway.mac }, rng)
  s.handshake()
  s.send(true, tlsClientHello('secure.example.org', rng))
  s.ack(false)
  // ServerHello + ChangeCipherSpec, then encrypted handshake (EncryptedExtensions, Certificate, …) as app data.
  const sh = tlsServerHello(rng, 0x1301, true)
  const enc1 = tlsAppData(2400, rng)
  const both = new Uint8Array(sh.length + enc1.length)
  both.set(sh)
  both.set(enc1, sh.length)
  s.send(false, both, 0.02)
  s.ack(true)
  const fin = new Uint8Array([...tlsChangeCipherSpec(), ...tlsAppData(53, rng)])
  s.send(true, fin)
  s.send(true, tlsAppData(420, rng))
  s.ack(false)
  s.send(false, tlsAppData(1200, rng), 0.04)
  s.send(false, tlsAppData(3800, rng))
  s.ack(true)
  tl.wait(2)
  s.send(true, tlsAlert(1, 0))
  s.close(true)
  return writePcapng(tl.frames, [{ linkType: 1, name: 'wlan0', tsresol: 6 }])
}

// ---------------------------------------------------------------- 3. DHCP DORA + ARP

function dhcpArp(): Uint8Array {
  const tl = new Timeline(T0 + 200)
  const newMac = '5c:e9:1e:77:88:99'
  const bcast = 'ff:ff:ff:ff:ff:ff'
  const xid = 0x5a1f33c2
  const server: Host = { mac: gateway.mac, ip: '192.168.1.1' }
  const offered = '192.168.1.57'
  const zero = '0.0.0.0'
  const broadcastIp = '255.255.255.255'
  const common: [number, number[]][] = [
    [54, ipOpt(server.ip)],
    [51, u32Opt(86400)],
    [1, ipOpt('255.255.255.0')],
    [3, ipOpt(gateway.ip)],
    [6, [...ipOpt('192.168.1.1'), ...ipOpt('1.1.1.1')]],
  ]
  const v4 = (src: string, dst: string, payload: Uint8Array, ttl = 64) => ipv4(src, dst, 17, payload, { ttl, df: false })
  tl.push(ethernet(newMac, bcast, 0x0800, v4(zero, broadcastIp, udp(68, 67, dhcp(1, 1, xid, newMac, { options: [[12, strOpt('lab-laptop')], [55, [1, 3, 6, 15, 51]]] })))), 0.001)
  tl.push(ethernet(server.mac, bcast, 0x0800, v4(server.ip, broadcastIp, udp(67, 68, dhcp(2, 2, xid, newMac, { yiaddr: offered, siaddr: server.ip, options: common })))), 0.35)
  tl.push(ethernet(newMac, bcast, 0x0800, v4(zero, broadcastIp, udp(68, 67, dhcp(1, 3, xid, newMac, { options: [[50, ipOpt(offered)], [54, ipOpt(server.ip)], [12, strOpt('lab-laptop')]] })))), 0.004)
  tl.push(ethernet(server.mac, bcast, 0x0800, v4(server.ip, broadcastIp, udp(67, 68, dhcp(2, 5, xid, newMac, { yiaddr: offered, siaddr: server.ip, options: common })))), 0.21)
  // Gratuitous ARP announcing the new address, then resolving the gateway.
  tl.push(ethernet(newMac, bcast, 0x0806, arp(1, newMac, offered, '00:00:00:00:00:00', offered)), 0.05)
  tl.push(ethernet(newMac, bcast, 0x0806, arp(1, newMac, offered, '00:00:00:00:00:00', gateway.ip)), 0.4)
  tl.push(ethernet(gateway.mac, newMac, 0x0806, arp(2, gateway.mac, gateway.ip, newMac, offered)), 0.002)
  const me: Host = { mac: newMac, ip: offered }
  for (let i = 1; i <= 2; i++) {
    tl.ip(me, gateway, 1, icmpEcho(true, 0x0021, i), i === 1 ? 0.01 : 1.0)
    tl.ip(gateway, me, 1, icmpEcho(false, 0x0021, i), 0.0011)
  }
  return writePcap(tl.frames)
}

// ---------------------------------------------------------------- 4. FTP login with cleartext credentials

function ftpLogin(): Uint8Array {
  const rng = mulberry32(4)
  const tl = new Timeline(T0 + 300)
  const server: Host = { mac: '08:00:27:aa:bb:cc', ip: '192.168.1.40' }
  const s = new TcpSession(tl, { client, server, cport: 50110, sport: 21, rtt: 0.004 }, rng)
  s.handshake()
  s.send(false, '220 (vsFTPd 3.0.5) Welcome to the lab file server\r\n', 0.01)
  s.ack(true)
  const step = (req: string, resp: string, think = 1.2) => {
    tl.wait(think)
    s.send(true, req)
    s.send(false, resp, 0.004)
    s.ack(true)
  }
  step('USER alice\r\n', '331 Please specify the password.\r\n')
  step('PASS summer2023\r\n', '530 Login incorrect.\r\n')
  step('USER alice\r\n', '331 Please specify the password.\r\n', 2)
  step('PASS S3cretP@ss!\r\n', '230 Login successful.\r\n')
  step('SYST\r\n', '215 UNIX Type: L8\r\n', 0.2)
  step('PWD\r\n', '257 "/home/alice" is the current directory\r\n', 0.3)
  step('QUIT\r\n', '221 Goodbye.\r\n', 3)
  s.close(false)
  return writePcap(tl.frames)
}

// ---------------------------------------------------------------- 5. Nmap-style SYN scan

function synScan(): Uint8Array {
  const rng = mulberry32(5)
  const tl = new Timeline(T0 + 400)
  const scanner: Host = { mac: '02:42:ac:11:00:66', ip: '10.0.0.66' }
  const target: Host = { mac: '02:42:ac:11:00:0a', ip: '10.0.0.10' }
  const ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 1025, 554, 199, 587, 113, 256, 5432, 6379, 27017]
  const open = new Set([22, 80, 443])
  const sport = 40613
  // Shuffle like nmap does.
  const order = [...ports].sort(() => rng() - 0.5)
  let id = 0x6a10
  for (const p of order) {
    const seq = Math.floor(rng() * 0xffffffff) >>> 0
    tl.ip(scanner, target, 6, tcp(sport, p, seq, 0, { syn: true }, undefined, { window: 1024, mss: 1460 }), 0.0009 + rng() * 0.002, { ttl: 43, id: id++, df: false })
    if (open.has(p)) {
      const sseq = Math.floor(rng() * 0xffffffff) >>> 0
      tl.ip(target, scanner, 6, tcp(p, sport, sseq, seq + 1, { syn: true, ack: true }, undefined, { window: 64240, mss: 1460 }), 0.0003, { ttl: 64 })
      // Nmap never completes the handshake: it resets immediately.
      tl.ip(scanner, target, 6, tcp(sport, p, seq + 1, 0, { rst: true }, undefined, { window: 0 }), 0.0001, { ttl: 64, df: false })
    } else {
      tl.ip(target, scanner, 6, tcp(p, sport, 0, seq + 1, { rst: true, ack: true }, undefined, { window: 0 }), 0.0003, { ttl: 64 })
    }
  }
  return writePcap(tl.frames)
}

// ---------------------------------------------------------------- 6. ARP spoofing

function arpSpoof(): Uint8Array {
  const tl = new Timeline(T0 + 500)
  const victim: Host = { mac: '3c:22:fb:1a:2b:3c', ip: '192.168.1.23' }
  const gw: Host = { mac: '00:1a:2b:3c:4d:5e', ip: '192.168.1.1' }
  const attacker: Host = { mac: 'de:ad:be:ef:13:37', ip: '192.168.1.66' }
  const bcast = 'ff:ff:ff:ff:ff:ff'
  // Normal resolution first.
  tl.push(ethernet(victim.mac, bcast, 0x0806, arp(1, victim.mac, victim.ip, '00:00:00:00:00:00', gw.ip)), 0.001)
  tl.push(ethernet(gw.mac, victim.mac, 0x0806, arp(2, gw.mac, gw.ip, victim.mac, victim.ip)), 0.0015)
  const internet: Host = { mac: gw.mac, ip: '8.8.8.8' }
  tl.ip(victim, internet, 1, icmpEcho(true, 0x0042, 1), 0.01)
  tl.ip(internet, victim, 1, icmpEcho(false, 0x0042, 1), 0.021, { ttl: 117 }, victim.mac)
  // Attacker poisons both sides repeatedly with unsolicited replies.
  for (let i = 0; i < 6; i++) {
    tl.push(ethernet(attacker.mac, victim.mac, 0x0806, arp(2, attacker.mac, gw.ip, victim.mac, victim.ip)), i === 0 ? 1.2 : 1.9)
    tl.push(ethernet(attacker.mac, gw.mac, 0x0806, arp(2, attacker.mac, victim.ip, gw.mac, gw.ip)), 0.0008)
    if (i === 1 || i === 3) {
      // Victim's traffic to the Internet is now addressed to the attacker's MAC.
      const seqn = i === 1 ? 2 : 3
      tl.push(ethernet(victim.mac, attacker.mac, 0x0800, ipv4(victim.ip, internet.ip, 1, icmpEcho(true, 0x0042, seqn))), 0.3)
      tl.push(ethernet(attacker.mac, gw.mac, 0x0800, ipv4(victim.ip, internet.ip, 1, icmpEcho(true, 0x0042, seqn), { ttl: 63 })), 0.0004)
      tl.push(ethernet(gw.mac, attacker.mac, 0x0800, ipv4(internet.ip, victim.ip, 1, icmpEcho(false, 0x0042, seqn), { ttl: 117 })), 0.02)
      tl.push(ethernet(attacker.mac, victim.mac, 0x0800, ipv4(internet.ip, victim.ip, 1, icmpEcho(false, 0x0042, seqn), { ttl: 116 })), 0.0004)
    }
  }
  return writePcap(tl.frames)
}

// ---------------------------------------------------------------- 7. DNS tunneling

function dnsTunnel(): Uint8Array {
  const rng = mulberry32(7)
  const tl = new Timeline(T0 + 600)
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
  const chunk = (n: number) => Array.from({ length: n }, () => alphabet[Math.floor(rng() * 32)]).join('')
  // Some normal lookups first.
  dnsLookup(tl, 0x1101, 'www.wikipedia.org', 'A', [{ type: 'A', data: '208.80.154.224' }])
  dnsLookup(tl, 0x1102, 'update.microsoft.com', 'A', [{ type: 'A', data: '20.72.235.82' }])
  dnsLookup(tl, 0x1103, 'nonexistent-intranet.corp', 'A', [], 3)
  for (let i = 0; i < 24; i++) {
    const name = `${chunk(52)}.${chunk(30)}.s${i}.x9.tunnelcdn.net`
    const reply = btoaSafe(chunk(60))
    dnsLookup(tl, 0x4000 + i, name, 'TXT', [{ type: 'TXT', data: reply, ttl: 0 }], 0, 40000 + i)
    tl.wait(0.15 + rng() * 0.1)
  }
  dnsLookup(tl, 0x1104, 'www.google.com', 'A', [{ type: 'A', data: '142.250.72.196' }])
  return writePcap(tl.frames)
}

const btoaSafe = (s: string) => btoa(s)

// ---------------------------------------------------------------- 8. SYN flood

function synFlood(): Uint8Array {
  const rng = mulberry32(8)
  const tl = new Timeline(T0 + 700)
  const server: Host = { mac: '00:50:56:9a:10:80', ip: '10.0.0.80' }
  const router = '00:50:56:9a:00:01'
  // One legitimate client connects successfully before the flood.
  const legit: Host = { mac: router, ip: '198.51.100.20' }
  const s = new TcpSession(tl, { client: legit, server, cport: 52001, sport: 80, rtt: 0.03 }, rng)
  s.handshake()
  s.send(true, 'GET / HTTP/1.1\r\nHost: shop.example.net\r\n\r\n')
  s.send(false, 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok', 0.01)
  s.ack(true)
  s.close(true)
  tl.wait(0.8)
  for (let i = 0; i < 120; i++) {
    const src = `${[45, 91, 103, 185, 203][Math.floor(rng() * 5)]}.${Math.floor(rng() * 254) + 1}.${Math.floor(rng() * 254) + 1}.${Math.floor(rng() * 254) + 1}`
    const sport = 1024 + Math.floor(rng() * 60000)
    const seq = Math.floor(rng() * 0xffffffff) >>> 0
    tl.push(ethernet(router, server.mac, 0x0800, ipv4(src, server.ip, 6, tcp(sport, 80, seq, 0, { syn: true }, undefined, { window: 512 }), { ttl: 240 + Math.floor(rng() * 15), df: false, id: Math.floor(rng() * 65535) })), 0.0004 + rng() * 0.0008)
    if (i % 3 === 0) {
      const sseq = Math.floor(rng() * 0xffffffff) >>> 0
      tl.push(ethernet(server.mac, router, 0x0800, ipv4(server.ip, src, 6, tcp(80, sport, sseq, seq + 1, { syn: true, ack: true }, undefined, { mss: 1460 }))), 0.0002)
    }
  }
  return writePcap(tl.frames)
}

export const SAMPLES: SampleCapture[] = [
  { id: 'web-basic', title: 'Basic web visit', difficulty: 'Recruit', learn: 'DNS lookup → TCP handshake → HTTP GET/200 → FIN teardown, end to end.', fileName: '01-web-basic.pcap', build: webBasic },
  { id: 'https-visit', title: 'HTTPS visit', difficulty: 'Recruit', learn: 'How TLS hides the page but still leaks the site name (SNI) in the ClientHello.', fileName: '02-https-visit.pcapng', build: httpsVisit },
  { id: 'dhcp-arp', title: 'DHCP DORA + ARP', difficulty: 'Recruit', learn: 'How a brand-new laptop gets an IP address and finds its gateway.', fileName: '03-dhcp-arp.pcap', build: dhcpArp },
  { id: 'ftp-login', title: 'FTP login (cleartext)', difficulty: 'Analyst', learn: 'Why FTP is dangerous: the username and password cross the wire in plain text.', fileName: '04-ftp-login.pcap', build: ftpLogin },
  { id: 'syn-scan', title: 'Nmap SYN scan', difficulty: 'Analyst', learn: 'Recognise a port scan: many SYNs, RST/ACK from closed ports, SYN/ACK from open ones.', fileName: '05-syn-scan.pcap', build: synScan },
  { id: 'arp-spoof', title: 'ARP spoofing', difficulty: 'Hunter', learn: 'Spot two MAC addresses claiming the gateway IP — a man-in-the-middle in progress.', fileName: '06-arp-spoof.pcap', build: arpSpoof },
  { id: 'dns-tunnel', title: 'DNS tunneling', difficulty: 'Hunter', learn: 'Long, random subdomains and TXT lookups that smuggle data out through DNS.', fileName: '07-dns-tunnel.pcap', build: dnsTunnel },
  { id: 'syn-flood', title: 'SYN flood', difficulty: 'Hunter', learn: 'A denial-of-service that fills the server with half-open connections from spoofed IPs.', fileName: '08-syn-flood.pcap', build: synFlood },
]

export function getSample(id: string): SampleCapture | undefined {
  return SAMPLES.find((s) => s.id === id)
}

