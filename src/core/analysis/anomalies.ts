// Heuristic detectors for "Spot the Anomaly". Each detector only fires when the evidence is clear,
// so the game never asks about an anomaly that isn't really in the capture.

import { entropy } from '../bytes'
import type { Anomaly, Conversation, PacketSummary } from '../types'

export const SUSPICIOUS_PORTS: Record<number, string> = {
  4444: 'Metasploit default handler',
  1337: 'common backdoor/"leet" port',
  31337: 'Back Orifice / "eleet" backdoor',
  6667: 'IRC (classic botnet C2)',
  6666: 'IRC (classic botnet C2)',
  12345: 'NetBus trojan',
  5555: 'Android debug bridge / common RAT port',
  9001: 'Tor relay default',
}

export function detectAnomalies(packets: PacketSummary[], convs: Conversation[]): Anomaly[] {
  const out: Anomaly[] = []
  const push = (a: Anomaly | null) => a && out.push(a)
  push(detectPortScan(packets))
  push(detectSynFlood(packets, convs))
  push(detectArpSpoof(packets))
  push(detectCleartextCreds(packets))
  push(detectDnsTunnel(packets))
  push(detectFailedLogins(packets))
  push(detectRstStorm(packets))
  push(detectUnusualPorts(convs))
  return out
}

function detectPortScan(packets: PacketSummary[]): Anomaly | null {
  // Pure SYNs from one source to one target across many distinct destination ports.
  const bySrcDst = new Map<string, { ports: Set<number>; frames: number[] }>()
  for (const p of packets) {
    const t = p.facts.tcp
    if (!t || !p.facts.ip || !t.flags.syn || t.flags.ack) continue
    const k = `${p.facts.ip.src}>${p.facts.ip.dst}`
    let e = bySrcDst.get(k)
    if (!e) bySrcDst.set(k, (e = { ports: new Set(), frames: [] }))
    e.ports.add(t.dstPort)
    e.frames.push(p.no)
  }
  let best: [string, { ports: Set<number>; frames: number[] }] | null = null
  for (const e of bySrcDst) if (!best || e[1].ports.size > best[1].ports.size) best = e
  if (!best || best[1].ports.size < 15) return null
  const [src, dst] = best[0].split('>')
  // Count closed-port replies.
  let rsts = 0
  const open = new Set<number>()
  for (const p of packets) {
    const t = p.facts.tcp
    if (!t || p.facts.ip?.src !== dst || p.facts.ip?.dst !== src) continue
    if (t.flags.rst) rsts++
    if (t.flags.syn && t.flags.ack) open.add(t.srcPort)
  }
  return {
    kind: 'port-scan',
    title: 'TCP SYN port scan',
    detail: `${src} sent SYNs to ${best[1].ports.size} different ports on ${dst}; ${rsts} were answered with RST (closed) and ${open.size} with SYN-ACK (open).`,
    packets: best[1].frames.slice(0, 20),
    severity: 'medium',
    evidence: { scanner: src, target: dst, ports: best[1].ports.size, rsts, openPorts: [...open].sort((a, b) => a - b).join(', ') || 'none' },
  }
}

function detectSynFlood(packets: PacketSummary[], convs: Conversation[]): Anomaly | null {
  // Many half-open connections to one service from many distinct sources.
  const byTarget = new Map<string, { srcs: Set<string>; syns: number; frames: number[] }>()
  for (const p of packets) {
    const t = p.facts.tcp
    if (!t || !p.facts.ip || !t.flags.syn || t.flags.ack) continue
    const k = `${p.facts.ip.dst}:${t.dstPort}`
    let e = byTarget.get(k)
    if (!e) byTarget.set(k, (e = { srcs: new Set(), syns: 0, frames: [] }))
    e.srcs.add(p.facts.ip.src)
    e.syns++
    e.frames.push(p.no)
  }
  let best: [string, { srcs: Set<string>; syns: number; frames: number[] }] | null = null
  for (const e of byTarget) if (!best || e[1].syns > best[1].syns) best = e
  if (!best || best[1].syns < 40 || best[1].srcs.size < 10) return null
  const [host, port] = [best[0].slice(0, best[0].lastIndexOf(':')), Number(best[0].slice(best[0].lastIndexOf(':') + 1))]
  const related = convs.filter((c) => c.proto === 'TCP' && c.b.addr === host && c.b.port === port)
  const completed = related.filter((c) => c.handshake?.ack !== undefined).length
  if (completed / Math.max(1, related.length) > 0.2) return null
  return {
    kind: 'syn-flood',
    title: 'SYN flood (half-open connections)',
    detail: `${best[1].syns} SYNs hit ${host}:${port} from ${best[1].srcs.size} different source addresses, but only ${completed} of ${related.length} connections finished the handshake.`,
    packets: best[1].frames.slice(0, 20),
    severity: 'high',
    evidence: { target: `${host}:${port}`, syns: best[1].syns, sources: best[1].srcs.size, completed },
  }
}

function detectArpSpoof(packets: PacketSummary[]): Anomaly | null {
  const seen = new Map<string, { mac: string; frame: number }>()
  for (const p of packets) {
    const a = p.facts.arp
    if (!a || a.senderIp === '0.0.0.0') continue
    const prev = seen.get(a.senderIp)
    if (prev && prev.mac !== a.senderMac) {
      // Count how many times the new MAC keeps claiming the IP.
      const claims = packets.filter((q) => q.facts.arp?.senderIp === a.senderIp && q.facts.arp.senderMac === a.senderMac)
      return {
        kind: 'arp-spoof',
        title: 'ARP spoofing / cache poisoning',
        detail: `${a.senderIp} was first announced by ${prev.mac}, then claimed by ${a.senderMac} (${claims.length} ARP messages). Two MACs for one IP is the signature of a man-in-the-middle.`,
        packets: claims.map((c) => c.no).slice(0, 20),
        severity: 'high',
        evidence: { ip: a.senderIp, originalMac: prev.mac, originalFrame: prev.frame, attackerMac: a.senderMac, claims: claims.length },
      }
    }
    if (!prev) seen.set(a.senderIp, { mac: a.senderMac, frame: p.no })
  }
  return null
}

function detectCleartextCreds(packets: PacketSummary[]): Anomaly | null {
  const hits = packets.filter((p) => p.facts.creds)
  if (!hits.length) return null
  const protos = [...new Set(hits.map((p) => p.facts.creds!.proto))]
  const user = hits.find((p) => p.facts.creds!.user)?.facts.creds!.user
  return {
    kind: 'cleartext-creds',
    title: 'Credentials sent in cleartext',
    detail: `${protos.join('/')} sent a login${user ? ` for "${user}"` : ''} without encryption — anyone on the path can read it.`,
    packets: hits.map((p) => p.no).slice(0, 20),
    severity: 'high',
    evidence: { protocols: protos.join(', '), user: user ?? 'unknown', packets: hits.length },
  }
}

function baseDomain(name: string): string {
  const parts = name.split('.')
  return parts.slice(-2).join('.')
}

function detectDnsTunnel(packets: PacketSummary[]): Anomaly | null {
  const byDomain = new Map<string, { n: number; txt: number; longest: number; ent: number; frames: number[] }>()
  for (const p of packets) {
    const d = p.facts.dns
    if (!d || d.isResponse || !d.qname) continue
    const labels = d.qname.split('.')
    const sub = labels.slice(0, -2).join('')
    if (sub.length < 20) continue
    const e = entropy(sub)
    const k = baseDomain(d.qname)
    let s = byDomain.get(k)
    if (!s) byDomain.set(k, (s = { n: 0, txt: 0, longest: 0, ent: 0, frames: [] }))
    s.n++
    if (d.qtype === 'TXT' || d.qtype === 'NULL') s.txt++
    s.longest = Math.max(s.longest, d.qname.length)
    s.ent += e
    s.frames.push(p.no)
  }
  for (const [domain, s] of byDomain) {
    const avgEnt = s.ent / s.n
    if (s.n >= 8 && avgEnt > 3.5) {
      return {
        kind: 'dns-tunnel',
        title: 'Possible DNS tunneling / exfiltration',
        detail: `${s.n} queries to *.${domain} carried long, random-looking subdomains (avg entropy ${avgEnt.toFixed(1)} bits/char, longest name ${s.longest} chars); ${s.txt} asked for TXT records.`,
        packets: s.frames.slice(0, 20),
        severity: 'high',
        evidence: { domain, queries: s.n, txt: s.txt, entropy: avgEnt.toFixed(2), longest: s.longest },
      }
    }
  }
  return null
}

function detectFailedLogins(packets: PacketSummary[]): Anomaly | null {
  const fails = packets.filter((p) => {
    const a = p.facts.app
    if (!a || a.isRequest) return false
    return (
      (a.proto === 'FTP' && a.code === 530) ||
      (a.proto === 'SMTP' && a.code === 535) ||
      (a.proto === 'POP' && a.command === '-ERR') ||
      (a.proto === 'IMAP' && a.command === 'NO') ||
      (a.proto === 'Telnet' && /login incorrect/i.test(a.line))
    )
  })
  const http401 = packets.filter((p) => p.facts.http?.status === 401)
  const all = [...fails, ...http401]
  if (all.length < 3) return null
  const proto = fails[0]?.facts.app?.proto ?? 'HTTP'
  return {
    kind: 'failed-logins',
    title: 'Repeated failed logins (brute force?)',
    detail: `${all.length} authentication failures (${proto}) in ${(all[all.length - 1].relTime - all[0].relTime).toFixed(1)} s — consistent with password guessing.`,
    packets: all.map((p) => p.no).slice(0, 20),
    severity: 'medium',
    evidence: { failures: all.length, protocol: proto },
  }
}

function detectRstStorm(packets: PacketSummary[]): Anomaly | null {
  let tcp = 0
  const rsts: number[] = []
  for (const p of packets) {
    if (!p.facts.tcp) continue
    tcp++
    if (p.facts.tcp.flags.rst) rsts.push(p.no)
  }
  if (rsts.length < 20 || rsts.length / tcp < 0.3) return null
  return {
    kind: 'rst-storm',
    title: 'Large number of TCP resets',
    detail: `${rsts.length} of ${tcp} TCP packets (${Math.round((rsts.length / tcp) * 100)}%) are RSTs — connections are being refused or torn down abnormally.`,
    packets: rsts.slice(0, 20),
    severity: 'low',
    evidence: { rsts: rsts.length, tcp },
  }
}

function detectUnusualPorts(convs: Conversation[]): Anomaly | null {
  for (const c of convs) {
    if (c.proto !== 'TCP' || c.b.port === undefined) continue
    const why = SUSPICIOUS_PORTS[c.b.port]
    // Only count connections that actually carried data or completed a handshake.
    if (why && c.handshake?.ack !== undefined) {
      return {
        kind: 'unusual-port',
        title: `Connection to suspicious port ${c.b.port}`,
        detail: `${c.a.addr} opened a TCP session to ${c.b.addr}:${c.b.port} (${why}).`,
        packets: c.packets.slice(0, 20),
        severity: 'medium',
        evidence: { client: c.a.addr, server: c.b.addr, port: c.b.port, reason: why },
      }
    }
  }
  // Well-known cleartext protocols running on a non-standard port.
  for (const c of convs) {
    if (c.proto !== 'TCP' || c.b.port === undefined) continue
    if (c.app === 'HTTP' && ![80, 8080, 8000, 8008].includes(c.b.port) && c.b.port > 1024 && c.handshake?.ack) {
      return {
        kind: 'unusual-port',
        title: `HTTP on non-standard port ${c.b.port}`,
        detail: `${c.a.addr} spoke HTTP to ${c.b.addr} on port ${c.b.port}. Services on odd ports can be shadow IT or malware C2.`,
        packets: c.packets.slice(0, 20),
        severity: 'low',
        evidence: { client: c.a.addr, server: c.b.addr, port: c.b.port, reason: 'HTTP on a non-standard port' },
      }
    }
  }
  return null
}

/**
 * Telnet sends credentials one keystroke at a time, so they can't be spotted in a single packet.
 * This walks each Telnet stream, finds the login/password prompts, and tags the keystroke packets.
 */
export function detectTelnetCreds(packets: PacketSummary[], convs: Conversation[]): void {
  for (const c of convs) {
    if (c.app !== 'Telnet') continue
    let state: 'idle' | 'user' | 'pass' = 'idle'
    let user = ''
    let pass = ''
    let userFrames: number[] = []
    let passFrames: number[] = []
    for (const no of c.packets) {
      const p = packets[no - 1]
      const a = p.facts.app
      if (!a || a.proto !== 'Telnet' || !a.line) continue
      const fromServer = p.facts.tcp?.srcPort === 23
      if (fromServer) {
        if (/login:\s*$/i.test(a.line)) {
          state = 'user'
          user = ''
        }
        else if (/password:\s*$/i.test(a.line)) state = 'pass'
        continue
      }
      if (state === 'idle') continue
      const done = /[\r\n]/.test(a.line)
      const chars = a.line.replace(/[\r\n\0]/g, '')
      if (state === 'user') {
        user += chars
        userFrames.push(no)
      } else {
        pass += chars
        passFrames.push(no)
      }
      if (done) {
        const frames = state === 'user' ? userFrames : passFrames
        for (const f of frames) {
          const pk = packets[f - 1]
          pk.facts.creds =
            state === 'user' ? { proto: 'Telnet', kind: 'user', user } : { proto: 'Telnet', kind: 'pass', user, secret: pass }
          pk.color = 'cleartext'
        }
        userFrames = []
        passFrames = []
        pass = ''
        state = 'idle'
      }
    }
  }
}
