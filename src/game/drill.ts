// Keystroke drill: a typing-tutor stream of terms, field names and values drawn from the capture.

import type { CaptureIndex } from '../core/types'
import { FIELDS } from '../core/filter/filter'
import { Kb } from './knowledge'
import { shuffle } from './options'

const CORE_TERMS = [
  'SYN', 'SYN-ACK', 'ACK', 'FIN', 'RST', 'handshake', 'NXDOMAIN', 'TTL', 'MSS', 'SNI',
  'ClientHello', 'ServerHello', 'cipher', 'DORA', 'broadcast', 'ARP', 'MAC', 'UDP', 'TCP',
  'ICMP', 'payload', 'checksum', 'port', 'socket', 'resolver', 'cleartext', 'exfiltration',
]

export interface DrillWord {
  text: string
  /** Where the word came from, shown as a faint tag. */
  tag: 'term' | 'field' | 'value' | 'filter'
}

/** Builds a varied word list: capture values (IPs, names, ports), filter fields present, and core terms. */
export function buildDrillWords(index: CaptureIndex, rng: () => number, count = 80): DrillWord[] {
  const kb = new Kb(index)
  const values = new Set<string>()
  const terms = new Set<string>(CORE_TERMS)
  const fields = new Set<string>()
  for (const p of index.packets.slice(0, 400)) {
    if (p.facts.ip) values.add(p.facts.ip.src).add(p.facts.ip.dst)
    if (p.facts.dns?.qname && p.facts.dns.qname.length <= 24) values.add(p.facts.dns.qname)
    if (p.facts.tcp) values.add(String(p.facts.tcp.dstPort))
    if (p.facts.http?.method) values.add(p.facts.http.method)
    if (p.facts.tls?.sni) values.add(p.facts.tls.sni)
    // Drill words are typed as single tokens, so multi-word labels are joined with '-'.
    const label = kb.label(p).replace(/\s+/g, '-')
    if (label.length <= 16 && !/…/.test(label)) terms.add(label)
  }
  for (const k of Object.keys(FIELDS)) {
    if (!k.includes('.')) continue
    const proto = k.split('.')[0]
    if (index.packets.some((p) => p.facts.protos.includes(proto === 'ip' ? 'ip' : proto))) fields.add(k)
  }
  const fits = (w: string) => w.length <= 24 && !/\s/.test(w)
  const pool: DrillWord[] = [
    ...[...terms].filter(fits).map((text) => ({ text, tag: 'term' as const })),
    ...[...values].filter(fits).map((text) => ({ text, tag: 'value' as const })),
    ...[...fields].filter(fits).map((text) => ({ text, tag: 'field' as const })),
    { text: 'tcp.flags.syn==1', tag: 'filter' },
    { text: 'dns&&udp', tag: 'filter' },
    { text: '!arp', tag: 'filter' },
  ]
  const out: DrillWord[] = []
  while (out.length < count) out.push(...shuffle(pool, rng))
  return out.slice(0, count)
}

export interface DrillStats {
  wpm: number
  accuracy: number
  words: number
  errors: number
}

/** Standard typing metrics: WPM counts correctly typed characters / 5 per minute. */
export function drillStats(correctChars: number, typedChars: number, words: number, seconds: number): DrillStats {
  const minutes = Math.max(seconds, 1) / 60
  return {
    wpm: Math.round(correctChars / 5 / minutes),
    accuracy: typedChars ? correctChars / typedChars : 0,
    words,
    errors: typedChars - correctChars,
  }
}

export function drillXp(s: DrillStats): number {
  return Math.min(120, Math.round(s.wpm * s.accuracy * s.accuracy * 0.8))
}
