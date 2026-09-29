// Builds the CaptureIndex: container parse → per-frame dissection (summaries only) → conversations → analysis.

import { detectAnomalies, detectTelnetCreds } from '../analysis/anomalies'
import { dissectFrame } from '../dissect'
import { flowKey } from '../dissect/tree'
import { parseContainer } from '../pcap/container'
import type { CaptureIndex, Conversation, PacketSummary, RawRecord } from '../types'
import { buildConversations } from './conversations'

export type IndexPhase = 'reading' | 'dissecting' | 'analyzing'
export type IndexProgress = (phase: IndexPhase, fraction: number, packets: number) => void

export function buildIndex(buf: Uint8Array, fileName: string, onProgress?: IndexProgress): CaptureIndex {
  const container = parseContainer(buf, (f) => onProgress?.('reading', f, 0))
  const { records } = container
  if (!records.length) {
    const why = container.warnings.length ? ` (${container.warnings[0]})` : ''
    throw new Error(`The capture contains no packets${why}.`)
  }
  const t0 = records[0].ts
  const tcpIsn = new Map<string, number>()
  const packets: PacketSummary[] = new Array(records.length)
  const step = Math.max(1, Math.floor(records.length / 50))
  for (let i = 0; i < records.length; i++) {
    packets[i] = summarize(buf, records[i], i + 1, t0, tcpIsn)
    if (onProgress && i % step === 0) onProgress('dissecting', i / records.length, i)
  }
  onProgress?.('analyzing', 1, records.length)
  const conversations = buildConversations(packets)
  detectTelnetCreds(packets, conversations)
  labelTlsVersions(packets, conversations)
  const anomalies = detectAnomalies(packets, conversations)
  const last = packets[packets.length - 1]
  return {
    fileName,
    format: container.format,
    linkTypes: container.linkTypes,
    packets,
    conversations,
    anomalies,
    warnings: container.warnings,
    totalBytes: buf.length,
    duration: last.relTime,
  }
}

export function frameBytes(buf: Uint8Array, rec: { dataOffset: number; capLen: number }): Uint8Array {
  return buf.subarray(rec.dataOffset, rec.dataOffset + rec.capLen)
}

function summarize(buf: Uint8Array, rec: RawRecord, no: number, t0: number, tcpIsn: Map<string, number>): PacketSummary {
  const bytes = frameBytes(buf, rec)
  const meta = { no, ts: rec.ts, relTime: rec.ts - t0, origLen: rec.origLen, linkType: rec.linkType, interfaceId: rec.interfaceId }
  let d = dissectFrame(bytes, meta, { tcpIsn })
  const t = d.facts.tcp
  const ip = d.facts.ip
  if (t && ip) {
    // First segment seen in a direction defines the base for relative sequence numbers.
    const k = flowKey(ip.src, t.srcPort, ip.dst, t.dstPort)
    if (!tcpIsn.has(k)) {
      tcpIsn.set(k, t.seq)
      d = dissectFrame(bytes, meta, { tcpIsn })
    }
  }
  return {
    no,
    ts: rec.ts,
    relTime: rec.ts - t0,
    capLen: rec.capLen,
    origLen: rec.origLen,
    linkType: rec.linkType,
    dataOffset: rec.dataOffset,
    src: d.src,
    dst: d.dst === 'ff:ff:ff:ff:ff:ff' ? 'Broadcast' : d.dst,
    protocol: d.protocol,
    info: d.info,
    color: d.color,
    facts: d.facts,
    streamId: -1,
  }
}

/** Once a ServerHello negotiates a version, label the whole conversation with it (as Wireshark does). */
function labelTlsVersions(packets: PacketSummary[], convs: Conversation[]): void {
  for (const c of convs) {
    if (c.app !== 'TLS') continue
    const sh = c.packets.map((n) => packets[n - 1]).find((p) => p.facts.tls?.handshakeTypes.includes('Server Hello'))
    if (!sh) continue
    const label = sh.protocol
    for (const n of c.packets) {
      const p = packets[n - 1]
      if (p.facts.tls && p.protocol.startsWith('TLS')) p.protocol = label
    }
  }
}

/** Rebuilds the ISN map from summaries so on-demand dissection shows the same relative numbers. */
export function isnMapFromSummaries(packets: PacketSummary[]): Map<string, number> {
  const m = new Map<string, number>()
  for (const p of packets) {
    const t = p.facts.tcp
    const ip = p.facts.ip
    if (!t || !ip) continue
    const k = flowKey(ip.src, t.srcPort, ip.dst, t.dstPort)
    if (!m.has(k)) m.set(k, t.seq)
  }
  return m
}
