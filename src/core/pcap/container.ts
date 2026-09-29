// Classic PCAP and PCAPNG container parsing. Produces raw frame records that point into the
// original buffer; dissection happens separately.

import type { LinkType, RawRecord } from '../types'

export class CaptureFormatError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CaptureFormatError'
  }
}

export interface ContainerResult {
  format: 'pcap' | 'pcapng'
  records: RawRecord[]
  linkTypes: LinkType[]
  warnings: string[]
}

export const SUPPORTED_LINK_TYPES: Record<number, string> = {
  0: 'BSD loopback (Null)',
  1: 'Ethernet',
  101: 'Raw IP',
  113: 'Linux cooked (SLL)',
  228: 'Raw IPv4',
  229: 'Raw IPv6',
  276: 'Linux cooked v2 (SLL2)',
}

type ProgressFn = (fraction: number) => void

export function parseContainer(buf: ArrayBuffer | Uint8Array, onProgress?: ProgressFn): ContainerResult {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  if (bytes.length < 4) throw new CaptureFormatError('The file is too small to be a packet capture.')
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const magicBE = view.getUint32(0, false)
  if (magicBE === 0x0a0d0d0a) return parsePcapng(bytes, view, onProgress)
  return parsePcap(bytes, view, onProgress)
}

function parsePcap(bytes: Uint8Array, view: DataView, onProgress?: ProgressFn): ContainerResult {
  const m = view.getUint32(0, false)
  let le: boolean
  let nanos = false
  let recHdrLen = 16
  switch (m) {
    case 0xa1b2c3d4:
      le = false
      break
    case 0xd4c3b2a1:
      le = true
      break
    case 0xa1b23c4d:
      le = false
      nanos = true
      break
    case 0x4d3cb2a1:
      le = true
      nanos = true
      break
    case 0xa1b2cd34:
      le = false
      recHdrLen = 24
      break
    case 0x34cdb2a1:
      le = true
      recHdrLen = 24
      break
    default:
      throw new CaptureFormatError(
        `Unrecognized file signature 0x${m.toString(16).padStart(8, '0')}. This doesn't look like a PCAP or PCAPNG file.`,
      )
  }
  // Check the signature first so random files get "not a capture" rather than "truncated".
  if (bytes.length < 24) throw new CaptureFormatError('The PCAP global header is truncated (needs 24 bytes).')
  const linkType = view.getUint32(20, le) & 0x0fffffff
  const warnings: string[] = []
  if (!(linkType in SUPPORTED_LINK_TYPES)) {
    warnings.push(`Link type ${linkType} isn't supported; frames will be shown as raw data.`)
  }
  const records: RawRecord[] = []
  let o = 24
  const divisor = nanos ? 1e9 : 1e6
  let lastReport = 0
  while (o < bytes.length) {
    if (o + recHdrLen > bytes.length) {
      warnings.push(`File ends in the middle of a packet header after ${records.length} packets (truncated capture).`)
      break
    }
    const sec = view.getUint32(o, le)
    const frac = view.getUint32(o + 4, le)
    const capLen = view.getUint32(o + 8, le)
    const origLen = view.getUint32(o + 12, le)
    if (capLen > 0x4000000) {
      const msg = `Packet ${records.length + 1} claims a length of ${capLen} bytes, which is impossible — the file is likely corrupt.`
      // Keep what was readable before the corruption, as for truncation.
      if (!records.length) throw new CaptureFormatError(msg)
      warnings.push(`${msg} Stopped there.`)
      break
    }
    const dataOffset = o + recHdrLen
    if (dataOffset + capLen > bytes.length) {
      warnings.push(`Packet ${records.length + 1} is cut off (truncated capture); stopped there.`)
      break
    }
    records.push({ ts: sec + frac / divisor, linkType, dataOffset, capLen, origLen, interfaceId: 0 })
    o = dataOffset + capLen
    if (onProgress && o - lastReport > 1 << 20) {
      lastReport = o
      onProgress(o / bytes.length)
    }
  }
  return { format: 'pcap', records, linkTypes: [linkType], warnings }
}

interface Iface {
  linkType: number
  /** Timestamp units per second. */
  unitsPerSec: number
  tsOffset: number
}

function parsePcapng(bytes: Uint8Array, view: DataView, onProgress?: ProgressFn): ContainerResult {
  const records: RawRecord[] = []
  const warnings: string[] = []
  const linkTypes = new Set<number>()
  let ifaces: Iface[] = []
  let le = true
  let o = 0
  let lastReport = 0
  let sawSection = false

  while (o < bytes.length) {
    if (o + 12 > bytes.length) {
      warnings.push('File ends in the middle of a block header (truncated capture).')
      break
    }
    const typeBE = view.getUint32(o, false)
    if (typeBE === 0x0a0d0d0a) {
      // Section Header Block: byte-order magic decides endianness for the whole section.
      if (o + 28 > bytes.length) {
        if (!records.length) throw new CaptureFormatError('The PCAPNG section header is truncated.')
        warnings.push('A later section header is truncated; stopped there.')
        break
      }
      const bom = view.getUint32(o + 8, false)
      if (bom === 0x1a2b3c4d) le = false
      else if (bom === 0x4d3c2b1a) le = true
      else throw new CaptureFormatError('Bad PCAPNG byte-order magic; the file is likely corrupt.')
      ifaces = []
      sawSection = true
    } else if (!sawSection) {
      throw new CaptureFormatError('PCAPNG file does not start with a Section Header Block.')
    }
    const type = view.getUint32(o, le)
    const blockLen = view.getUint32(o + 4, le)
    if (blockLen < 12 || blockLen % 4 !== 0) {
      throw new CaptureFormatError(`Invalid PCAPNG block length ${blockLen} at offset ${o}; the file is likely corrupt.`)
    }
    if (o + blockLen > bytes.length) {
      warnings.push(`Last block is cut off after ${records.length} packets (truncated capture).`)
      break
    }
    const body = o + 8
    const bodyEnd = o + blockLen - 4
    // Minimum block sizes (header 8 + fixed fields + trailer 4); smaller blocks would read past their end.
    const MIN: Record<number, number> = { 1: 20, 2: 32, 3: 16, 6: 32 }
    if (MIN[type] && blockLen < MIN[type]) {
      warnings.push(`Block at offset ${o} is too short for its type (${blockLen} bytes); skipped.`)
      o += blockLen
      continue
    }

    try {
      switch (type) {
        case 0x0a0d0d0a:
          break
        case 0x00000001: {
          // Interface Description Block
          const linkType = view.getUint16(body, le)
          const iface: Iface = { linkType, unitsPerSec: 1e6, tsOffset: 0 }
          let p = body + 8
          while (p + 4 <= bodyEnd) {
            const code = view.getUint16(p, le)
            const len = view.getUint16(p + 2, le)
            if (code === 0) break
            if (code === 9 && len >= 1) {
              const r = bytes[p + 4]
              iface.unitsPerSec = r & 0x80 ? 2 ** (r & 0x7f) : 10 ** (r & 0x7f)
            } else if (code === 14 && len >= 8 && p + 12 <= bodyEnd) {
              const hi = view.getUint32(p + 4, le)
              const lo = view.getUint32(p + 8, le)
              iface.tsOffset = le ? lo * 4294967296 + hi : hi * 4294967296 + lo
            }
            p += 4 + ((len + 3) & ~3)
          }
          ifaces.push(iface)
          linkTypes.add(linkType)
          if (!(linkType in SUPPORTED_LINK_TYPES)) {
            warnings.push(`Interface ${ifaces.length - 1} uses unsupported link type ${linkType}; its frames show as raw data.`)
          }
          break
        }
        case 0x00000006:
        case 0x00000002: {
          // Enhanced Packet Block (6) / obsolete Packet Block (2)
          const enhanced = type === 6
          const ifId = enhanced ? view.getUint32(body, le) : view.getUint16(body, le)
          const tsHi = view.getUint32(body + 4, le)
          const tsLo = view.getUint32(body + 8, le)
          const capLen = view.getUint32(body + 12, le)
          const origLen = view.getUint32(body + 16, le)
          const dataOffset = body + 20
          const iface = ifaces[ifId]
          if (!iface) {
            warnings.push(`Packet references unknown interface ${ifId}; skipped.`)
            break
          }
          if (dataOffset + capLen > bodyEnd) {
            warnings.push(`Packet ${records.length + 1} has an inconsistent length; skipped.`)
            break
          }
          const units = tsHi * 4294967296 + tsLo
          records.push({
            ts: units / iface.unitsPerSec + iface.tsOffset,
            linkType: iface.linkType,
            dataOffset,
            capLen,
            origLen,
            interfaceId: ifId,
          })
          break
        }
        case 0x00000003: {
          // Simple Packet Block: always interface 0, no timestamp.
          const iface = ifaces[0]
          if (!iface) {
            warnings.push('Simple Packet Block before any interface; skipped.')
            break
          }
          const origLen = view.getUint32(body, le)
          const capLen = Math.max(0, Math.min(origLen, bodyEnd - (body + 4)))
          records.push({
            // SPBs carry no timestamp; filled in from neighbouring packets after the loop.
            ts: NaN,
            linkType: iface.linkType,
            dataOffset: body + 4,
            capLen,
            origLen,
            interfaceId: 0,
          })
          break
        }
        default:
          // Name resolution, statistics, custom and decryption-secrets blocks are ignored.
          break
      }
    } catch (e) {
      if (!(e instanceof RangeError)) throw e
      if (!records.length) throw new CaptureFormatError(`Corrupt PCAPNG block at offset ${o}; the file can't be read.`)
      warnings.push(`Corrupt block at offset ${o}; stopped after ${records.length} packets.`)
      break
    }
    o += blockLen
    if (onProgress && o - lastReport > 1 << 20) {
      lastReport = o
      onProgress(o / bytes.length)
    }
  }
  backfillTimestamps(records)
  return { format: 'pcapng', records, linkTypes: [...linkTypes], warnings }
}

/** Simple Packet Blocks have no timestamp: borrow the previous packet's, or the next one's at the start. */
function backfillTimestamps(records: RawRecord[]): void {
  let last = NaN
  for (const r of records) {
    if (Number.isNaN(r.ts)) r.ts = last
    else last = r.ts
  }
  const first = records.find((r) => !Number.isNaN(r.ts))?.ts ?? 0
  for (const r of records) if (Number.isNaN(r.ts)) r.ts = first
}
