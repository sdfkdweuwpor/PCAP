// Minimal PCAP / PCAPNG writers. Used to build the synthetic sample captures and parser tests.

export interface FrameToWrite {
  ts: number
  data: Uint8Array
  /** PCAPNG only: index into the interfaces list. */
  interfaceId?: number
  /** Defaults to data.length. */
  origLen?: number
}

export function writePcap(
  frames: FrameToWrite[],
  linkType = 1,
  opts: { nanos?: boolean; bigEndian?: boolean } = {},
): Uint8Array {
  const le = !opts.bigEndian
  const total = 24 + frames.reduce((n, f) => n + 16 + f.data.length, 0)
  const out = new Uint8Array(total)
  const v = new DataView(out.buffer)
  v.setUint32(0, opts.nanos ? 0xa1b23c4d : 0xa1b2c3d4, le)
  v.setUint16(4, 2, le)
  v.setUint16(6, 4, le)
  v.setInt32(8, 0, le)
  v.setUint32(12, 0, le)
  v.setUint32(16, 262144, le)
  v.setUint32(20, linkType, le)
  let o = 24
  const mult = opts.nanos ? 1e9 : 1e6
  for (const f of frames) {
    const sec = Math.floor(f.ts)
    const frac = Math.round((f.ts - sec) * mult)
    v.setUint32(o, sec, le)
    v.setUint32(o + 4, frac, le)
    v.setUint32(o + 8, f.data.length, le)
    v.setUint32(o + 12, f.origLen ?? f.data.length, le)
    out.set(f.data, o + 16)
    o += 16 + f.data.length
  }
  return out
}

export interface NgInterface {
  linkType: number
  /** if_tsresol option value; default 6 (microseconds). */
  tsresol?: number
  name?: string
}

const pad4 = (n: number) => (n + 3) & ~3

export function writePcapng(frames: FrameToWrite[], interfaces: NgInterface[] = [{ linkType: 1 }]): Uint8Array {
  const blocks: Uint8Array[] = []
  const block = (type: number, body: Uint8Array) => {
    const len = 12 + pad4(body.length)
    const b = new Uint8Array(len)
    const v = new DataView(b.buffer)
    v.setUint32(0, type, true)
    v.setUint32(4, len, true)
    b.set(body, 8)
    v.setUint32(len - 4, len, true)
    blocks.push(b)
  }
  // Section Header Block
  {
    const body = new Uint8Array(16)
    const v = new DataView(body.buffer)
    v.setUint32(0, 0x1a2b3c4d, true)
    v.setUint16(4, 1, true)
    v.setUint16(6, 0, true)
    v.setInt32(8, -1, true)
    v.setInt32(12, -1, true)
    block(0x0a0d0d0a, body)
  }
  for (const itf of interfaces) {
    const name = itf.name ? new TextEncoder().encode(itf.name) : null
    let optLen = 0
    if (name) optLen += 4 + pad4(name.length)
    if (itf.tsresol !== undefined) optLen += 8
    if (optLen) optLen += 4 // opt_endofopt
    const body = new Uint8Array(8 + optLen)
    const v = new DataView(body.buffer)
    v.setUint16(0, itf.linkType, true)
    v.setUint32(4, 262144, true)
    let p = 8
    if (name) {
      v.setUint16(p, 2, true)
      v.setUint16(p + 2, name.length, true)
      body.set(name, p + 4)
      p += 4 + pad4(name.length)
    }
    if (itf.tsresol !== undefined) {
      v.setUint16(p, 9, true)
      v.setUint16(p + 2, 1, true)
      body[p + 4] = itf.tsresol
      p += 8
    }
    block(0x00000001, body)
  }
  for (const f of frames) {
    const itf = interfaces[f.interfaceId ?? 0]
    const r = itf.tsresol ?? 6
    const unitsPerSec = r & 0x80 ? 2 ** (r & 0x7f) : 10 ** r
    const units = Math.round(f.ts * unitsPerSec)
    const body = new Uint8Array(20 + pad4(f.data.length))
    const v = new DataView(body.buffer)
    v.setUint32(0, f.interfaceId ?? 0, true)
    v.setUint32(4, Math.floor(units / 4294967296), true)
    v.setUint32(8, units % 4294967296, true)
    v.setUint32(12, f.data.length, true)
    v.setUint32(16, f.origLen ?? f.data.length, true)
    body.set(f.data, 20)
    block(0x00000006, body)
  }
  const total = blocks.reduce((n, b) => n + b.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const b of blocks) {
    out.set(b, o)
    o += b.length
  }
  return out
}
