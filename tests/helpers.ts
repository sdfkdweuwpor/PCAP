import { dissectFrame } from '../src/core/dissect'
import { buildIndex, frameBytes, isnMapFromSummaries } from '../src/core/index/indexer'
import type { CaptureIndex, Dissection, Field } from '../src/core/types'
import { writePcap } from '../src/core/pcap/writer'

export function indexOf(bytes: Uint8Array, name = 'test.pcap') {
  const index = buildIndex(bytes, name)
  const isn = isnMapFromSummaries(index.packets)
  const dissect = (no: number): Dissection => {
    const p = index.packets[no - 1]
    return dissectFrame(frameBytes(bytes, p), { no, ts: p.ts, relTime: p.relTime, origLen: p.origLen, linkType: p.linkType }, { tcpIsn: isn })
  }
  return { index, dissect, bytes }
}

export function single(frame: Uint8Array, linkType = 1): { index: CaptureIndex; d: Dissection; frame: Uint8Array } {
  const { index, dissect } = indexOf(writePcap([{ ts: 1700000000, data: frame }], linkType))
  return { index, d: dissect(1), frame }
}

export function find(layers: Field[], key: string): Field | undefined {
  for (const f of layers) {
    if (f.key === key) return f
    const r = f.children && find(f.children, key)
    if (r) return r
  }
  return undefined
}

export function all(layers: Field[]): Field[] {
  return layers.flatMap((f) => [f, ...all(f.children ?? [])])
}

/** Bytes covered by a field. */
export function slice(frame: Uint8Array, f: Field): number[] {
  return [...frame.subarray(f.offset, f.offset + f.length)]
}
