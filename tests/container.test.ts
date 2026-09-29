import { describe, expect, it } from 'vitest'
import { CaptureFormatError, parseContainer } from '../src/core/pcap/container'
import { writePcap, writePcapng } from '../src/core/pcap/writer'
import { buildIndex } from '../src/core/index/indexer'

const frameA = Uint8Array.from({ length: 60 }, (_, i) => i)
const frameB = Uint8Array.from({ length: 42 }, (_, i) => 255 - i)

describe('classic PCAP', () => {
  it('reads little-endian microsecond files', () => {
    const buf = writePcap([
      { ts: 1700000000.25, data: frameA },
      { ts: 1700000001.5, data: frameB, origLen: 1500 },
    ])
    expect([...buf.subarray(0, 4)]).toEqual([0xd4, 0xc3, 0xb2, 0xa1])
    const r = parseContainer(buf)
    expect(r.format).toBe('pcap')
    expect(r.records).toHaveLength(2)
    expect(r.records[0].ts).toBeCloseTo(1700000000.25, 6)
    expect(r.records[1].origLen).toBe(1500)
    expect(r.records[1].capLen).toBe(42)
    expect([...buf.subarray(r.records[0].dataOffset, r.records[0].dataOffset + 4)]).toEqual([0, 1, 2, 3])
  })

  it('reads big-endian (0xa1b2c3d4) files', () => {
    const buf = writePcap([{ ts: 10.5, data: frameA }], 1, { bigEndian: true })
    expect([...buf.subarray(0, 4)]).toEqual([0xa1, 0xb2, 0xc3, 0xd4])
    const r = parseContainer(buf)
    expect(r.records[0].ts).toBeCloseTo(10.5, 6)
    expect(r.linkTypes).toEqual([1])
  })

  it('reads nanosecond (0xa1b23c4d) files', () => {
    const buf = writePcap([{ ts: 5.123456789, data: frameA }], 1, { nanos: true, bigEndian: true })
    expect([...buf.subarray(0, 4)]).toEqual([0xa1, 0xb2, 0x3c, 0x4d])
    expect(parseContainer(buf).records[0].ts).toBeCloseTo(5.123456789, 8)
  })

  it('keeps packets before a truncation and warns', () => {
    const buf = writePcap([
      { ts: 1, data: frameA },
      { ts: 2, data: frameB },
    ])
    const r = parseContainer(buf.subarray(0, buf.length - 10))
    expect(r.records).toHaveLength(1)
    expect(r.warnings[0]).toMatch(/truncated/i)
  })

  it('rejects files with an unknown signature', () => {
    expect(() => parseContainer(new TextEncoder().encode('this is not a capture file'))).toThrow(CaptureFormatError)
    expect(() => parseContainer(new Uint8Array([1, 2]))).toThrow(/too small/)
  })

  it('rejects impossible record lengths as corrupt', () => {
    const buf = writePcap([{ ts: 1, data: frameA }])
    new DataView(buf.buffer).setUint32(24 + 8, 0x7fffffff, true)
    expect(() => parseContainer(buf)).toThrow(/corrupt/)
  })

  it('reports an empty capture clearly', () => {
    expect(() => buildIndex(writePcap([]), 'empty.pcap')).toThrow(/no packets/)
  })
})

describe('PCAPNG', () => {
  it('handles multiple interfaces with their own link types and timestamp resolution', () => {
    const buf = writePcapng(
      [
        { ts: 100.000001, data: frameA, interfaceId: 0 },
        { ts: 100.123456789, data: frameB, interfaceId: 1 },
      ],
      [{ linkType: 1, name: 'eth0' }, { linkType: 101, tsresol: 9 }],
    )
    const r = parseContainer(buf)
    expect(r.format).toBe('pcapng')
    expect(r.linkTypes.sort()).toEqual([1, 101])
    expect(r.records.map((x) => x.linkType)).toEqual([1, 101])
    expect(r.records[0].ts).toBeCloseTo(100.000001, 6)
    expect(r.records[1].ts).toBeCloseTo(100.123456789, 7)
    expect(r.records[1].interfaceId).toBe(1)
    expect([...buf.subarray(r.records[1].dataOffset, r.records[1].dataOffset + 2)]).toEqual([255, 254])
  })

  it('supports binary (2^-n) timestamp resolution', () => {
    const buf = writePcapng([{ ts: 3.5, data: frameA }], [{ linkType: 1, tsresol: 0x80 | 10 }])
    expect(parseContainer(buf).records[0].ts).toBeCloseTo(3.5, 3)
  })

  it('reads Simple Packet Blocks', () => {
    const base = writePcapng([], [{ linkType: 1 }])
    const body = new Uint8Array(4 + 60)
    new DataView(body.buffer).setUint32(0, 60, true)
    body.set(frameA, 4)
    const blk = new Uint8Array(12 + body.length)
    const v = new DataView(blk.buffer)
    v.setUint32(0, 3, true)
    v.setUint32(4, blk.length, true)
    blk.set(body, 8)
    v.setUint32(blk.length - 4, blk.length, true)
    const buf = new Uint8Array(base.length + blk.length)
    buf.set(base)
    buf.set(blk, base.length)
    const r = parseContainer(buf)
    expect(r.records).toHaveLength(1)
    expect(r.records[0].capLen).toBe(60)
  })

  it('rejects a bad byte-order magic', () => {
    const buf = writePcapng([{ ts: 1, data: frameA }])
    buf[8] = 0
    expect(() => parseContainer(buf)).toThrow(CaptureFormatError)
  })

  it('warns and stops on a truncated block', () => {
    const buf = writePcapng([
      { ts: 1, data: frameA },
      { ts: 2, data: frameB },
    ])
    const r = parseContainer(buf.subarray(0, buf.length - 8))
    expect(r.records).toHaveLength(1)
    expect(r.warnings.join(' ')).toMatch(/truncated/i)
  })
})
