// A ~20 MB capture must index quickly (it runs in a Web Worker in the app, so the UI never blocks).

import { describe, expect, it } from 'vitest'
import { buildIndex } from '../src/core/index/indexer'
import { writePcap, type FrameToWrite } from '../src/core/pcap/writer'
import { dnsQuery, ethernet, ipv4, tcp, text, udp } from '../src/samples/builder'

function bigCapture(targetBytes: number): Uint8Array {
  const frames: FrameToWrite[] = []
  const body = text('GET /' + 'x'.repeat(900) + ' HTTP/1.1\r\nHost: perf.test\r\n\r\n')
  let size = 24
  let i = 0
  while (size < targetBytes) {
    const port = 20000 + (i % 5000)
    const data =
      i % 10 === 0
        ? ethernet('02:00:00:00:00:01', '02:00:00:00:00:02', 0x0800, ipv4('10.0.0.2', '10.0.0.1', 17, udp(port, 53, dnsQuery(i & 0xffff, `host${i % 97}.example.com`))))
        : ethernet('02:00:00:00:00:01', '02:00:00:00:00:02', 0x0800, ipv4('10.0.0.2', '10.0.0.3', 6, tcp(port, 80, i * 1000, 1, { ack: true, psh: true }, body)))
    frames.push({ ts: 1700000000 + i / 1000, data })
    size += 16 + data.length
    i++
  }
  return writePcap(frames)
}

describe('performance', () => {
  it('indexes a 20 MB capture in well under 10 seconds', () => {
    const buf = bigCapture(20 * 1024 * 1024)
    const t0 = performance.now()
    const idx = buildIndex(buf, 'big.pcap')
    const ms = performance.now() - t0
    console.log(`indexed ${idx.packets.length} packets (${(buf.length / 1048576).toFixed(1)} MB) in ${ms.toFixed(0)} ms`)
    expect(idx.packets.length).toBeGreaterThan(15000)
    expect(ms).toBeLessThan(10000)
  }, 30000)
})
