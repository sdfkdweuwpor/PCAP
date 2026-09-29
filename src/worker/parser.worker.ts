/// <reference lib="webworker" />
// Parses a capture off the main thread so the UI never freezes, streaming progress back.

import { buildIndex } from '../core/index/indexer'
import { CaptureFormatError } from '../core/pcap/container'
import type { WorkerRequest, WorkerResponse } from './protocol'

const post = (m: WorkerResponse) => (self as unknown as DedicatedWorkerGlobalScope).postMessage(m)

self.onmessage = (e: MessageEvent<WorkerRequest>) => {
  const msg = e.data
  if (msg.type !== 'parse') return
  const { id } = msg
  try {
    let last = 0
    const index = buildIndex(new Uint8Array(msg.buffer), msg.fileName, (phase, fraction, packets) => {
      const now = performance.now()
      if (now - last < 50 && fraction < 1) return
      last = now
      post({ type: 'progress', id, phase, fraction, packets })
    })
    post({ type: 'done', id, index })
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    const kind = err instanceof CaptureFormatError ? 'format' : /no packets/.test(message) ? 'empty' : 'internal'
    post({ type: 'error', id, message, kind })
  }
}
