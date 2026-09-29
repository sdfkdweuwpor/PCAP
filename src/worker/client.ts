// Promise wrapper around the parser worker. Falls back to main-thread parsing if workers are unavailable.

import { buildIndex, type IndexPhase } from '../core/index/indexer'
import type { CaptureIndex } from '../core/types'
import type { WorkerRequest, WorkerResponse } from './protocol'

export interface ParseProgress {
  phase: IndexPhase
  fraction: number
  packets: number
}

export class ParseError extends Error {
  kind: 'format' | 'empty' | 'internal'
  constructor(message: string, kind: 'format' | 'empty' | 'internal') {
    super(message)
    this.kind = kind
  }
}

let worker: Worker | null = null
let nextId = 1

function getWorker(): Worker | null {
  if (worker) return worker
  try {
    worker = new Worker(new URL('./parser.worker.ts', import.meta.url), { type: 'module' })
  } catch {
    worker = null
  }
  return worker
}

/** Parses in a worker. The caller keeps `bytes`; a copy is transferred to the worker. */
export function parseCapture(bytes: Uint8Array, fileName: string, onProgress: (p: ParseProgress) => void): Promise<CaptureIndex> {
  const w = getWorker()
  if (!w) {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        try {
          resolve(buildIndex(bytes, fileName, (phase, fraction, packets) => onProgress({ phase, fraction, packets })))
        } catch (e) {
          reject(new ParseError(e instanceof Error ? e.message : String(e), 'format'))
        }
      }, 0)
    })
  }
  const id = nextId++
  const copy = bytes.slice().buffer
  return new Promise((resolve, reject) => {
    const onMessage = (e: MessageEvent<WorkerResponse>) => {
      const m = e.data
      if (m.id !== id) return
      if (m.type === 'progress') onProgress({ phase: m.phase, fraction: m.fraction, packets: m.packets })
      else {
        w.removeEventListener('message', onMessage)
        w.removeEventListener('error', onError)
        if (m.type === 'done') resolve(m.index)
        else reject(new ParseError(m.message, m.kind))
      }
    }
    const onError = (e: ErrorEvent) => {
      w.removeEventListener('message', onMessage)
      w.removeEventListener('error', onError)
      worker?.terminate()
      worker = null
      reject(new ParseError(e.message || 'The parser crashed.', 'internal'))
    }
    w.addEventListener('message', onMessage)
    w.addEventListener('error', onError)
    const req: WorkerRequest = { type: 'parse', id, buffer: copy, fileName }
    w.postMessage(req, [copy])
  })
}
