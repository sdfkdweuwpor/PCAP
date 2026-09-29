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
  if (!w) return parseOnMainThread(bytes, fileName, onProgress)
  return parseInWorker(w, bytes, fileName, onProgress).catch((e) => {
    // A worker that fails to load (blocked script, old browser) should not stop the app: parse here instead.
    if (e instanceof ParseError && e.kind === 'internal' && e.message.startsWith('worker:')) return parseOnMainThread(bytes, fileName, onProgress)
    throw e
  })
}

function parseOnMainThread(bytes: Uint8Array, fileName: string, onProgress: (p: ParseProgress) => void): Promise<CaptureIndex> {
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

function parseInWorker(w: Worker, bytes: Uint8Array, fileName: string, onProgress: (p: ParseProgress) => void): Promise<CaptureIndex> {
  const id = nextId++
  const copy = bytes.slice().buffer
  const packets: CaptureIndex['packets'] = []
  return new Promise((resolve, reject) => {
    const onMessage = (e: MessageEvent<WorkerResponse>) => {
      const m = e.data
      if (m.id !== id) return
      if (m.type === 'progress') onProgress({ phase: m.phase, fraction: m.fraction, packets: m.packets })
      else if (m.type === 'chunk') {
        for (const p of m.packets) packets.push(p)
        onProgress({ phase: 'analyzing', fraction: 1, packets: packets.length })
      } else {
        detach()
        if (m.type === 'done') resolve({ ...m.index, packets })
        else reject(new ParseError(m.message, m.kind))
      }
    }
    // "worker:" errors make the caller fall back to parsing on the main thread.
    const fail = (why: string) => {
      detach()
      worker?.terminate()
      worker = null
      reject(new ParseError(`worker: ${why}`, 'internal'))
    }
    const onError = (e: ErrorEvent) => fail(e.message || 'failed to start')
    const onMessageError = () => fail('a message could not be deserialised')
    const detach = () => {
      w.removeEventListener('message', onMessage)
      w.removeEventListener('error', onError)
      w.removeEventListener('messageerror', onMessageError)
    }
    w.addEventListener('message', onMessage)
    w.addEventListener('error', onError)
    w.addEventListener('messageerror', onMessageError)
    const req: WorkerRequest = { type: 'parse', id, buffer: copy, fileName }
    w.postMessage(req, [copy])
  })
}
