import type { IndexPhase } from '../core/index/indexer'
import type { CaptureIndex } from '../core/types'

export type WorkerRequest = { type: 'parse'; id: number; buffer: ArrayBuffer; fileName: string }

export type WorkerResponse =
  | { type: 'progress'; id: number; phase: IndexPhase; fraction: number; packets: number }
  | { type: 'done'; id: number; index: CaptureIndex }
  | { type: 'error'; id: number; message: string; kind: 'format' | 'empty' | 'internal' }
