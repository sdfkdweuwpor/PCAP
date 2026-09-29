// Loaded capture + viewer state (selection, filter, highlights). Packet trees are dissected lazily
// on the main thread from the retained bytes and cached.

import { create } from 'zustand'
import { dissectFrame } from '../core/dissect'
import { compileFilter, FilterError } from '../core/filter/filter'
import { frameBytes, isnForPacket } from '../core/index/indexer'
import type { CaptureIndex, Dissection, PacketSummary } from '../core/types'
import { buildQuestionBank, type QuestionBank } from '../game/engine'
import { getSample } from '../samples/samples'
import { parseCapture, ParseError, type ParseProgress } from '../worker/client'

export const MAX_SOFT_BYTES = 50 * 1024 * 1024
export const ACCEPTED = ['.pcap', '.pcapng', '.cap']

export type Tab = 'packets' | 'flow' | 'conversations' | 'stream'

export interface Range {
  offset: number
  length: number
}

export interface FlashState {
  frames: number[]
  kind: 'correct' | 'wrong' | 'answer'
  token: number
}

export interface SweepState {
  packet: number
  fieldKeys: string[]
  token: number
}

interface CaptureStore {
  status: 'idle' | 'loading' | 'ready' | 'error'
  progress: ParseProgress | null
  error: { message: string; kind: string } | null
  sizeWarning: string | null
  fileName: string
  index: CaptureIndex | null
  bytes: Uint8Array | null
  bank: QuestionBank | null
  loadMs: number

  selected: number | null
  multi: number[]
  filterText: string
  filterError: string | null
  visible: number[] | null
  hover: Range | null
  hoverKey: string | null
  selectedField: (Range & { key?: string; name: string }) | null
  revealSecrets: boolean
  tab: Tab
  flowConv: number | null
  streamConv: number | null
  flash: FlashState | null
  sweep: SweepState | null
  /** Rows the game wants locked (field hunt / says questions). */
  lockedTo: number | null

  loadFile: (file: File) => Promise<void>
  loadSample: (id: string) => Promise<void>
  loadBytes: (bytes: Uint8Array, name: string) => Promise<void>
  close: () => void
  select: (no: number | null) => void
  toggleMulti: (no: number) => void
  clearMulti: () => void
  setFilter: (text: string) => void
  setHover: (r: Range | null, key?: string | null) => void
  selectField: (f: CaptureStore['selectedField']) => void
  setReveal: (v: boolean) => void
  setTab: (t: Tab) => void
  setFlowConv: (id: number | null) => void
  setStreamConv: (id: number | null) => void
  flashRows: (frames: number[] | null, kind?: FlashState['kind']) => void
  showMe: (packet: number, fieldKeys?: string[]) => void
  lock: (no: number | null) => void
}

let cache = new Map<number, Dissection>()
let token = 0
/** Increments per load so a slow parse can't overwrite a newer capture. */
let loadSeq = 0

export function getPacket(no: number): PacketSummary | undefined {
  return useCapture.getState().index?.packets[no - 1]
}

export function getFrameBytes(no: number): Uint8Array {
  const { index, bytes } = useCapture.getState()
  if (!index || !bytes) return new Uint8Array()
  return frameBytes(bytes, index.packets[no - 1])
}

/** On-demand dissection with a bounded cache. */
export function getDissection(no: number): Dissection | null {
  const { index, bytes } = useCapture.getState()
  if (!index || !bytes) return null
  const hit = cache.get(no)
  if (hit) return hit
  const p = index.packets[no - 1]
  if (!p) return null
  const d = dissectFrame(frameBytes(bytes, p), { no, ts: p.ts, relTime: p.relTime, origLen: p.origLen, linkType: p.linkType }, { tcpIsn: isnForPacket(p) })
  if (cache.size > 2000) cache = new Map()
  cache.set(no, d)
  return d
}

export const useCapture = create<CaptureStore>((set, get) => ({
  status: 'idle',
  progress: null,
  error: null,
  sizeWarning: null,
  fileName: '',
  index: null,
  bytes: null,
  bank: null,
  loadMs: 0,
  selected: null,
  multi: [],
  filterText: '',
  filterError: null,
  visible: null,
  hover: null,
  hoverKey: null,
  selectedField: null,
  revealSecrets: false,
  tab: 'packets',
  flowConv: null,
  streamConv: null,
  flash: null,
  sweep: null,
  lockedTo: null,

  async loadFile(file) {
    const lower = file.name.toLowerCase()
    if (!ACCEPTED.some((ext) => lower.endsWith(ext))) {
      set({
        status: 'error',
        error: { message: `"${file.name}" isn't a .pcap, .pcapng or .cap file. In Wireshark use File → Save As and pick one of those formats.`, kind: 'format' },
      })
      return
    }
    const sizeWarning =
      file.size > MAX_SOFT_BYTES
        ? `This capture is ${(file.size / 1048576).toFixed(0)} MB. Everything is indexed, but packet details are decoded on demand and questions may take a moment.`
        : null
    let buf: ArrayBuffer
    try {
      buf = await file.arrayBuffer()
    } catch {
      set({ status: 'error', error: { message: 'The browser could not read that file.', kind: 'internal' } })
      return
    }
    set({ sizeWarning })
    await get().loadBytes(new Uint8Array(buf), file.name)
  },

  async loadSample(id) {
    const s = getSample(id)
    if (!s) return
    set({ sizeWarning: null })
    await get().loadBytes(s.build(), s.fileName)
  },

  async loadBytes(bytes, name) {
    const t0 = performance.now()
    const seq = ++loadSeq
    const current = () => seq === loadSeq
    set({ status: 'loading', progress: { phase: 'reading', fraction: 0, packets: 0 }, error: null, fileName: name })
    try {
      const index = await parseCapture(bytes, name, (progress) => current() && set({ progress }))
      if (!current()) return
      cache = new Map()
      set({
        index,
        bytes,
        status: 'ready',
        progress: { phase: 'analyzing', fraction: 1, packets: index.packets.length },
        selected: null,
        multi: [],
        filterText: '',
        filterError: null,
        visible: null,
        selectedField: null,
        hover: null,
        hoverKey: null,
        tab: 'packets',
        flowConv: null,
        streamConv: null,
        lockedTo: null,
        bank: null,
        sweep: null,
        flash: null,
        revealSecrets: false,
        loadMs: performance.now() - t0,
      })
      // Questions are generated after the UI can render the capture.
      setTimeout(() => {
        if (get().index !== index) return
        const bank = buildQuestionBank(index, (no) => getDissection(no)!, index.packets.length)
        set({ bank })
      }, 0)
    } catch (e) {
      if (!current()) return
      const kind = e instanceof ParseError ? e.kind : 'internal'
      const message = e instanceof Error ? e.message : String(e)
      set({ status: 'error', error: { message, kind }, index: null, bytes: null })
    }
  },

  close() {
    cache = new Map()
    loadSeq++
    set({
      status: 'idle',
      index: null,
      bytes: null,
      bank: null,
      error: null,
      progress: null,
      fileName: '',
      selected: null,
      lockedTo: null,
      sweep: null,
      flash: null,
      revealSecrets: false,
      filterText: '',
      filterError: null,
      visible: null,
    })
  },

  select(no) {
    const locked = get().lockedTo
    if (locked !== null && no !== locked) return
    set({ selected: no, selectedField: null, hover: null, hoverKey: null })
    const p = no ? get().index?.packets[no - 1] : undefined
    if (p && p.streamId >= 0) {
      // Flow graph and follow-stream both track the selected packet's conversation.
      const proto = get().index?.conversations[p.streamId]?.proto
      set({ flowConv: p.streamId, ...(proto === 'TCP' || proto === 'UDP' ? { streamConv: p.streamId } : {}) })
    }
  },
  toggleMulti(no) {
    const m = get().multi
    set({ multi: m.includes(no) ? m.filter((x) => x !== no) : [...m, no] })
  },
  clearMulti() {
    set({ multi: [] })
  },
  setFilter(text) {
    const { index } = get()
    if (!index) return set({ filterText: text })
    try {
      const pred = compileFilter(text)
      const visible = text.trim() ? index.packets.filter(pred).map((p) => p.no) : null
      set({ filterText: text, filterError: null, visible })
    } catch (e) {
      set({ filterText: text, filterError: e instanceof FilterError ? e.message : 'Invalid filter.' })
    }
  },
  setHover(r, key = null) {
    set({ hover: r, hoverKey: key })
  },
  selectField(f) {
    set({ selectedField: f })
  },
  setReveal(v) {
    set({ revealSecrets: v })
  },
  setTab(t) {
    set({ tab: t })
  },
  setFlowConv(id) {
    set({ flowConv: id })
  },
  setStreamConv(id) {
    set({ streamConv: id })
  },
  flashRows(frames, kind = 'answer') {
    set({ flash: frames ? { frames, kind, token: ++token } : null })
  },
  showMe(packet, fieldKeys = []) {
    const p = get().index?.packets[packet - 1]
    if (!p) return
    set({
      tab: 'packets',
      selected: packet,
      sweep: { packet, fieldKeys, token: ++token },
      flowConv: p && p.streamId >= 0 ? p.streamId : get().flowConv,
    })
  },
  lock(no) {
    set({ lockedTo: no })
    if (no !== null) get().select(no)
  },
}))
