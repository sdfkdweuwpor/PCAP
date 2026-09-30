// Persistent learner progress and settings (localStorage, JSON import/export).

import { create } from 'zustand'
import type { ConceptStat } from '../game/engine'
import { CONCEPT_LABEL, type Concept } from '../game/types'
import { loadJSON, removeKey, saveJSON } from './storage'

export interface Settings {
  theme: 'dark' | 'paper'
  /** Scanline/vignette overlay on the phosphor screens. */
  crt: boolean
  /** 'system' follows prefers-reduced-motion. */
  reduceMotion: 'system' | 'on' | 'off'
  unlockAll: boolean
  showTimer: boolean
  /** Single-key shortcuts (a–j, 1–4, n, ?, 1–8 on the start screen). Can be turned off (WCAG 2.1.4). */
  hotkeys: boolean
  /** Optional AI explain hook — off by default, never sends data unless explicitly enabled. */
  aiExplain: boolean
}

export interface SessionRecord {
  at: number
  file: string
  mode: string
  answered: number
  correct: number
  xp: number
  bestStreak: number
}

export interface Progress {
  version: 1
  xp: number
  bestStreak: number
  answered: number
  correct: number
  concepts: Partial<Record<Concept, ConceptStat>>
  sessions: SessionRecord[]
  /** Keystroke drill personal bests. */
  drill: { bestWpm: number; bestAccuracy: number; runs: number }
  settings: Settings
}

const KEY = 'packetquest.progress.v1'

export const DEFAULT_PROGRESS: Progress = {
  version: 1,
  xp: 0,
  bestStreak: 0,
  answered: 0,
  correct: 0,
  concepts: {},
  sessions: [],
  drill: { bestWpm: 0, bestAccuracy: 0, runs: 0 },
  settings: { theme: 'paper', crt: true, reduceMotion: 'system', unlockAll: false, showTimer: true, hotkeys: true, aiExplain: false },
}

interface ProgressStore extends Progress {
  storageOk: boolean
  record: (concept: Concept, score: number, xp: number, streak: number) => void
  addSession: (s: SessionRecord) => void
  recordDrill: (wpm: number, accuracy: number, xp: number) => void
  setSettings: (s: Partial<Settings>) => void
  exportJSON: () => string
  importJSON: (json: string) => string | null
  reset: () => void
}

const num = (v: unknown, min = 0, max = Number.MAX_SAFE_INTEGER) => {
  const n = typeof v === 'number' ? v : Number(v)
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : min
}
const bool = (v: unknown, fallback: boolean) => (typeof v === 'boolean' ? v : fallback)
const oneOf = <T extends string>(v: unknown, allowed: readonly T[], fallback: T): T => (allowed.includes(v as T) ? (v as T) : fallback)

/**
 * Coerces anything (a stored blob, an imported file) into a valid Progress. Unknown concepts are dropped and every
 * number is clamped, so a hand-edited or corrupted file can never crash the UI or be persisted in a broken state.
 */
export function sanitizeProgress(raw: unknown): Progress {
  const d = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  const concepts: Progress['concepts'] = {}
  if (d.concepts && typeof d.concepts === 'object') {
    for (const [k, v] of Object.entries(d.concepts as Record<string, unknown>)) {
      if (!Object.hasOwn(CONCEPT_LABEL, k) || !v || typeof v !== 'object') continue
      const seen = Math.floor(num((v as ConceptStat).seen))
      if (!seen) continue
      concepts[k as Concept] = { seen, correct: num((v as ConceptStat).correct, 0, seen) }
    }
  }
  const sessions = Array.isArray(d.sessions)
    ? d.sessions
        .filter((x): x is Record<string, unknown> => !!x && typeof x === 'object')
        .slice(0, 25)
        .map((x) => ({
          at: num(x.at),
          file: String(x.file ?? '').slice(0, 200),
          mode: String(x.mode ?? '').slice(0, 20),
          answered: Math.floor(num(x.answered)),
          correct: Math.floor(num(x.correct)),
          xp: Math.floor(num(x.xp)),
          bestStreak: Math.floor(num(x.bestStreak)),
        }))
    : []
  const st = (d.settings && typeof d.settings === 'object' ? d.settings : {}) as Record<string, unknown>
  const def = DEFAULT_PROGRESS.settings
  // Older saves used amber/green phosphor screens (both now 'dark') or light/dark.
  const legacy = st.theme === 'amber' || st.theme === 'green' ? 'dark' : st.theme === 'light' ? 'paper' : st.theme
  const drill = (d.drill && typeof d.drill === 'object' ? d.drill : {}) as Record<string, unknown>
  const answered = Math.floor(num(d.answered))
  return {
    version: 1,
    xp: Math.floor(num(d.xp, 0, 1e9)),
    bestStreak: Math.floor(num(d.bestStreak)),
    answered,
    correct: Math.floor(num(d.correct, 0, answered)),
    concepts,
    sessions,
    drill: { bestWpm: Math.floor(num(drill.bestWpm, 0, 400)), bestAccuracy: num(drill.bestAccuracy, 0, 1), runs: Math.floor(num(drill.runs)) },
    settings: {
      theme: oneOf(legacy, ['dark', 'paper'] as const, def.theme),
      crt: bool(st.crt, def.crt),
      reduceMotion: oneOf(st.reduceMotion, ['system', 'on', 'off'] as const, def.reduceMotion),
      unlockAll: bool(st.unlockAll, def.unlockAll),
      showTimer: bool(st.showTimer, def.showTimer),
      hotkeys: bool(st.hotkeys, def.hotkeys),
      aiExplain: bool(st.aiExplain, def.aiExplain),
    },
  }
}

function initial(): Progress {
  return sanitizeProgress(loadJSON<Partial<Progress>>(KEY, {}))
}

export const useProgress = create<ProgressStore>((set, get) => {
  const persist = () => {
    const { version, xp, bestStreak, answered, correct, concepts, sessions, drill, settings } = get()
    const ok = saveJSON(KEY, { version, xp, bestStreak, answered, correct, concepts, sessions, drill, settings })
    if (ok !== get().storageOk) set({ storageOk: ok })
  }
  return {
    ...initial(),
    storageOk: true,
    record(concept, score, xp, streak) {
      set((s) => {
        const prev = s.concepts[concept] ?? { seen: 0, correct: 0 }
        return {
          xp: s.xp + xp,
          answered: s.answered + 1,
          correct: s.correct + (score >= 1 ? 1 : 0),
          bestStreak: Math.max(s.bestStreak, streak),
          concepts: { ...s.concepts, [concept]: { seen: prev.seen + 1, correct: prev.correct + score } },
        }
      })
      persist()
    },
    recordDrill(wpm, accuracy, xp) {
      set((s) => ({
        xp: s.xp + xp,
        drill: {
          bestWpm: Math.max(s.drill.bestWpm, wpm),
          bestAccuracy: Math.max(s.drill.bestAccuracy, accuracy),
          runs: s.drill.runs + 1,
        },
      }))
      persist()
    },
    addSession(rec) {
      set((s) => ({ sessions: [rec, ...s.sessions].slice(0, 25) }))
      persist()
    },
    setSettings(patch) {
      set((s) => ({ settings: { ...s.settings, ...patch } }))
      persist()
    },
    exportJSON() {
      const { version, xp, bestStreak, answered, correct, concepts, sessions, drill, settings } = get()
      return JSON.stringify({ app: 'PacketQuest', version, xp, bestStreak, answered, correct, concepts, sessions, drill, settings }, null, 2)
    },
    importJSON(json) {
      let d: unknown
      try {
        d = JSON.parse(json)
      } catch {
        return 'Could not read that file: it is not valid JSON.'
      }
      if (!d || typeof d !== 'object' || typeof (d as { xp?: unknown }).xp !== 'number')
        return 'That file does not look like a PacketQuest progress export.'
      const clean = sanitizeProgress(d)
      set({ ...clean })
      persist()
      return null
    },
    reset() {
      removeKey(KEY)
      set({ ...DEFAULT_PROGRESS, settings: get().settings })
      persist()
    },
  }
})
