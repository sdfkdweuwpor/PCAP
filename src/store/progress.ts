// Persistent learner progress and settings (localStorage, JSON import/export).

import { create } from 'zustand'
import type { ConceptStat } from '../game/engine'
import type { Concept } from '../game/types'
import { loadJSON, removeKey, saveJSON } from './storage'

export interface Settings {
  theme: 'dark' | 'light'
  /** 'system' follows prefers-reduced-motion. */
  reduceMotion: 'system' | 'on' | 'off'
  unlockAll: boolean
  showTimer: boolean
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
  settings: { theme: 'dark', reduceMotion: 'system', unlockAll: false, showTimer: true, aiExplain: false },
}

interface ProgressStore extends Progress {
  storageOk: boolean
  record: (concept: Concept, score: number, xp: number, streak: number) => void
  addSession: (s: SessionRecord) => void
  setSettings: (s: Partial<Settings>) => void
  exportJSON: () => string
  importJSON: (json: string) => string | null
  reset: () => void
}

function initial(): Progress {
  const p = loadJSON<Progress>(KEY, DEFAULT_PROGRESS)
  return { ...p, settings: { ...DEFAULT_PROGRESS.settings, ...p.settings } }
}

export const useProgress = create<ProgressStore>((set, get) => {
  const persist = () => {
    const { version, xp, bestStreak, answered, correct, concepts, sessions, settings } = get()
    const ok = saveJSON(KEY, { version, xp, bestStreak, answered, correct, concepts, sessions, settings })
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
    addSession(rec) {
      set((s) => ({ sessions: [rec, ...s.sessions].slice(0, 25) }))
      persist()
    },
    setSettings(patch) {
      set((s) => ({ settings: { ...s.settings, ...patch } }))
      persist()
    },
    exportJSON() {
      const { version, xp, bestStreak, answered, correct, concepts, sessions, settings } = get()
      return JSON.stringify({ app: 'PacketQuest', version, xp, bestStreak, answered, correct, concepts, sessions, settings }, null, 2)
    },
    importJSON(json) {
      try {
        const d = JSON.parse(json)
        if (typeof d !== 'object' || d === null || typeof d.xp !== 'number' || typeof d.concepts !== 'object')
          return 'That file does not look like a PacketQuest progress export.'
        set({
          xp: Math.max(0, d.xp),
          bestStreak: Number(d.bestStreak) || 0,
          answered: Number(d.answered) || 0,
          correct: Number(d.correct) || 0,
          concepts: d.concepts ?? {},
          sessions: Array.isArray(d.sessions) ? d.sessions.slice(0, 25) : [],
          settings: { ...DEFAULT_PROGRESS.settings, ...(d.settings ?? {}) },
        })
        persist()
        return null
      } catch {
        return 'Could not read that file: it is not valid JSON.'
      }
    },
    reset() {
      removeKey(KEY)
      set({ ...DEFAULT_PROGRESS, settings: get().settings })
      persist()
    },
  }
})
