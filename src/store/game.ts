// Game session state: deck, current question, grading, XP/streaks, story mode and blitz.

import { create } from 'zustand'
import { buildDeck, grade } from '../game/engine'
import { rankFor, STREAK_MILESTONES, unlockedModes, xpFor, type Rank, type XpBreakdown } from '../game/scoring'
import type { Answer, Concept, Grade, Mode, Question } from '../game/types'
import { getDissection, useCapture } from './capture'
import { useProgress } from './progress'

export type PlayMode = Mode | 'mixed' | 'blitz'

export interface Result {
  question: Question
  score: number
  xp: number
  seconds: number
  hintUsed: boolean
}

export interface Feedback {
  grade: Grade
  xp: XpBreakdown
  answer: Answer
}

interface GameStore {
  playMode: PlayMode | null
  phase: 'menu' | 'question' | 'feedback' | 'summary' | 'story'
  deck: Question[]
  idx: number
  questionStart: number
  sessionStart: number
  hintUsed: boolean
  feedback: Feedback | null
  streak: number
  sessionBest: number
  sessionXp: number
  results: Result[]
  blitzEndsAt: number | null
  levelUp: Rank | null
  milestone: number | null
  storyIdx: number
  storyChecked: number | null
  /** Pending field selection for Field Hunt. */
  fieldPick: { key?: string; offset?: number; via: 'tree' | 'hex'; name: string } | null

  start: (mode: PlayMode) => void
  current: () => Question | null
  submit: (a: Answer) => void
  useHint: () => void
  next: () => void
  finish: () => void
  toMenu: () => void
  dismissLevelUp: () => void
  setFieldPick: (p: GameStore['fieldPick']) => void
  storyGo: (i: number) => void
  storyCheck: (choice: number) => void
}

const ALL_MODES: Mode[] = ['pick', 'says', 'means', 'field', 'order', 'anomaly']
export const BLITZ_SECONDS = 60

function focusFor(q: Question | null) {
  const cap = useCapture.getState()
  cap.clearMulti()
  cap.selectField(null)
  cap.flashRows(null)
  if (!q) return cap.lock(null)
  if (q.kind === 'field') cap.lock(q.packet)
  else if (q.focusPacket && q.kind === 'choice') {
    cap.lock(null)
    cap.select(q.focusPacket)
  } else {
    cap.lock(null)
    if (q.kind === 'pick') cap.select(null)
  }
  if (q.kind === 'pick' || q.kind === 'field') cap.setTab('packets')
}

export const useGame = create<GameStore>((set, get) => ({
  playMode: null,
  phase: 'menu',
  deck: [],
  idx: 0,
  questionStart: 0,
  sessionStart: 0,
  hintUsed: false,
  feedback: null,
  streak: 0,
  sessionBest: 0,
  sessionXp: 0,
  results: [],
  blitzEndsAt: null,
  levelUp: null,
  milestone: null,
  storyIdx: 0,
  storyChecked: null,
  fieldPick: null,

  start(mode) {
    const bank = useCapture.getState().bank
    if (!bank) return
    const now = Date.now()
    if (mode === 'story') {
      set({ playMode: 'story', phase: 'story', storyIdx: 0, storyChecked: null, results: [], sessionXp: 0, streak: 0, sessionBest: 0, sessionStart: now })
      const first = bank.story.steps[0]
      if (first) useCapture.getState().showMe(first.packet)
      return
    }
    const prog = useProgress.getState()
    const unlocked = unlockedModes(prog.xp, prog.settings.unlockAll)
    const modes =
      mode === 'mixed' || mode === 'blitz'
        ? ALL_MODES.filter((m) => unlocked.has(m) && (m !== 'order' || mode !== 'blitz'))
        : [mode]
    const deck = buildDeck(bank, {
      modes,
      count: mode === 'blitz' ? 40 : mode === 'mixed' ? 12 : 10,
      concepts: useProgress.getState().concepts,
      seed: now,
    })
    set({
      playMode: mode,
      phase: deck.length ? 'question' : 'menu',
      deck,
      idx: 0,
      questionStart: now,
      sessionStart: now,
      hintUsed: false,
      feedback: null,
      streak: 0,
      sessionBest: 0,
      sessionXp: 0,
      results: [],
      blitzEndsAt: mode === 'blitz' ? now + BLITZ_SECONDS * 1000 : null,
      fieldPick: null,
    })
    focusFor(deck[0] ?? null)
  },

  current() {
    const { deck, idx } = get()
    return deck[idx] ?? null
  },

  submit(a) {
    const s = get()
    const q = s.current()
    if (!q || s.phase !== 'question') return
    const layers = q.kind === 'field' ? getDissection(q.packet)?.layers : undefined
    const g = grade(q, a, layers)
    const seconds = (Date.now() - s.questionStart) / 1000
    const streak = g.score >= 1 ? s.streak + 1 : 0
    const xp = xpFor({ tier: q.tier, score: g.score, seconds, streak: s.streak, hintUsed: s.hintUsed })
    const before = rankFor(useProgress.getState().xp)
    useProgress.getState().record(q.concept as Concept, g.score, xp.total, streak)
    const after = rankFor(useProgress.getState().xp)
    const cap = useCapture.getState()
    const answerFrames = q.kind === 'pick' ? q.answer : q.highlight.map((h) => h.packet)
    if (q.kind === 'pick') {
      if (g.score >= 1) cap.flashRows(a.kind === 'pick' ? a.packets : answerFrames, 'correct')
      else {
        cap.flashRows(a.kind === 'pick' ? a.packets : [], 'wrong')
        // After the shake, glide the highlight to the right packet.
        setTimeout(() => {
          useCapture.getState().flashRows(answerFrames, 'answer')
          useCapture.getState().select(answerFrames[0])
        }, 650)
      }
    }
    set({
      phase: 'feedback',
      feedback: { grade: g, xp, answer: a },
      streak,
      sessionBest: Math.max(s.sessionBest, streak),
      sessionXp: s.sessionXp + xp.total,
      results: [...s.results, { question: q, score: g.score, xp: xp.total, seconds, hintUsed: s.hintUsed }],
      levelUp: after.name !== before.name ? after : s.levelUp,
      milestone: STREAK_MILESTONES.includes(streak) ? streak : null,
    })
    // Blitz keeps momentum: auto-advance after a short beat.
    if (s.playMode === 'blitz') setTimeout(() => get().phase === 'feedback' && get().next(), g.score >= 1 ? 700 : 1600)
  },

  useHint() {
    set({ hintUsed: true })
  },

  next() {
    const s = get()
    const blitzOver = s.blitzEndsAt !== null && Date.now() >= s.blitzEndsAt
    if (s.idx + 1 >= s.deck.length || blitzOver) return get().finish()
    const q = s.deck[s.idx + 1]
    set({ idx: s.idx + 1, phase: 'question', feedback: null, hintUsed: false, questionStart: Date.now(), milestone: null, fieldPick: null })
    focusFor(q)
  },

  finish() {
    const s = get()
    const correct = s.results.filter((r) => r.score >= 1).length
    if (s.results.length) {
      useProgress.getState().addSession({
        at: Date.now(),
        file: useCapture.getState().fileName,
        mode: s.playMode ?? 'mixed',
        answered: s.results.length,
        correct,
        xp: s.sessionXp,
        bestStreak: s.sessionBest,
      })
    }
    useCapture.getState().lock(null)
    set({ phase: 'summary', blitzEndsAt: null, feedback: null })
  },

  toMenu() {
    useCapture.getState().lock(null)
    set({ phase: 'menu', playMode: null, deck: [], idx: 0, feedback: null, blitzEndsAt: null, fieldPick: null })
  },

  dismissLevelUp() {
    set({ levelUp: null })
  },

  setFieldPick(p) {
    set({ fieldPick: p })
  },

  storyGo(i) {
    const steps = useCapture.getState().bank?.story.steps ?? []
    const idx = Math.max(0, Math.min(steps.length - 1, i))
    set({ storyIdx: idx, storyChecked: null })
    const st = steps[idx]
    if (st) useCapture.getState().showMe(st.packet)
  },

  storyCheck(choice) {
    const s = get()
    const step = useCapture.getState().bank?.story.steps[s.storyIdx]
    if (!step?.check || s.storyChecked !== null) return
    const ok = choice === step.check.correct
    const streak = ok ? s.streak + 1 : 0
    const xp = xpFor({ tier: step.check.tier, score: ok ? 1 : 0, seconds: 30, streak: s.streak, hintUsed: false })
    const before = rankFor(useProgress.getState().xp)
    useProgress.getState().record(step.check.concept, ok ? 1 : 0, xp.total, streak)
    const after = rankFor(useProgress.getState().xp)
    set({
      storyChecked: choice,
      streak,
      sessionBest: Math.max(s.sessionBest, streak),
      sessionXp: s.sessionXp + xp.total,
      results: [...s.results, { question: step.check, score: ok ? 1 : 0, xp: xp.total, seconds: 0, hintUsed: false }],
      levelUp: after.name !== before.name ? after : s.levelUp,
      milestone: STREAK_MILESTONES.includes(streak) ? streak : null,
    })
  },
}))
