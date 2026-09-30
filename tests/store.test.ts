// Zustand stores driven directly (no DOM, no worker): story-mode bookkeeping and progress sanitising.
// useCapture is populated with setState (bypassing loadBytes, which needs the parser worker).

import { beforeEach, describe, expect, it } from 'vitest'
import { buildQuestionBank } from '../src/game/engine'
import { BASE_XP } from '../src/game/scoring'
import { CONCEPT_LABEL } from '../src/game/types'
import { SAMPLES } from '../src/samples/samples'
import { useCapture } from '../src/store/capture'
import { useGame } from '../src/store/game'
import { DEFAULT_PROGRESS, sanitizeProgress, useProgress } from '../src/store/progress'
import { indexOf } from './helpers'

function loadSample(id: string) {
  const s = SAMPLES.find((x) => x.id === id)!
  const bytes = s.build()
  const { index, dissect } = indexOf(bytes, s.fileName)
  const bank = buildQuestionBank(index, dissect, 42)
  useCapture.setState({ status: 'ready', index, bytes, bank, fileName: s.fileName, selected: null, lockedTo: null })
  return { index, bank }
}

function resetStores() {
  useProgress.setState({ ...DEFAULT_PROGRESS, storageOk: true })
  useGame.setState({
    playMode: null,
    phase: 'menu',
    deck: [],
    idx: 0,
    feedback: null,
    streak: 0,
    sessionBest: 0,
    sessionXp: 0,
    results: [],
    levelUp: null,
    milestone: null,
    storyIdx: 0,
    storyChecked: null,
    storyAnswers: {},
  })
}

describe('story mode', () => {
  beforeEach(() => {
    resetStores()
    loadSample('web-basic')
  })

  const game = () => useGame.getState()
  const progress = () => useProgress.getState()
  const steps = () => useCapture.getState().bank!.story.steps
  /** Story steps that carry a quick check, with their index. */
  const checked = () => steps().flatMap((st, i) => (st.check ? [{ st, i, check: st.check }] : []))

  it('web-basic has at least two quick-check steps to work with', () => {
    expect(checked().length).toBeGreaterThanOrEqual(2)
  })

  it('start("story") begins at step 0 with nothing answered and the first packet shown', () => {
    game().start('story')
    expect(game()).toMatchObject({ phase: 'story', playMode: 'story', storyIdx: 0, storyChecked: null, storyAnswers: {}, results: [], sessionXp: 0, streak: 0 })
    expect(useCapture.getState().selected).toBe(steps()[0].packet)
  })

  it('answering, navigating away and back restores the choice; checking again pays nothing and adds no result', () => {
    const { i, check } = checked()[0]
    game().start('story')
    game().storyGo(i)
    expect(game().storyIdx).toBe(i)
    expect(game().storyChecked).toBeNull()
    expect(useCapture.getState().selected).toBe(steps()[i].packet)

    // Answer correctly.
    game().storyCheck(check.correct)
    const after = game()
    const xp = BASE_XP[check.tier] // 30 s answer time: no speed bonus; first in a streak: no streak bonus
    expect(after.storyChecked).toBe(check.correct)
    expect(after.storyAnswers).toEqual({ [i]: check.correct })
    expect(after.results).toHaveLength(1)
    expect(after.results[0]).toMatchObject({ score: 1, xp, seconds: 0, hintUsed: false })
    expect(after.results[0].question).toBe(check)
    expect(after.sessionXp).toBe(xp)
    expect(after.streak).toBe(1)
    expect(progress().xp).toBe(xp)
    expect(progress().answered).toBe(1)
    expect(progress().correct).toBe(1)
    expect(progress().concepts[check.concept]).toEqual({ seen: 1, correct: 1 })

    // Navigate to a different step: nothing is selected there, unless it was answered too.
    const elsewhere = steps().findIndex((_, k) => k !== i && !checked().some((c) => c.i === k))
    expect(elsewhere).toBeGreaterThanOrEqual(0)
    game().storyGo(elsewhere)
    expect(game().storyIdx).toBe(elsewhere)
    expect(game().storyChecked).toBeNull()

    // Come back: the previous choice is restored.
    game().storyGo(i)
    expect(game().storyChecked).toBe(check.correct)

    // Checking again (same or a different choice) changes nothing.
    for (const again of [check.correct, (check.correct + 1) % 4, (check.correct + 2) % 4]) {
      game().storyCheck(again)
      expect(game().storyChecked).toBe(check.correct)
      expect(game().storyAnswers).toEqual({ [i]: check.correct })
      expect(game().results).toHaveLength(1)
      expect(game().sessionXp).toBe(xp)
      expect(game().streak).toBe(1)
      expect(progress().xp).toBe(xp)
      expect(progress().answered).toBe(1)
      expect(progress().concepts[check.concept]).toEqual({ seen: 1, correct: 1 })
    }
  })

  it('a wrong answer earns nothing, resets the streak, and is what comes back when the step is revisited', () => {
    const [a, b] = checked()
    game().start('story')
    game().storyGo(a.i)
    game().storyCheck(a.check.correct)
    const xpAfterA = game().sessionXp
    expect(game().streak).toBe(1)

    game().storyGo(b.i)
    const wrong = (b.check.correct + 1) % 4
    game().storyCheck(wrong)
    expect(game().storyChecked).toBe(wrong)
    expect(game().results).toHaveLength(2)
    expect(game().results[1]).toMatchObject({ score: 0, xp: 0 })
    expect(game().sessionXp).toBe(xpAfterA) // 0 XP for the wrong one
    expect(game().streak).toBe(0)
    expect(game().sessionBest).toBe(1)
    expect(progress().answered).toBe(2)
    expect(progress().correct).toBe(1)
    expect(progress().xp).toBe(xpAfterA)

    // Away and back: the wrong choice is restored, and it cannot be retried for credit.
    game().storyGo(a.i)
    expect(game().storyChecked).toBe(a.check.correct)
    game().storyGo(b.i)
    expect(game().storyChecked).toBe(wrong)
    game().storyCheck(b.check.correct)
    expect(game().storyChecked).toBe(wrong)
    expect(game().results).toHaveLength(2)
    expect(game().sessionXp).toBe(xpAfterA)
    expect(progress().answered).toBe(2)
    expect(game().storyAnswers).toEqual({ [a.i]: a.check.correct, [b.i]: wrong })
  })

  it('steps without a check ignore storyCheck', () => {
    const plain = steps().findIndex((st) => !st.check)
    expect(plain).toBeGreaterThanOrEqual(0)
    game().start('story')
    game().storyGo(plain)
    game().storyCheck(0)
    expect(game().storyChecked).toBeNull()
    expect(game().storyAnswers).toEqual({})
    expect(game().results).toHaveLength(0)
    expect(progress().answered).toBe(0)
  })

  it('storyGo clamps to the first and last step', () => {
    game().start('story')
    game().storyGo(-5)
    expect(game().storyIdx).toBe(0)
    game().storyGo(9999)
    expect(game().storyIdx).toBe(steps().length - 1)
  })

  it('starting the story again forgets the earlier answers', () => {
    const { i, check } = checked()[0]
    game().start('story')
    game().storyGo(i)
    game().storyCheck(check.correct)
    expect(game().storyChecked).toBe(check.correct)
    game().start('story')
    expect(game().storyAnswers).toEqual({})
    expect(game().storyChecked).toBeNull()
    game().storyGo(i)
    expect(game().storyChecked).toBeNull()
    expect(game().results).toHaveLength(0)
  })
})

describe('sanitizeProgress', () => {
  const CONCEPTS = Object.keys(CONCEPT_LABEL)

  it('turns garbage into a valid Progress: numeric xp >= 0, known concepts only, a valid theme, boolean settings', () => {
    const p = sanitizeProgress({ xp: 'lots', concepts: { evil: { seen: 5, correct: 5 } }, settings: { theme: 'neon' } })
    expect(p.version).toBe(1)
    expect(p.xp).toBe(0)
    expect(p.concepts).toEqual({})
    expect(['dark', 'paper']).toContain(p.settings.theme)
    expect(p.settings.theme).toBe('paper')
    for (const k of ['crt', 'unlockAll', 'showTimer', 'hotkeys', 'aiExplain'] as const) expect(typeof p.settings[k], k).toBe('boolean')
    expect(p).toEqual(DEFAULT_PROGRESS)
  })

  it('accepts non-objects and returns the defaults', () => {
    for (const raw of [undefined, null, 'lots', 42, true, [], [1, 2, 3]]) expect(sanitizeProgress(raw), String(raw)).toEqual(DEFAULT_PROGRESS)
  })

  it('migrates legacy themes: amber/green -> dark, light -> paper; valid themes are kept', () => {
    expect(sanitizeProgress({ settings: { theme: 'amber' } }).settings.theme).toBe('dark')
    expect(sanitizeProgress({ settings: { theme: 'green' } }).settings.theme).toBe('dark')
    expect(sanitizeProgress({ settings: { theme: 'light' } }).settings.theme).toBe('paper')
    expect(sanitizeProgress({ settings: { theme: 'dark' } }).settings.theme).toBe('dark')
    expect(sanitizeProgress({ settings: { theme: 'paper' } }).settings.theme).toBe('paper')
    expect(sanitizeProgress({ settings: { theme: 'DARK' } }).settings.theme).toBe('paper') // not a known spelling: default
    expect(sanitizeProgress({ settings: { theme: 3 } }).settings.theme).toBe('paper')
  })

  it('clamps numbers and validates every section', () => {
    const many = Array.from({ length: 30 }, (_, k) => ({ at: 1000 + k, file: `f${k}.pcap`, mode: 'pick', answered: 10, correct: 7, xp: 50, bestStreak: 3 }))
    const p = sanitizeProgress({
      xp: -50,
      bestStreak: 'x',
      answered: 10,
      correct: 99,
      concepts: {
        dns: { seen: 4, correct: 99 },
        http: { seen: 0, correct: 3 },
        tls: 'yes',
        arp: null,
        udp: { seen: 2.9, correct: 1.5 },
        evil: { seen: 5, correct: 5 },
      },
      sessions: [null, 5, 'x', { at: 'x', file: 123, mode: 'm'.repeat(50), answered: -2, correct: 'z' }, ...many],
      drill: { bestWpm: 9999, bestAccuracy: 7, runs: -4 },
      settings: { theme: 'dark', crt: 'yes', reduceMotion: 'weird', unlockAll: 1, showTimer: false, hotkeys: null, aiExplain: true },
    })
    expect(p.xp).toBe(0)
    expect(p.bestStreak).toBe(0)
    expect(p.answered).toBe(10)
    expect(p.correct).toBe(10) // never more correct than answered
    expect(p.concepts).toEqual({ dns: { seen: 4, correct: 4 }, udp: { seen: 2, correct: 1.5 } })
    expect(p.sessions).toHaveLength(25)
    expect(p.sessions[0]).toEqual({ at: 0, file: '123', mode: 'm'.repeat(20), answered: 0, correct: 0, xp: 0, bestStreak: 0 })
    expect(p.sessions[1]).toEqual(many[0])
    expect(p.drill).toEqual({ bestWpm: 400, bestAccuracy: 1, runs: 0 })
    expect(p.settings).toEqual({ theme: 'dark', crt: true, reduceMotion: 'system', unlockAll: false, showTimer: false, hotkeys: true, aiExplain: true })
  })

  it('keeps a valid Progress unchanged (idempotent) and clamps xp at 1e9', () => {
    const valid = {
      ...DEFAULT_PROGRESS,
      xp: 1234,
      bestStreak: 7,
      answered: 40,
      correct: 31,
      concepts: { dns: { seen: 8, correct: 6.5 }, tls: { seen: 3, correct: 3 } },
      sessions: [{ at: 5, file: 'a.pcap', mode: 'mixed', answered: 12, correct: 9, xp: 100, bestStreak: 4 }],
      drill: { bestWpm: 55, bestAccuracy: 0.97, runs: 3 },
      settings: { theme: 'paper' as const, crt: false, reduceMotion: 'on' as const, unlockAll: true, showTimer: false, hotkeys: false, aiExplain: true },
    }
    expect(sanitizeProgress(valid)).toEqual(valid)
    expect(sanitizeProgress(sanitizeProgress(valid))).toEqual(valid)
    expect(sanitizeProgress({ xp: 1e12 }).xp).toBe(1e9)
    expect(sanitizeProgress({ xp: '250' }).xp).toBe(250)
    expect(sanitizeProgress({ xp: 12.9 }).xp).toBe(12)
    expect(sanitizeProgress({ xp: NaN }).xp).toBe(0)
    expect(sanitizeProgress({ xp: Infinity }).xp).toBe(0)
  })

  it('every real concept key survives', () => {
    const concepts = Object.fromEntries(CONCEPTS.map((c) => [c, { seen: 2, correct: 1 }]))
    expect(Object.keys(sanitizeProgress({ concepts }).concepts).sort()).toEqual([...CONCEPTS].sort())
  })

  // Regression (found by this audit, since fixed in src/store/progress.ts line 86): `k in CONCEPT_LABEL` was true for inherited
  // Object.prototype names, so "constructor" / "toString" / "hasOwnProperty" passed as known concepts (the check is now
  // Object.hasOwn). Input: JSON.parse('{"concepts":{"constructor":{"seen":3,"correct":1},"toString":{"seen":2,"correct":1}}}').
  // Before the fix the result kept both keys, and ModeMenu.tsx:72-79 / SettingsDialog.tsx:219 then called
  // CONCEPT_LABEL[c].toLowerCase(), which throws (Object.toLowerCase is not a function); importJSON also persisted them.
  it('drops concept keys that only exist on Object.prototype ("constructor", "toString", "__proto__")', () => {
    const raw = JSON.parse(
      '{"concepts":{"constructor":{"seen":3,"correct":1},"toString":{"seen":2,"correct":1},"hasOwnProperty":{"seen":4,"correct":4},"__proto__":{"seen":5,"correct":5},"dns":{"seen":2,"correct":1}}}',
    )
    const p = sanitizeProgress(raw)
    expect(Object.keys(p.concepts)).toEqual(['dns'])
    for (const k of Object.keys(p.concepts)) expect(Object.hasOwn(CONCEPT_LABEL, k)).toBe(true)
  })

  it('does not pollute Object.prototype', () => {
    sanitizeProgress(JSON.parse('{"concepts":{"__proto__":{"seen":5,"correct":5}},"settings":{"__proto__":{"crt":false}}}'))
    expect(({} as Record<string, unknown>).seen).toBeUndefined()
    expect(({} as Record<string, unknown>).crt).toBeUndefined()
  })
})

describe('useProgress import / export', () => {
  beforeEach(resetStores)
  const store = () => useProgress.getState()

  it('rejects text that is not JSON or not a progress export, leaving the state alone', () => {
    store().record('dns', 1, 10, 1)
    expect(store().importJSON('{ not json')).toBe('Could not read that file: it is not valid JSON.')
    expect(store().importJSON('[1,2]')).toBe('That file does not look like a PacketQuest progress export.')
    expect(store().importJSON('{"xp":"lots"}')).toBe('That file does not look like a PacketQuest progress export.')
    expect(store().xp).toBe(10)
  })

  it('a hostile import is sanitised before it reaches the store', () => {
    expect(store().importJSON(JSON.stringify({ xp: 500, concepts: { evil: { seen: 9, correct: 9 }, dns: { seen: 3, correct: 2 } }, settings: { theme: 'neon', crt: 'sure' } }))).toBeNull()
    expect(store().xp).toBe(500)
    expect(store().concepts).toEqual({ dns: { seen: 3, correct: 2 } })
    expect(store().settings.theme).toBe('paper')
    expect(store().settings.crt).toBe(true)
  })

  it('export then import round-trips', () => {
    store().record('dns', 1, 25, 1)
    store().record('tls', 0.5, 0, 0)
    store().setSettings({ theme: 'paper', hotkeys: false })
    const json = store().exportJSON()
    const before = JSON.parse(json)
    expect(before.app).toBe('PacketQuest')
    resetStores()
    expect(store().xp).toBe(0)
    expect(store().importJSON(json)).toBeNull()
    expect(store().xp).toBe(25)
    expect(store().answered).toBe(2)
    expect(store().correct).toBe(1)
    expect(store().concepts).toEqual({ dns: { seen: 1, correct: 1 }, tls: { seen: 1, correct: 0.5 } })
    expect(store().settings).toMatchObject({ theme: 'paper', hotkeys: false })
    expect(JSON.parse(store().exportJSON())).toEqual(before)
  })
})
