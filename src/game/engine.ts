// Question engine: runs every generator against a capture, validates the results, grades answers
// and assembles decks weighted toward the learner's weak concepts.

import type { CaptureIndex, Dissection, Field } from '../core/types'
import { anomalyGenerators } from './generators/anomaly'
import { GenCtx, type Generator } from './generators/context'
import { fieldGenerators } from './generators/field'
import { meansGenerators } from './generators/means'
import { orderGenerators } from './generators/order'
import { pickGenerators } from './generators/pick'
import { saysGenerators } from './generators/says'
import { buildStory } from './generators/story'
import { filterGenerators, gradeFilter, matchSet } from './generators/filters'
import { gradeText, typedGenerators } from './generators/typed'
import { correctNotLongest, lengthRatio, MAX_LENGTH_RATIO, shuffle } from './options'
import type { Answer, Concept, Grade, Mode, Question, Story } from './types'

export const ALL_GENERATORS: Generator[] = [
  ...pickGenerators,
  ...saysGenerators,
  ...meansGenerators,
  ...fieldGenerators,
  ...orderGenerators,
  ...anomalyGenerators,
  ...typedGenerators,
  ...filterGenerators,
]

export interface QuestionBank {
  questions: Question[]
  story: Story
  rejected: { id: string; reason: string }[]
}

export function buildQuestionBank(index: CaptureIndex, dissect: (no: number) => Dissection, seed = 1): QuestionBank {
  const rng = seeded(seed)
  const ctx = new GenCtx(index, dissect, rng)
  const questions: Question[] = []
  const rejected: QuestionBank['rejected'] = []
  const seen = new Set<string>()
  for (const g of ALL_GENERATORS) {
    let qs: Question[] = []
    try {
      qs = g.generate(ctx)
    } catch (e) {
      rejected.push({ id: g.id, reason: `generator threw: ${e instanceof Error ? e.message : e}` })
      continue
    }
    for (const q of qs) {
      const err = validateQuestion(q, index)
      if (err) rejected.push({ id: q.id, reason: err })
      else if (!seen.has(q.id)) {
        seen.add(q.id)
        questions.push(q)
      }
    }
  }
  let story: Story
  try {
    story = buildStory(ctx)
  } catch {
    story = { id: 'story', title: 'Walkthrough', steps: [] }
  }
  return { questions, story, rejected }
}

export function validateQuestion(q: Question, index: CaptureIndex): string | null {
  const n = index.packets.length
  const okFrame = (f: number) => Number.isInteger(f) && f >= 1 && f <= n
  if (!q.prompt || !q.explanation.says || !q.explanation.means || !q.explanation.matters) return 'missing text'
  for (const h of q.highlight) if (!okFrame(h.packet)) return `bad highlight frame ${h.packet}`
  switch (q.kind) {
    case 'pick':
      if (!q.answer.length || !q.answer.every(okFrame)) return 'bad answer frames'
      if (q.multi && q.answer.length < 2) return 'multi-select with one answer'
      return null
    case 'choice':
      if (q.options.length !== 4) return 'needs 4 options'
      if (new Set(q.options).size !== 4) return 'duplicate options'
      if (q.correct < 0 || q.correct > 3) return 'bad correct index'
      if (lengthRatio(q.options) > MAX_LENGTH_RATIO) return `options unbalanced (${lengthRatio(q.options).toFixed(2)})`
      if (!correctNotLongest(q.options, q.correct)) return 'correct option is noticeably the longest'
      return null
    case 'field':
      if (!okFrame(q.packet) || !q.targetKeys.length) return 'bad field target'
      return null
    case 'order':
      if (q.cards.length < 3) return 'too few cards'
      if (!q.cards.every((c) => okFrame(c.packet))) return 'bad card frame'
      for (let i = 1; i < q.cards.length; i++) if (q.cards[i].packet <= q.cards[i - 1].packet) return 'cards not in wire order'
      return null
    case 'text':
      if (!q.accept.length || q.accept.some((a) => !a.trim())) return 'no accepted answers'
      if (gradeText(q, q.accept[0]).score !== 1) return 'canonical answer does not grade as correct'
      return null
    case 'filter': {
      if (!q.target.length || !q.target.every(okFrame)) return 'bad filter target'
      const got = matchSet(index, q.reference)
      if (got.length !== q.target.length || got.some((x, i) => x !== q.target[i])) return 'reference filter does not match target'
      return null
    }
  }
}

// ---------------------------------------------------------------- grading

function walk(fs: Field[], f: (x: Field, parent: Field | null) => void, parent: Field | null = null) {
  for (const x of fs) {
    f(x, parent)
    if (x.children) walk(x.children, f, x)
  }
}

/** Deepest field (excluding whole-frame) containing a byte offset — the "owning field" of a hex byte. */
export function fieldAtOffset(layers: Field[], offset: number): Field | undefined {
  let best: Field | undefined
  walk(layers, (x) => {
    if (x.key === 'frame' || x.length <= 0) return
    if (offset >= x.offset && offset < x.offset + x.length) {
      if (!best || x.length <= best.length) best = x
    }
  })
  return best
}

export function findByKey(layers: Field[], key: string): Field | undefined {
  let hit: Field | undefined
  walk(layers, (x) => {
    if (!hit && x.key === key) hit = x
  })
  return hit
}

export function grade(q: Question, a: Answer, layers?: Field[], index?: CaptureIndex): Grade {
  switch (q.kind) {
    case 'pick': {
      if (a.kind !== 'pick') return { score: 0, feedback: 'No packet selected.' }
      if (q.multi) {
        const want = new Set(q.answer)
        const got = new Set(a.packets)
        const hits = [...got].filter((x) => want.has(x)).length
        if (hits === want.size && got.size === want.size) return { score: 1, feedback: 'Exactly right.' }
        if (hits >= Math.ceil(want.size / 2) && got.size <= want.size + 1)
          return { score: 0.5, feedback: `You found ${hits} of ${want.size} and picked ${got.size - hits} extra.` }
        return { score: 0, feedback: `You found ${hits} of ${want.size}.` }
      }
      const ok = a.packets.length === 1 && q.answer.includes(a.packets[0])
      return { score: ok ? 1 : 0, feedback: ok ? 'That’s the one.' : 'Not that packet.' }
    }
    case 'choice': {
      if (a.kind !== 'choice') return { score: 0, feedback: 'No option selected.' }
      const ok = a.index === q.correct
      return { score: ok ? 1 : 0, feedback: ok ? 'Correct.' : 'Not quite.' }
    }
    case 'field': {
      if (a.kind !== 'field' || !layers) return { score: 0, feedback: 'No field selected.' }
      const target = q.targetKeys.map((k) => findByKey(layers, k)).find(Boolean)
      let clicked: Field | undefined
      if (a.key) clicked = findByKey(layers, a.key)
      if (a.offset !== undefined && (!clicked || a.via === 'hex')) clicked = fieldAtOffset(layers, a.offset)
      if (!clicked) return { score: 0, feedback: 'No field selected.' }
      if (clicked.key && q.targetKeys.includes(clicked.key)) return { score: 1, feedback: `Yes — that is the ${q.targetLabel}.` }
      // A hex click inside the target's bytes counts as correct even if a child field owns the byte.
      if (target && a.offset !== undefined && a.offset >= target.offset && a.offset < target.offset + target.length)
        return { score: 1, feedback: `Yes — those bytes are the ${q.targetLabel}.` }
      if (clicked.key && q.partialKeys.includes(clicked.key))
        return { score: 0.5, feedback: `Close: the ${q.targetLabel} is in there, but you picked "${clicked.name}". Partial credit.` }
      if (target && clicked.key !== 'frame' && clicked.children?.length && contains(clicked, target) && clicked.length <= target.length * 6)
        return { score: 0.5, feedback: `Close: "${clicked.name}" contains the ${q.targetLabel}. Partial credit.` }
      return { score: 0, feedback: `That is "${clicked.name}", not the ${q.targetLabel}.` }
    }
    case 'text': {
      if (a.kind !== 'text') return { score: 0, feedback: 'Nothing typed.' }
      const r = gradeText(q, a.text)
      return { score: r.score, feedback: r.score ? r.note || 'Exactly right.' : `Expected ${q.accept[0]}.` }
    }
    case 'filter': {
      if (a.kind !== 'filter' || !index) return { score: 0, feedback: 'No filter submitted.' }
      try {
        const r = gradeFilter(q, index, a.text)
        return { score: r.score, feedback: r.note }
      } catch (e) {
        return { score: 0, feedback: e instanceof Error ? e.message : 'Invalid filter.' }
      }
    }
    case 'order': {
      if (a.kind !== 'order') return { score: 0, feedback: 'No order submitted.' }
      const want = q.cards.map((c) => c.id)
      const correctPositions = a.ids.filter((id, i) => want[i] === id).length
      if (correctPositions === want.length) return { score: 1, feedback: 'Perfect order.' }
      if (correctPositions >= want.length - 2 && want.length >= 5)
        return { score: 0.5, feedback: `${correctPositions} of ${want.length} in the right place.` }
      return { score: 0, feedback: `${correctPositions} of ${want.length} in the right place.` }
    }
  }
}

function contains(outer: Field, inner: Field): boolean {
  return inner.offset >= outer.offset && inner.offset + inner.length <= outer.offset + outer.length
}

// ---------------------------------------------------------------- decks

export interface ConceptStat {
  seen: number
  correct: number
}

export interface DeckOptions {
  modes: Mode[]
  count: number
  concepts?: Partial<Record<Concept, ConceptStat>>
  seed?: number
  exclude?: Set<string>
}

/** Weight: unseen concepts 1.5, weak concepts (low accuracy) up to 3, mastered ones 0.6. */
export function conceptWeight(stat?: ConceptStat): number {
  if (!stat || stat.seen === 0) return 1.5
  const acc = stat.correct / stat.seen
  return Math.max(0.6, 1 + (1 - acc) * 2 - Math.min(stat.seen, 10) * 0.02)
}

export function buildDeck(bank: QuestionBank, o: DeckOptions): Question[] {
  const rng = seeded(o.seed ?? Date.now())
  const pool = bank.questions.filter((q) => o.modes.includes(q.mode) && !o.exclude?.has(q.id))
  // Weighted sampling without replacement (Efraimidis–Spirakis).
  const keyed = pool.map((q) => ({ q, k: Math.pow(rng(), 1 / conceptWeight(o.concepts?.[q.concept])) }))
  keyed.sort((a, b) => b.k - a.k)
  const chosen = keyed.slice(0, o.count).map((x) => x.q)
  // Gentle difficulty ramp: Recruit first, Hunter last, randomised within tiers.
  const tierRank = { Recruit: 0, Analyst: 1, Hunter: 2 }
  return shuffle(chosen, rng).sort((a, b) => tierRank[a.tier] - tierRank[b.tier])
}

export function seeded(seed: number): () => number {
  let a = seed >>> 0 || 1
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
