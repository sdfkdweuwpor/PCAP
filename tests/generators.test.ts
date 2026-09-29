// Every generator is run against every sample capture; the resulting questions must be valid,
// balanced and answerable.

import { describe, expect, it } from 'vitest'
import { ALL_GENERATORS, buildDeck, buildQuestionBank, grade, validateQuestion } from '../src/game/engine'
import { GenCtx } from '../src/game/generators/context'
import { lengthRatio, makeOptions, balanceOptions } from '../src/game/options'
import { xpFor, rankFor, unlockedModes } from '../src/game/scoring'
import { SAMPLES } from '../src/samples/samples'
import { find, indexOf } from './helpers'

const loaded = SAMPLES.map((s) => {
  const { index, dissect } = indexOf(s.build(), s.fileName)
  return { sample: s, index, dissect, bank: buildQuestionBank(index, dissect, 42) }
})

describe.each(loaded)('$sample.id', ({ index, dissect, bank }) => {
  it('produces at least 15 valid questions across at least 3 modes, with nothing rejected', () => {
    expect(bank.rejected).toEqual([])
    expect(bank.questions.length).toBeGreaterThanOrEqual(15)
    expect(new Set(bank.questions.map((q) => q.mode)).size).toBeGreaterThanOrEqual(3)
    for (const q of bank.questions) expect(validateQuestion(q, index)).toBeNull()
  })

  it('never makes the correct option noticeably longer than the distractors', () => {
    for (const q of bank.questions) {
      if (q.kind !== 'choice') continue
      expect(lengthRatio(q.options)).toBeLessThanOrEqual(1.25)
      const others = q.options.filter((_, i) => i !== q.correct).map((o) => o.length)
      expect(q.options[q.correct].length).toBeLessThanOrEqual(Math.max(...others) * 1.1)
    }
  })

  it('randomises the correct answer position', () => {
    const positions = new Set(bank.questions.filter((q) => q.kind === 'choice').map((q) => (q.kind === 'choice' ? q.correct : -1)))
    if (bank.questions.filter((q) => q.kind === 'choice').length >= 6) expect(positions.size).toBeGreaterThan(1)
  })

  it('grades its own correct answers as correct', () => {
    for (const q of bank.questions) {
      if (q.kind === 'pick') expect(grade(q, { kind: 'pick', packets: q.multi ? q.answer : [q.answer[0]] }).score).toBe(1)
      if (q.kind === 'choice') expect(grade(q, { kind: 'choice', index: q.correct }).score).toBe(1)
      if (q.kind === 'order') expect(grade(q, { kind: 'order', ids: q.cards.map((c) => c.id) }).score).toBe(1)
      if (q.kind === 'field') {
        const layers = dissect(q.packet).layers
        const target = q.targetKeys.map((k) => find(layers, k)).find(Boolean)!
        expect(grade(q, { kind: 'field', key: target.key, via: 'tree' }, layers).score).toBe(1)
        expect(grade(q, { kind: 'field', offset: target.offset, via: 'hex' }, layers).score).toBe(1)
      }
    }
  })

  it('only asks anomaly questions about anomalies the heuristics detected', () => {
    const anomalyQs = bank.questions.filter((q) => q.mode === 'anomaly')
    if (!index.anomalies.length) expect(anomalyQs).toEqual([])
    for (const q of anomalyQs) expect(index.anomalies.some((a) => q.id.endsWith(a.kind))).toBe(true)
  })

  it('builds a story with at least 5 steps and some quick checks', () => {
    expect(bank.story.steps.length).toBeGreaterThanOrEqual(5)
    expect(bank.story.steps.some((s) => s.check)).toBe(true)
  })

  it('never leaks a cleartext secret into prompts, options or explanations', () => {
    const secrets = index.packets.map((p) => p.facts.creds?.secret).filter(Boolean) as string[]
    for (const q of bank.questions) {
      const text = JSON.stringify([q.prompt, q.explanation, q.kind === 'choice' ? q.options : '', q.kind === 'order' ? q.cards : ''])
      for (const s of secrets) expect(text).not.toContain(s)
    }
  })
})

describe('generator coverage', () => {
  it('every generator produces at least one question on some sample', () => {
    for (const g of ALL_GENERATORS) {
      const produced = loaded.some(({ index, dissect }) => g.generate(new GenCtx(index, dissect, () => 0.5)).length > 0)
      expect(produced, `${g.id} (${g.needs}) never fired`).toBe(true)
    }
  })

  it('covers every mode across the samples', () => {
    const modes = new Set(loaded.flatMap((l) => l.bank.questions.map((q) => q.mode)))
    expect([...modes].sort()).toEqual(['anomaly', 'field', 'means', 'order', 'pick', 'says'])
  })
})

describe('grading details', () => {
  const web = loaded.find((l) => l.sample.id === 'web-basic')!
  it('gives partial credit for the right data in the wrong representation', () => {
    const q = web.bank.questions.find((x) => x.kind === 'field' && x.targetKeys[0] === 'dns.qry.name')
    expect(q && q.kind === 'field').toBe(true)
    if (q?.kind !== 'field') return
    const layers = web.dissect(q.packet).layers
    expect(grade(q, { kind: 'field', key: 'dns.qry', via: 'tree' }, layers).score).toBe(0.5)
    expect(grade(q, { kind: 'field', key: 'ip.ttl', via: 'tree' }, layers).score).toBe(0)
  })

  it('scores multi-select picks with partial credit', () => {
    const q = web.bank.questions.find((x) => x.kind === 'pick' && x.multi)
    if (q?.kind !== 'pick') throw new Error('no multi pick')
    expect(grade(q, { kind: 'pick', packets: q.answer.slice(0, 2) }).score).toBe(0.5)
    expect(grade(q, { kind: 'pick', packets: [1] }).score).toBe(0)
  })

  it('decks respect the requested modes and favour weak concepts', () => {
    const deck = buildDeck(web.bank, { modes: ['says'], count: 5, seed: 1 })
    expect(deck.every((q) => q.mode === 'says')).toBe(true)
    let dns = 0
    for (let s = 1; s <= 40; s++) {
      const d = buildDeck(web.bank, { modes: ['pick', 'says', 'means'], count: 4, seed: s, concepts: { dns: { seen: 10, correct: 1 }, http: { seen: 10, correct: 10 }, 'tcp-handshake': { seen: 10, correct: 10 } } })
      dns += d.filter((q) => q.concept === 'dns').length
    }
    let dnsBaseline = 0
    for (let s = 1; s <= 40; s++) dnsBaseline += buildDeck(web.bank, { modes: ['pick', 'says', 'means'], count: 4, seed: s, concepts: { dns: { seen: 10, correct: 10 } } }).filter((q) => q.concept === 'dns').length
    expect(dns).toBeGreaterThan(dnsBaseline)
  })
})

describe('options and scoring', () => {
  it('pads short options so none stands out', () => {
    const out = balanceOptions(['Short answer.', 'A considerably longer answer option.', 'Medium length answer.', 'Another answer here.'])
    expect(out && lengthRatio(out)).toBeLessThanOrEqual(1.25)
    expect(makeOptions('x', ['a', 'b'], Math.random)).toBeNull()
  })

  it('XP scales with tier, speed, streak and hints', () => {
    const slow = xpFor({ tier: 'Analyst', score: 1, seconds: 60, streak: 0, hintUsed: false }).total
    expect(slow).toBe(20)
    expect(xpFor({ tier: 'Analyst', score: 1, seconds: 2, streak: 0, hintUsed: false }).total).toBeGreaterThan(slow)
    expect(xpFor({ tier: 'Analyst', score: 1, seconds: 60, streak: 5, hintUsed: false }).total).toBe(30)
    expect(xpFor({ tier: 'Analyst', score: 1, seconds: 60, streak: 0, hintUsed: true }).total).toBe(10)
    expect(xpFor({ tier: 'Hunter', score: 0, seconds: 1, streak: 9, hintUsed: false }).total).toBe(0)
    expect(rankFor(0).name).toBe('Recruit')
    expect(rankFor(700).name).toBe('Hunter')
    expect(unlockedModes(0).has('anomaly')).toBe(false)
    expect(unlockedModes(0, true).has('anomaly')).toBe(true)
  })
})
