// Every generator is run against every sample capture; the resulting questions must be valid,
// balanced and answerable.

import { describe, expect, it } from 'vitest'
import type { CaptureIndex } from '../src/core/types'
import { writePcap } from '../src/core/pcap/writer'
import { ALL_GENERATORS, buildDeck, buildQuestionBank, grade, seeded, validateQuestion } from '../src/game/engine'
import { GenCtx } from '../src/game/generators/context'
import { lengthRatio, makeOptions, balanceOptions, correctNotLongest } from '../src/game/options'
import { xpFor, rankFor, unlockedModes } from '../src/game/scoring'
import type { PickQuestion } from '../src/game/types'
import { TcpSession, Timeline, dnsQuery, dnsResponse, icmpEcho, mulberry32, tlsClientHello, tlsServerHello, udp, type Host } from '../src/samples/builder'
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

  it('never makes the correct option more than 3 characters longer than the longest distractor (questions and story checks)', () => {
    const choices = [...bank.questions, ...bank.story.steps.map((st) => st.check)].filter((q) => q?.kind === 'choice')
    expect(choices.length).toBeGreaterThan(0)
    for (const q of choices) {
      if (q?.kind !== 'choice') continue
      const distractors = q.options.filter((_, i) => i !== q.correct)
      expect(distractors, q.id).toHaveLength(3)
      expect(new Set(q.options).size, `${q.id}: duplicate options`).toBe(4)
      expect(q.options[q.correct].length, `${q.id}: ${JSON.stringify(q.options)}`).toBeLessThanOrEqual(Math.max(...distractors.map((o) => o.length)) + 3)
      expect(correctNotLongest(q.options, q.correct), q.id).toBe(true)
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
      if (q.kind === 'text') expect(grade(q, { kind: 'text', text: q.accept[0] }).score, q.id).toBe(1)
      if (q.kind === 'filter') expect(grade(q, { kind: 'filter', text: q.reference }, undefined, index).score, q.id).toBe(1)
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
    expect([...modes].sort()).toEqual(['anomaly', 'field', 'filter', 'means', 'order', 'pick', 'says', 'type'])
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

// ---------------------------------------------------------------- audit regressions

/** A hand-built pick question for exercising grade() in isolation. */
function pq(answer: number[], multi: boolean): PickQuestion {
  return {
    id: 'pick.test',
    mode: 'pick',
    kind: 'pick',
    tier: 'Analyst',
    concept: 'tcp-handshake',
    prompt: 'p',
    hint: 'h',
    explanation: { says: 's', means: 'm', matters: 'x' },
    highlight: answer.map((packet) => ({ packet })),
    answer,
    multi,
  }
}
const pickScore = (q: PickQuestion, packets: number[]) => grade(q, { kind: 'pick', packets }).score

describe('grade(): multi-select picks', () => {
  const three = pq([3, 4, 5], true)

  it('1 for exactly the right set (order and repeats do not matter)', () => {
    expect(pickScore(three, [3, 4, 5])).toBe(1)
    expect(pickScore(three, [5, 3, 4])).toBe(1)
    expect(pickScore(three, [3, 3, 4, 5])).toBe(1)
    expect(grade(three, { kind: 'pick', packets: [3, 4, 5] }).feedback).toBe('Exactly right.')
  })

  it('0.5 only when hits >= ceil(want / 2) AND at most 1 extra pick', () => {
    // want = 3 -> need at least 2 hits.
    expect(pickScore(three, [3, 4])).toBe(0.5) // 2 hits, 0 extra
    expect(pickScore(three, [3, 4, 9])).toBe(0.5) // 2 hits, 1 extra
    expect(pickScore(three, [3, 4, 5, 9])).toBe(0.5) // all found but 1 extra
    expect(grade(three, { kind: 'pick', packets: [3, 4, 9] }).feedback).toBe('You found 2 of 3 and picked 1 extra.')
    expect(pickScore(three, [3, 4, 9, 10])).toBe(0) // 2 hits + 2 wrong: too many extras
    expect(pickScore(three, [3, 4, 5, 9, 10])).toBe(0) // everything found but 2 extras
    expect(grade(three, { kind: 'pick', packets: [3, 4, 9, 10] }).feedback).toBe('You found 2 of 3.')
    expect(pickScore(three, [3])).toBe(0) // 1 hit < 2
    expect(pickScore(three, [3, 9])).toBe(0) // 1 hit, 1 extra
    expect(pickScore(three, [9, 10, 11])).toBe(0)
    expect(pickScore(three, [])).toBe(0)
  })

  it('the hit threshold is ceil(want / 2) for other sizes', () => {
    const four = pq([1, 2, 3, 4], true) // ceil(4/2) = 2
    expect(pickScore(four, [1, 2])).toBe(0.5)
    expect(pickScore(four, [1])).toBe(0)
    expect(pickScore(four, [1, 2, 9, 10])).toBe(0) // 2 extras
    const five = pq([1, 2, 3, 4, 5], true) // ceil(5/2) = 3
    expect(pickScore(five, [1, 2])).toBe(0)
    expect(pickScore(five, [1, 2, 3])).toBe(0.5)
    expect(pickScore(five, [1, 2, 3, 9])).toBe(0.5)
    expect(pickScore(five, [1, 2, 3, 9, 10])).toBe(0)
  })

  it('a single-select pick is all or nothing', () => {
    const one = pq([7, 9], false) // two packets qualify
    expect(pickScore(one, [7])).toBe(1)
    expect(pickScore(one, [9])).toBe(1)
    expect(pickScore(one, [7, 9])).toBe(0)
    expect(pickScore(one, [8])).toBe(0)
    expect(pickScore(one, [])).toBe(0)
  })

  it('on the web-basic handshake question', () => {
    const q = loaded.find((l) => l.sample.id === 'web-basic')!.bank.questions.find((x) => x.id === 'pick.handshake:1') as PickQuestion
    expect(q.answer).toEqual([3, 4, 5])
    expect(pickScore(q, [3, 4, 5])).toBe(1)
    expect(pickScore(q, [3, 4, 6, 7])).toBe(0) // 2 right + 2 wrong
    expect(pickScore(q, [3, 4, 6])).toBe(0.5) // 2 right + 1 wrong
  })
})

describe('makeOptions padding', () => {
  const rng = () => 0.3
  const LONG = ['A considerably longer distractor option here.', 'Another rather long distractor text now.', 'Third quite long distractor answer ok.']

  /** The distractors that came back unchanged vs. padded (not one of the originals). */
  const carriesPad = (option: string, originals: string[]) => !originals.includes(option)

  it('pads a short correct answer too, instead of leaving it as the one unpadded option', () => {
    const r = makeOptions('Yes.', LONG, rng)
    // Either the question is dropped or every short option was padded, including the correct one.
    expect(r).not.toBeNull()
    const correct = r!.options[r!.correct]
    expect(correct).not.toBe('Yes.')
    expect(correct).toMatch(/^Yes .*\.$/) // "Yes at this point in the conversation."
    expect(lengthRatio(r!.options)).toBeLessThanOrEqual(1.25)
    expect(correctNotLongest(r!.options, r!.correct)).toBe(true)
  })

  it('a long correct answer with short distractors is dropped (null) rather than leaving only the distractors padded', () => {
    expect(makeOptions('The server replies with an error code and closes the socket.', ['The server sends data now.', 'The client resets it.', 'A third statement here.'], rng)).toBeNull()
    expect(makeOptions('The server replies with an error code.', ['The server sends data now again.', 'The client resets it, again.', 'A third statement here.'], rng)).toBeNull()
  })

  it('leaves already-balanced options alone', () => {
    const d = ['The server opens a connection.', 'The client closes a connection.', 'The client resets a connection.']
    const r = makeOptions('The client opens a connection.', d, seeded(1))!
    expect([...r.options].sort()).toEqual(['The client opens a connection.', ...d].sort())
    expect(r.options[r.correct]).toBe('The client opens a connection.')
  })

  it('returns null with fewer than three distinct distractors (repeats and the correct answer itself do not count)', () => {
    expect(makeOptions('x', ['a', 'b'], rng)).toBeNull()
    expect(makeOptions('x', ['a', 'b', 'b'], rng)).toBeNull()
    expect(makeOptions('x', ['a', 'b', 'x'], rng)).toBeNull()
  })

  it('property: over 3000 random statement sets the invariants hold whenever a question is produced', () => {
    const r = seeded(99)
    const words = 'the client server opens closes sends replies packet connection request response asks agrees port address name lookup handshake finished data error resets to a an of and for'.split(' ')
    const sentence = (n: number) => {
      const s = Array.from({ length: n }, () => words[Math.floor(r() * words.length)]).join(' ')
      return s[0].toUpperCase() + s.slice(1) + '.'
    }
    let produced = 0
    let padded = 0
    for (let i = 0; i < 3000; i++) {
      const correct = sentence(3 + Math.floor(r() * 9))
      const distractors = [0, 1, 2].map(() => sentence(3 + Math.floor(r() * 9)))
      const res = makeOptions(correct, distractors, r)
      if (!res) continue
      produced++
      const c = res.options[res.correct]
      const others = res.options.filter((_, j) => j !== res.correct)
      const ctx = JSON.stringify({ correct, distractors, options: res.options })
      expect(res.options, ctx).toHaveLength(4)
      expect(new Set(res.options).size, ctx).toBe(4)
      expect(lengthRatio(res.options), ctx).toBeLessThanOrEqual(1.25)
      // The correct option is never more than 3 characters longer than the longest distractor.
      expect(c.length, ctx).toBeLessThanOrEqual(Math.max(...others.map((o) => o.length)) + 3)
      // Never "only the distractors carry a pad": if any distractor was padded, the correct answer was too.
      const distractorPadded = others.some((o) => carriesPad(o, distractors))
      if (distractorPadded) {
        padded++
        expect(carriesPad(c, [correct]), ctx).toBe(true)
      }
    }
    expect(produced).toBeGreaterThan(1000) // the property must actually have been exercised
    expect(padded).toBeGreaterThan(100)
  })

  // Regression (found by this audit, since fixed in src/game/options.ts makeOptions): the pad added to the correct answer
  // could make it identical to a distractor and nothing re-checked uniqueness, although the doc comment promises "Returns
  // null if balancing fails or options repeat". validateQuestion() rejected such a question in the main bank, but story-mode
  // checks (says.ts via story.ts) are never validated, so a duplicate option could have been shown there.
  // Input: correct 'The client opens a connection to the server.'; distractors 'The client opens a connection to the
  // server now.', 'The client closes a connection to the server.', 'Short.'
  // Before the fix: two identical options 'The client opens a connection to the server now.'. Now: null.
  it('never returns two identical options (padding must not collide with a distractor)', () => {
    const r = makeOptions(
      'The client opens a connection to the server.',
      ['The client opens a connection to the server now.', 'The client closes a connection to the server.', 'Short.'],
      rng,
    )
    if (r) expect(new Set(r.options).size).toBe(4)
  })
})

// ---------------------------------------------------------------- pick answers list every matching packet

/** A capture with repeated lookups, repeated requests and several TLS sessions, so "all matching packets" is more than one. */
function busyCapture(): { index: CaptureIndex; dissect: ReturnType<typeof indexOf>['dissect'] } {
  const tl = new Timeline(5000)
  const rng = mulberry32(21)
  const client: Host = { mac: '3c:22:fb:1a:2b:3c', ip: '192.168.1.23' }
  const resolver: Host = { mac: '00:1a:2b:3c:4d:5e', ip: '192.168.1.1' }
  const web1: Host = { mac: '00:1a:2b:3c:4d:5f', ip: '93.184.216.34' }
  const web2: Host = { mac: '00:1a:2b:3c:4d:60', ip: '203.0.113.9' }
  const tlsA: Host = { mac: '00:1a:2b:3c:4d:61', ip: '104.18.32.7' }
  const tlsB: Host = { mac: '00:1a:2b:3c:4d:62', ip: '104.18.32.8' }
  const pair = (id: number, sport: number, name: string, type: 'A' | 'AAAA', answers: Parameters<typeof dnsResponse>[3], rcode = 0) => {
    tl.ip(client, resolver, 17, udp(sport, 53, dnsQuery(id, name, type)))
    tl.ip(resolver, client, 17, udp(53, sport, dnsResponse(id, name, type, answers, rcode)))
  }
  pair(1, 50001, 'www.example.com', 'A', [{ type: 'A', data: '93.184.216.34' }])
  pair(2, 50002, 'www.example.com', 'A', [{ type: 'A', data: '93.184.216.34' }]) // the same lookup again
  pair(3, 50003, 'www.example.com', 'AAAA', [{ type: 'AAAA', data: '2606:2800:220:1::1' }])
  pair(4, 50004, 'api.example.com', 'A', [{ type: 'A', data: '93.184.216.35' }])
  pair(5, 50005, 'nope.test', 'A', [], 3)
  pair(6, 50006, 'nope.test', 'A', [], 3)
  const get = (uri: string, host: string) => `GET ${uri} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: test\r\n\r\n`
  const ok = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nhi'
  const nf = 'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nno'
  const http = (server: Host, cport: number, uri: string, host: string, resp: string) =>
    new TcpSession(tl, { client, server, cport, sport: 80, rtt: 0.001 }, rng).handshake().exchange(get(uri, host), resp).close()
  http(web1, 51001, '/index.html', 'www.example.com', ok)
  http(web1, 51002, '/index.html', 'www.example.com', ok) // same URI and host again
  http(web2, 51003, '/index.html', 'other.example.net', ok) // same URI, different host
  http(web1, 51004, '/missing', 'www.example.com', nf)
  http(web1, 51005, '/gone', 'www.example.com', nf)
  const tls = (server: Host, cport: number, sni: string, suite: number) => {
    const t = new TcpSession(tl, { client, server, cport, sport: 443, rtt: 0.001 }, rng).handshake()
    t.send(true, tlsClientHello(sni, rng)).send(false, tlsServerHello(rng, suite)).close()
  }
  tls(tlsA, 52001, 'a.example', 0x1301)
  tls(tlsB, 52002, 'b.example', 0x1302)
  for (let seq = 1; seq <= 3; seq++) {
    tl.ip(client, { mac: '00:1a:2b:3c:4d:70', ip: '8.8.8.8' }, 1, icmpEcho(true, 7, seq))
    tl.ip({ mac: '00:1a:2b:3c:4d:70', ip: '8.8.8.8' }, client, 1, icmpEcho(false, 7, seq))
  }
  const { index, dissect } = indexOf(writePcap(tl.frames), 'busy.pcap')
  return { index, dissect }
}

/** Every packet that matches what a pick question's prompt is asking for, computed straight from the dissected facts. */
function matching(q: PickQuestion, index: CaptureIndex): number[] | null {
  const P = index.packets
  const first = P[q.answer[0] - 1]
  const nos = (f: (p: (typeof P)[number]) => boolean) => P.filter(f).map((p) => p.no)
  const [kind] = q.id.split(':')
  switch (kind) {
    case 'pick.dns-query':
      return nos((p) => !!p.facts.dns && !p.facts.dns.isResponse && p.facts.dns.qname === first.facts.dns!.qname && p.facts.dns.qtype === first.facts.dns!.qtype)
    case 'pick.dns-answer':
      return nos((p) => !!p.facts.dns?.isResponse && p.facts.dns.qname === first.facts.dns!.qname && p.facts.dns.answers.some((a) => a.type === 'A' || a.type === 'AAAA'))
    case 'pick.dns-nxdomain':
      return nos((p) => !!p.facts.dns?.isResponse && p.facts.dns.rcode === 3)
    case 'pick.tls-ch':
      return nos((p) => !!p.facts.tls?.handshakeTypes.includes('Client Hello'))
    case 'pick.tls-sh':
      return nos((p) => !!p.facts.tls?.handshakeTypes.includes('Server Hello'))
    case 'pick.http-request': {
      const h = first.facts.http!
      return nos((p) => !!p.facts.http?.isRequest && p.facts.http.uri === h.uri && (p.facts.http.host ?? p.facts.ip?.dst) === (h.host ?? first.facts.ip?.dst))
    }
    case 'pick.http-error': {
      const is404 = first.facts.http!.status === 404
      return nos((p) => (is404 ? p.facts.http?.status === 404 : (p.facts.http?.status ?? 0) >= 400))
    }
    case 'pick.icmp-reply':
      return nos((p) => !!p.facts.icmp && !p.facts.icmp.v6 && p.facts.icmp.type === 0 && p.facts.ip?.src === first.facts.ip!.src)
    case 'pick.ftp-success':
      return nos((p) => p.facts.app?.proto === 'FTP' && !p.facts.app.isRequest && p.facts.app.code === 230)
    case 'pick.creds':
      return nos((p) => !!p.facts.creds?.secret)
    case 'pick.dhcp-discover':
    case 'pick.dhcp-offer':
    case 'pick.dhcp-request':
    case 'pick.dhcp-ack': {
      const type = { discover: 'Discover', offer: 'Offer', request: 'Request', ack: 'ACK' }[kind.slice('pick.dhcp-'.length)]
      return nos((p) => p.facts.dhcp?.msgType === type)
    }
    default:
      return null // single-packet questions (a specific SYN, FIN, …)
  }
}

describe('pick answers list every packet that matches the prompt', () => {
  const busy = busyCapture()
  const busyBank = buildQuestionBank(busy.index, busy.dissect, 42)
  const banks = [...loaded.map((l) => ({ id: l.sample.id, index: l.index, bank: l.bank })), { id: 'busy', index: busy.index, bank: busyBank }]

  it('the busy capture builds a clean bank with the pick questions under test', () => {
    expect(busyBank.rejected).toEqual([])
    const kinds = new Set(busyBank.questions.filter((q) => q.kind === 'pick').map((q) => q.id.split(':')[0]))
    for (const k of ['pick.dns-query', 'pick.dns-answer', 'pick.dns-nxdomain', 'pick.tls-ch', 'pick.tls-sh', 'pick.http-request', 'pick.http-error', 'pick.icmp-reply'])
      expect(kinds, k).toContain(k)
  })

  it.each(banks)('$id: every pick answer contains all packets matching its prompt', ({ index, bank }) => {
    for (const q of bank.questions) {
      if (q.kind !== 'pick') continue
      const want = matching(q, index)
      if (!want) continue
      expect(want.length, q.id).toBeGreaterThan(0)
      expect(q.answer, `${q.id}: ${q.prompt}`).toEqual(expect.arrayContaining(want))
    }
  })

  it('the check above is exercised on every question kind it knows about, across the samples and the busy capture', () => {
    const seen = new Set<string>()
    for (const { index, bank } of banks) for (const q of bank.questions) if (q.kind === 'pick' && matching(q, index)) seen.add(q.id.split(':')[0])
    for (const k of ['pick.dns-query', 'pick.dns-answer', 'pick.dns-nxdomain', 'pick.tls-ch', 'pick.tls-sh', 'pick.http-request', 'pick.http-error', 'pick.icmp-reply', 'pick.ftp-success', 'pick.creds', 'pick.dhcp-offer'])
      expect(seen, k).toContain(k)
  })

  it('busy: DNS answers, ClientHellos, ServerHellos and same-URI requests are all accepted', () => {
    const P = busy.index.packets
    const q = (prefix: string) => busyBank.questions.filter((x) => x.id.startsWith(prefix)) as PickQuestion[]
    const dnsResp = (name: string, type: string) => P.filter((p) => p.facts.dns?.isResponse && p.facts.dns.qname === name && p.facts.dns.qtype === type).map((p) => p.no)
    // www.example.com has an A response twice and an AAAA response once; pick.dns-answer accepts all three.
    const www = q('pick.dns-answer').find((x) => P[x.answer[0] - 1].facts.dns!.qname === 'www.example.com')!
    expect(www.answer).toEqual([...dnsResp('www.example.com', 'A'), ...dnsResp('www.example.com', 'AAAA')].sort((a, b) => a - b))
    expect(www.answer).toHaveLength(3)
    // pick.dns-query names the record type in its prompt, so only the two A queries qualify.
    const qA = q('pick.dns-query').find((x) => x.prompt.includes('IPv4 address of www.example.com'))!
    expect(qA.answer).toHaveLength(2)
    expect(qA.answer.every((n) => P[n - 1].facts.dns!.qtype === 'A' && !P[n - 1].facts.dns!.isResponse)).toBe(true)
    // Both ClientHellos / ServerHellos.
    const ch = P.filter((p) => p.facts.tls?.handshakeTypes.includes('Client Hello')).map((p) => p.no)
    const sh = P.filter((p) => p.facts.tls?.handshakeTypes.includes('Server Hello')).map((p) => p.no)
    expect(ch).toHaveLength(2)
    expect(sh).toHaveLength(2)
    expect(q('pick.tls-ch')[0].answer).toEqual(ch)
    expect(q('pick.tls-sh')[0].answer).toEqual(sh)
    // Two GET /index.html to www.example.com; the request for the same URI on another host is NOT part of the answer.
    const same = P.filter((p) => p.facts.http?.uri === '/index.html' && p.facts.http.host === 'www.example.com').map((p) => p.no)
    const other = P.filter((p) => p.facts.http?.uri === '/index.html' && p.facts.http.host === 'other.example.net').map((p) => p.no)
    expect(same).toHaveLength(2)
    expect(other).toHaveLength(1)
    const idx = q('pick.http-request').find((x) => x.prompt.includes('/index.html from www.example.com'))!
    expect(idx.answer).toEqual(same)
    expect(idx.answer).not.toContain(other[0])
    // Both 404s.
    expect(q('pick.http-error')[0].answer).toEqual(P.filter((p) => p.facts.http?.status === 404).map((p) => p.no))
    expect(q('pick.http-error')[0].answer).toHaveLength(2)
    // Both NXDOMAIN replies and all three echo replies from 8.8.8.8.
    expect(q('pick.dns-nxdomain')[0].answer).toHaveLength(2)
    expect(q('pick.icmp-reply')[0].answer).toHaveLength(3)
  })

  it('every pick question grades its own full answer as correct (multi) or any single listed packet (single)', () => {
    for (const { bank } of banks)
      for (const q of bank.questions) {
        if (q.kind !== 'pick') continue
        if (q.multi) expect(pickScore(q, q.answer), q.id).toBe(1)
        else for (const n of q.answer) expect(pickScore(q, [n]), `${q.id} #${n}`).toBe(1)
      }
  })
})
