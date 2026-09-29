// Modes H (Type the Answer), I (Filter Forge) and J (Keystroke Drill): grading, generation and stats.

import { describe, expect, it } from 'vitest'
import { buildDrillWords, drillStats, drillXp, type DrillStats } from '../src/game/drill'
import { buildQuestionBank, grade, seeded } from '../src/game/engine'
import { gradeFilter, matchSet } from '../src/game/generators/filters'
import { gradeText } from '../src/game/generators/typed'
import type { FilterQuestion, TextQuestion } from '../src/game/types'
import { SAMPLES } from '../src/samples/samples'
import { indexOf } from './helpers'

const loaded = SAMPLES.map((s) => {
  const { index, dissect } = indexOf(s.build(), s.fileName)
  return { sample: s, index, dissect, bank: buildQuestionBank(index, dissect, 42) }
})
const web = loaded.find((l) => l.sample.id === 'web-basic')!
const https = loaded.find((l) => l.sample.id === 'https-visit')!

/** A hand-built text question for exercising gradeText in isolation. */
function tq(match: TextQuestion['match'], accept: string[]): TextQuestion {
  return {
    id: 't',
    mode: 'type',
    kind: 'text',
    tier: 'Recruit',
    concept: 'dns',
    prompt: 'p',
    hint: 'h',
    explanation: { says: 's', means: 'm', matters: 'x' },
    highlight: [{ packet: 1 }],
    accept,
    match,
    placeholder: '',
  }
}

// ---------------------------------------------------------------- gradeText

describe('gradeText', () => {
  it('rejects empty and whitespace-only input for every match type', () => {
    for (const m of ['number', 'ip', 'mac', 'exact', 'fuzzy'] as const) {
      expect(gradeText(tq(m, ['64']), '').score).toBe(0)
      expect(gradeText(tq(m, ['64']), '   \t ').score).toBe(0)
    }
  })

  describe('number', () => {
    const q = tq('number', ['64'])
    it('accepts the bare number and ignores surrounding text', () => {
      expect(gradeText(q, '64').score).toBe(1)
      expect(gradeText(q, ' 64 ').score).toBe(1)
      expect(gradeText(q, 'ttl 64').score).toBe(1)
      expect(gradeText(q, 'TTL = 64 hops').score).toBe(1)
    })
    it('ignores leading zeros', () => {
      expect(gradeText(q, '064').score).toBe(1)
    })
    it('rejects a different number or no number at all', () => {
      expect(gradeText(q, '128').score).toBe(0)
      expect(gradeText(q, '6').score).toBe(0)
      expect(gradeText(q, 'sixty-four').score).toBe(0)
    })
    it('supports several accepted numbers (any one of the open ports)', () => {
      const ports = tq('number', ['22', '80', '443'])
      for (const p of ['22', '80', '443']) expect(gradeText(ports, p).score).toBe(1)
      expect(gradeText(ports, '8080').score).toBe(0)
    })
    it('needs exactly one non-negative whole number in the answer', () => {
      const q = tq('number', ['443'])
      for (const s of ['443', ' 443 ', 'port 443', 'port: 443', 'dst port = 443', '0443', '443.']) expect(gradeText(q, s).score, s).toBe(1)
      // Two numbers, even if one is right, is a hedge, not an answer.
      for (const s of ['443 or 80', '80 443', '443, 80', '4 43', '0x1bb']) expect(gradeText(q, s).score, s).toBe(0)
      // Negative and fractional numbers are not the port.
      for (const s of ['-443', '- 443', '443.5', 'port 8443', '44']) expect(gradeText(q, s).score, s).toBe(0)
      // Each of several accepted values is fine alone, but not together.
      const ports = tq('number', ['22', '80', '443'])
      expect(gradeText(ports, '22').score).toBe(1)
      expect(gradeText(ports, '22 80').score).toBe(0)
      expect(gradeText(ports, '22, 80, 443').score).toBe(0)
    })
  })

  describe('ip', () => {
    const q = tq('ip', ['93.184.216.34'])
    it('accepts the canonical address and tolerates whitespace / trailing dot', () => {
      expect(gradeText(q, '93.184.216.34').score).toBe(1)
      expect(gradeText(q, '  93.184.216.34  ').score).toBe(1)
      expect(gradeText(q, '93. 184.216.34').score).toBe(1)
      expect(gradeText(q, '93.184.216.34.').score).toBe(1)
    })
    it('normalises leading zeros in any octet', () => {
      expect(gradeText(q, '093.184.216.034').score).toBe(1)
      expect(gradeText(q, '093.0184.0216.0034').score).toBe(1)
    })
    it('normalises leading zeros on the accepted side too', () => {
      expect(gradeText(tq('ip', ['093.184.216.034']), '93.184.216.34').score).toBe(1)
    })
    it('rejects a different address', () => {
      expect(gradeText(q, '93.184.216.35').score).toBe(0)
      expect(gradeText(q, '93.184.216').score).toBe(0)
      expect(gradeText(q, '93.184.216.34.5').score).toBe(0)
      expect(gradeText(q, 'example.com').score).toBe(0)
    })
    it('accepts any of several A records', () => {
      const multi = tq('ip', ['10.0.0.1', '10.0.0.2'])
      expect(gradeText(multi, '10.0.0.2').score).toBe(1)
      expect(gradeText(multi, '10.0.0.3').score).toBe(0)
    })
  })

  describe('mac', () => {
    const q = tq('mac', ['de:ad:be:ef:13:37'])
    it('accepts colons, dashes, dots, bare hex and any case', () => {
      for (const s of ['de:ad:be:ef:13:37', 'DE:AD:BE:EF:13:37', 'de-ad-be-ef-13-37', 'DE-AD-BE-EF-13-37', 'dead.beef.1337', 'deadbeef1337', ' De:aD:Be:eF:13:37 '])
        expect(gradeText(q, s).score, s).toBe(1)
    })
    it('rejects a different MAC', () => {
      expect(gradeText(q, 'de:ad:be:ef:13:38').score).toBe(0)
      expect(gradeText(q, 'ff:ff:ff:ff:ff:ff').score).toBe(0)
      expect(gradeText(q, 'de:ad:be:ef:13').score).toBe(0)
    })
    it('needs exactly 12 hex digits once ": - ." and spaces are removed', () => {
      const m = tq('mac', ['aa:bb:cc:dd:ee:ff'])
      for (const s of ['aabb.ccdd.eeff', 'AA-BB-CC-DD-EE-FF', 'aa bb cc dd ee ff', 'aabbccddeeff', 'aa.bb.cc.dd.ee.ff', 'Aa:bB:Cc:dD:Ee:fF']) expect(gradeText(m, s).score, s).toBe(1)
      for (const s of ['aa:bb:cc:dd:ee', 'aa:bb:cc:dd:ee:ff:00', 'aa:bb:cc:dd:ee:fg', 'aabbccddeef', 'mac aa:bb:cc:dd:ee:ff', 'aa:bb:cc:dd:ee:f']) expect(gradeText(m, s).score, s).toBe(0)
    })
  })

  describe('exact', () => {
    const q = tq('exact', ['NXDOMAIN'])
    it('is case/whitespace/quote/trailing-dot insensitive but not typo tolerant', () => {
      expect(gradeText(q, 'nxdomain').score).toBe(1)
      expect(gradeText(q, '  "NXDomain" ').score).toBe(1)
      expect(gradeText(q, 'nxdomain.').score).toBe(1)
      expect(gradeText(q, 'nxdomian').score).toBe(0)
    })
  })

  describe('fuzzy', () => {
    it('ignores case, surrounding/inner whitespace and a trailing dot', () => {
      const q = tq('fuzzy', ['www.example.com'])
      expect(gradeText(q, 'WWW.Example.COM').score).toBe(1)
      expect(gradeText(q, '   www.example.com   ').score).toBe(1)
      expect(gradeText(q, 'www.example.com.').score).toBe(1)
      const multi = tq('fuzzy', ['No such name'])
      expect(gradeText(multi, 'no   such\tname').score).toBe(1)
    })
    it('strips wrapping quotes', () => {
      const q = tq('fuzzy', ['alice'])
      expect(gradeText(q, '"alice"').score).toBe(1)
      expect(gradeText(q, "'alice'").score).toBe(1)
    })
    it('is punctuation-insensitive ("syn ack" vs "SYN, ACK") and says so', () => {
      const q = tq('fuzzy', ['SYN, ACK'])
      expect(gradeText(q, 'SYN, ACK')).toEqual({ score: 1, note: '' })
      for (const s of ['syn ack', 'syn,ack', 'SYN-ACK', 'syn/ack', 'SYN+ACK', 'synack', 'Syn . Ack']) expect(gradeText(q, s).score, s).toBe(1)
      expect(gradeText(q, 'syn ack').note).toMatch(/punctuation/i)
    })
    it('accepts any spelling in the accept list', () => {
      const q = tq('fuzzy', ['NXDOMAIN', 'No such name', 'NX domain', '3'])
      for (const s of ['nxdomain', 'no such name', 'nx domain', '3']) expect(gradeText(q, s).score, s).toBe(1)
    })

    it('forgives a single typo in words of 5+ characters (and reports it)', () => {
      const q = tq('fuzzy', ['NXDOMAIN'])
      for (const s of ['nxdomai', 'nxdomainn', 'nxdxmain']) {
        const r = gradeText(q, s)
        expect(r.score, s).toBe(1)
        expect(r.note, s).toMatch(/typo/i)
      }
      const host = tq('fuzzy', ['secure.example.org'])
      expect(gradeText(host, 'secure.exmple.org').score).toBe(1) // dropped letter
    })
    it('does not forgive two typos in a 5-15 character word', () => {
      const q = tq('fuzzy', ['NXDOMAIN'])
      expect(gradeText(q, 'nxdoamn').score).toBe(0)
      expect(gradeText(q, 'nxdxmxin').score).toBe(0)
      const five = tq('fuzzy', ['alice'])
      expect(gradeText(five, 'alicf').score).toBe(1)
      expect(gradeText(five, 'alcf').score).toBe(0)
    })
    it('allows no typos in words shorter than 5 characters', () => {
      const udp = tq('fuzzy', ['UDP'])
      expect(gradeText(udp, 'udb').score).toBe(0)
      expect(gradeText(udp, 'ud').score).toBe(0)
      const four = tq('fuzzy', ['ping'])
      expect(gradeText(four, 'pong').score).toBe(0)
      expect(gradeText(four, 'ping').score).toBe(1)
    })
    it('compares cipher-suite names token by token: same token count, digits exact, one slip per 5+-letter word', () => {
      const cipher = tq('fuzzy', ['TLS_AES_128_GCM_SHA256'])
      // Exact, in any case.
      expect(gradeText(cipher, 'TLS_AES_128_GCM_SHA256').score).toBe(1)
      expect(gradeText(cipher, 'tls_aes_128_gcm_sha256').score).toBe(1)
      // Any wrong or missing digit fails, however few characters differ (these used to earn the 16+ character typo budget).
      for (const s of ['TLS_AES_128_GCM_SHA25', 'TLS_AES_28_GCM_SHA25', 'tls_aes_128_gcm_sha265', 'TLS_AES_128_GCM_SHA2', 'TLS_AES_128_GCM_SHA', 'TLS_AES_28_GCM_SHA2', 'TLS_AES_256_GCM_SHA256', 'TLS_AES_128_GCM_SHA384'])
        expect(gradeText(cipher, s).score, s).toBe(0)
      // A different number of tokens fails.
      for (const s of ['TLS_AES_128_GCM', 'TLS_AES_128_GCM_SHA256_X', 'TLS_AES_128', 'AES_128_GCM_SHA256'])
        expect(gradeText(cipher, s).score, s).toBe(0)
      // Words shorter than 5 letters get no slip.
      for (const s of ['TLS_AEX_128_GCM_SHA256', 'TLS_AES_128_GCN_SHA256', 'TLX_AES_128_GCM_SHA256']) expect(gradeText(cipher, s).score, s).toBe(0)
      // Separators alone are not a difference (spaces / hyphens carry the same tokens).
      const dashed = gradeText(cipher, 'TLS-AES-128-GCM-SHA256')
      expect(dashed.score).toBe(1)
      expect(dashed.note).toMatch(/punctuation/)
    })
    it('forgives one letter slip in a 5+-letter word of a cipher name, and at most two slips overall', () => {
      const ecdhe = tq('fuzzy', ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'])
      expect(gradeText(ecdhe, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')).toEqual({ score: 1, note: '' })
      expect(gradeText(ecdhe, 'tls_ecdhe_rsa_with_aes_128_gcm_sha256').score).toBe(1)
      const slip = gradeText(ecdhe, 'TLS_ECDHA_RSA_WITH_AES_128_GCM_SHA256') // ECDHE has 5 letters
      expect(slip.score).toBe(1)
      expect(slip.note).toMatch(/typo/i)
      expect(gradeText(ecdhe, 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256').score).toBe(1) // a dropped letter is one edit too
      // …but not in a 3-letter word (RSA), a 4-letter word (WITH), two edits in one word, or with a digit typo elsewhere.
      expect(gradeText(ecdhe, 'TLS_ECDHE_RSB_WITH_AES_128_GCM_SHA256').score).toBe(0)
      expect(gradeText(ecdhe, 'TLS_ECDHE_RSA_WITX_AES_128_GCM_SHA256').score).toBe(0)
      expect(gradeText(ecdhe, 'TLS_ECDHXX_RSA_WITH_AES_128_GCM_SHA256').score).toBe(0)
      expect(gradeText(ecdhe, 'TLS_ECDHA_RSA_WITH_AES_128_GCM_SHA25').score).toBe(0)
      expect(gradeText(ecdhe, 'TLS_ECDHE_RSA_WITH_AES_128_GCM').score).toBe(0) // token missing

      // Two slips are fine, three are not (this synthetic name has four words of 5+ letters).
      const ecdsa = tq('fuzzy', ['TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'])
      expect(gradeText(ecdsa, 'TLS_ECDHA_ECDSB_WITH_AES_256_GCM_SHA384').score).toBe(1)
      const words = tq('fuzzy', ['ALPHA_BRAVO_CHARLIE_DELTA'])
      expect(gradeText(words, 'ALPHX_BRAVO_CHARLIE_DELTA').score).toBe(1)
      expect(gradeText(words, 'ALPHX_BRAVX_CHARLIE_DELTA').score).toBe(1)
      expect(gradeText(words, 'ALPHX_BRAVX_CHARLIX_DELTA').score).toBe(0)
      expect(gradeText(words, 'ALPHX_BRAVX_CHARLIX_DELTX').score).toBe(0)
    })
    it('a name made only of digit-bearing words allows no slip at all', () => {
      const chacha = tq('fuzzy', ['TLS_CHACHA20_POLY1305_SHA256'])
      expect(gradeText(chacha, 'TLS_CHACHA20_POLY1305_SHA256').score).toBe(1)
      expect(gradeText(chacha, 'tls_chacha20_poly1305_sha256').score).toBe(1)
      for (const s of ['TLS_CHACHA20_POLY1305_SHA265', 'TLS_CHACHA2O_POLY1305_SHA256', 'TLS_CHACHA20_POLY1350_SHA256', 'TLS_CHACHA20_POLY1305_SHA25', 'TLS_AES_128_GCM_SHA256'])
        expect(gradeText(chacha, s).score, s).toBe(0)
    })
    it('other strings of 16+ characters (no underscore) keep the two-typo budget, but never for digits', () => {
      const host = tq('fuzzy', ['secure.example.org'])
      expect(gradeText(host, 'secure.exmpl.org').score).toBe(1) // 2 letters dropped
      expect(gradeText(host, 'secure.exmpl.rg').score).toBe(0) // 3
      const versioned = tq('fuzzy', ['Transport Layer Security 1.3'])
      expect(gradeText(versioned, 'Transport Layer Securty 1.3').score).toBe(1)
      expect(gradeText(versioned, 'Transport Layer Security 1.2').score).toBe(0)
    })
    it('digits must match exactly even in short answers ("TLS 1.2" is not "TLS 1.3")', () => {
      const ver = tq('fuzzy', ['TLS 1.3'])
      expect(gradeText(ver, 'TLS 1.3').score).toBe(1)
      expect(gradeText(ver, 'tls 1.3').score).toBe(1)
      for (const s of ['TLS 1.2', 'TLS 1.30', 'TLS 2.3', 'TLS 1.', 'TLS']) expect(gradeText(ver, s).score, s).toBe(0)
      expect(gradeText(tq('fuzzy', ['HTTP/1.1']), 'HTTP/1.0').score).toBe(0)
      expect(gradeText(tq('fuzzy', ['SHA256']), 'SHA265').score).toBe(0)
      expect(gradeText(tq('fuzzy', ['SHA1']), 'SHA2').score).toBe(0)
    })
    it('host-name answers accept a pasted URL and reduce it to the host', () => {
      const host = tq('fuzzy', ['www.example.com'])
      const url = gradeText(host, 'https://www.example.com/path?q=1')
      expect(url).toEqual({ score: 1, note: 'Accepted (just the host name was needed).' })
      for (const s of ['http://www.example.com', 'www.example.com/index.html', 'https://WWW.Example.com:8443/', 'ftp://www.example.com', 'www.example.com?x=1', 'www.example.com#frag', 'https://www.example.com.'])
        expect(gradeText(host, s).score, s).toBe(1)
      for (const s of ['https://www.example.org/path', 'https://example.com/www.example.com', 'https://evil.com/?h=www.example.com', 'https://www.example.com.evil.net/', 'www.example.com.evil.net'])
        expect(gradeText(host, s).score, s).toBe(0)
      // Only host-shaped accept lists get this treatment.
      expect(gradeText(tq('fuzzy', ['alice']), 'https://alice/').score).toBe(0)
    })
    it('rejects clearly wrong answers', () => {
      const q = tq('fuzzy', ['SYN, ACK'])
      for (const s of ['FIN, ACK', 'RST', 'SYN', 'ACK', 'syn syn', 'banana']) expect(gradeText(q, s).score, s).toBe(0)
      const dns = tq('fuzzy', ['www.example.com'])
      for (const s of ['example.com', 'www.example.org', 'google.com', 'x']) expect(gradeText(dns, s).score, s).toBe(0)
      const udp = tq('fuzzy', ['UDP', 'User Datagram Protocol'])
      for (const s of ['TCP', 'ICMP', 'DNS']) expect(gradeText(udp, s).score, s).toBe(0)
    })
    it('does not confuse the two ends of a SYN-ACK question', () => {
      const q = tq('fuzzy', ['SYN, ACK', 'SYN ACK', 'SYN-ACK', 'SYNACK', 'ACK, SYN', 'ACK SYN', 'SYN/ACK', 'SYN+ACK'])
      expect(gradeText(q, 'ack syn').score).toBe(1)
      expect(gradeText(q, 'FIN ACK').score).toBe(0)
    })
  })
})

// ---------------------------------------------------------------- generated text questions

describe.each(loaded)('type mode on $sample.id', ({ index, bank }) => {
  const texts = bank.questions.filter((q): q is TextQuestion => q.kind === 'text')

  it('asks at least one text question, all in mode "type"', () => {
    expect(texts.length).toBeGreaterThan(0)
    for (const q of texts) expect(q.mode).toBe('type')
  })

  it('grades the canonical answer (accept[0]) as 1 through the engine', () => {
    for (const q of texts) {
      const g = grade(q, { kind: 'text', text: q.accept[0] })
      expect(g.score, `${q.id}: ${q.accept[0]}`).toBe(1)
    }
  })

  it('grades every accepted spelling as 1', () => {
    for (const q of texts) for (const a of q.accept) expect(grade(q, { kind: 'text', text: a }).score, `${q.id}: ${a}`).toBe(1)
  })

  it('grades a clearly wrong answer as 0 and empty input as 0', () => {
    for (const q of texts) {
      const wrong =
        q.match === 'number' ? 'no digits here' : q.match === 'ip' ? '0.0.0.0' : q.match === 'mac' ? '01:23:45:67:89:ab' : 'zzzz qqqq wrong answer'
      const g = grade(q, { kind: 'text', text: wrong })
      expect(g.score, `${q.id} vs "${wrong}"`).toBe(0)
      expect(g.feedback).toContain(q.accept[0])
      expect(grade(q, { kind: 'text', text: '' }).score, q.id).toBe(0)
    }
  })

  it('grades a wrong number as 0 (accepted value + 1000)', () => {
    for (const q of texts.filter((x) => x.match === 'number')) {
      const off = String(Math.max(...q.accept.map(Number)) + 1000)
      expect(grade(q, { kind: 'text', text: off }).score, q.id).toBe(0)
    }
  })

  it('rejects a submission of the wrong answer kind', () => {
    for (const q of texts) expect(grade(q, { kind: 'choice', index: 0 }).score).toBe(0)
  })

  it('never puts a cleartext password in the accept list, prompt, hint, explanation or placeholder', () => {
    const secrets = index.packets.map((p) => p.facts.creds?.secret).filter(Boolean) as string[]
    for (const q of texts) {
      const blob = JSON.stringify([q.accept, q.prompt, q.hint, q.explanation, q.placeholder])
      for (const s of secrets) expect(blob, `${q.id} leaks ${s}`).not.toContain(s)
    }
  })

  it('never accepts a password as the answer', () => {
    const secrets = index.packets.map((p) => p.facts.creds?.secret).filter(Boolean) as string[]
    for (const q of texts) for (const s of secrets) expect(grade(q, { kind: 'text', text: s }).score, `${q.id} accepts password ${s}`).toBe(0)
  })
})

describe('type mode specifics', () => {
  it('asks about a known value on web-basic', () => {
    const byId = (id: string) => web.bank.questions.find((q) => q.id === id) as TextQuestion
    expect(grade(byId('type.ttl:1'), { kind: 'text', text: 'ttl 64' }).score).toBe(1)
    expect(grade(byId('type.answer-ip:2'), { kind: 'text', text: '093.184.216.034' }).score).toBe(1)
    expect(grade(byId('type.flags:4'), { kind: 'text', text: 'syn ack' }).score).toBe(1)
    expect(grade(byId('type.flags:4'), { kind: 'text', text: 'FIN, ACK' }).score).toBe(0)
    expect(grade(byId('type.status:11'), { kind: 'text', text: '404' }).score).toBe(1)
    expect(grade(byId('type.status:11'), { kind: 'text', text: '200' }).score).toBe(0)
  })

  it('accepts a MAC typed with dashes/uppercase on arp-spoof', () => {
    const l = loaded.find((x) => x.sample.id === 'arp-spoof')!
    const q = l.bank.questions.find((x) => x.id === 'type.arp-attacker') as TextQuestion
    expect(q.match).toBe('mac')
    expect(grade(q, { kind: 'text', text: 'DE-AD-BE-EF-13-37' }).score).toBe(1)
    expect(grade(q, { kind: 'text', text: 'de:ad:be:ef:13:38' }).score).toBe(0)
  })

  it('accepts either spelling of the tunnelling domain, with or without trailing dot', () => {
    const l = loaded.find((x) => x.sample.id === 'dns-tunnel')!
    const q = l.bank.questions.find((x) => x.id === 'type.tunnel-domain') as TextQuestion
    expect(grade(q, { kind: 'text', text: 'TunnelCDN.net.' }).score).toBe(1)
    expect(grade(q, { kind: 'text', text: 'wikipedia.org' }).score).toBe(0)
  })

  it('grades the cipher-suite name on https-visit token by token (a digit typo is no longer forgiven)', () => {
    const q = https.bank.questions.find((x) => x.id.startsWith('type.cipher:')) as TextQuestion
    expect(q.accept[0]).toBe('TLS_AES_128_GCM_SHA256')
    expect(grade(q, { kind: 'text', text: 'TLS_AES_128_GCM_SHA256' }).score).toBe(1)
    expect(grade(q, { kind: 'text', text: 'tls_aes_128_gcm_sha256' }).score).toBe(1)
    expect(grade(q, { kind: 'text', text: ' Tls_Aes_128_Gcm_Sha256 ' }).score).toBe(1)
    // Previously accepted as "1 typo"; SHA265 is a different (non-existent) hash name.
    expect(grade(q, { kind: 'text', text: 'tls_aes_128_gcm_sha265' })).toEqual({ score: 0, feedback: 'Expected TLS_AES_128_GCM_SHA256.' })
    expect(grade(q, { kind: 'text', text: 'TLS_AES_128_GCM_SHA25' }).score).toBe(0)
    expect(grade(q, { kind: 'text', text: 'TLS_AES_28_GCM_SHA25' }).score).toBe(0)
    expect(grade(q, { kind: 'text', text: 'TLS_AES_256_GCM_SHA384' }).score).toBe(0)
    expect(grade(q, { kind: 'text', text: 'TLS_CHACHA20_POLY1305_SHA256' }).score).toBe(0)
  })

  it('accepts a pasted URL for host-name questions, through the engine (web-basic Host header, https-visit SNI)', () => {
    const host = web.bank.questions.find((x) => x.id.startsWith('type.host:')) as TextQuestion
    expect(host.accept).toEqual(['www.example.com'])
    expect(grade(host, { kind: 'text', text: 'https://www.example.com/path?q=1' }).score).toBe(1)
    expect(grade(host, { kind: 'text', text: 'http://example.com/' }).score).toBe(0)
    const sni = https.bank.questions.find((x) => x.id.startsWith('type.sni:')) as TextQuestion
    expect(grade(sni, { kind: 'text', text: 'https://secure.example.org/' }).score).toBe(1)
  })

  it('accepts the common spellings of NXDOMAIN, including "Non-Existent Domain" and "name error"', () => {
    const l = loaded.find((x) => x.sample.id === 'dns-tunnel')!
    const q = l.bank.questions.find((x) => x.id.startsWith('type.rcode:')) as TextQuestion
    expect(q.match).toBe('fuzzy')
    for (const s of ['NXDOMAIN', 'nxdomain', 'Non-Existent Domain', 'non existent domain', 'name error', 'Name Error', 'No such name', 'NX domain', '3'])
      expect(grade(q, { kind: 'text', text: s }).score, s).toBe(1)
    for (const s of ['SERVFAIL', 'refused', 'no error', '0', '2', 'error']) expect(grade(q, { kind: 'text', text: s }).score, s).toBe(0)
  })

  // Regression: short answers must not forgive digit typos ("TLS 1.2" is not "TLS 1.3").
  it('does not accept TLS 1.2 as the answer to "which TLS version was negotiated" (real answer: TLS 1.3)', () => {
    const q = https.bank.questions.find((x) => x.id.startsWith('type.tlsver:')) as TextQuestion
    expect(q.accept).toContain('TLS 1.3')
    expect(grade(q, { kind: 'text', text: 'TLS 1.3' }).score).toBe(1)
    expect(grade(q, { kind: 'text', text: 'TLS 1.2' }).score).toBe(0)
  })
})

// ---------------------------------------------------------------- filter questions

describe.each(loaded)('filter mode on $sample.id', ({ index, bank }) => {
  const filters = bank.questions.filter((q): q is FilterQuestion => q.kind === 'filter')

  it('generates at least one filter question, all in mode "filter"', () => {
    expect(filters.length).toBeGreaterThan(0)
    for (const q of filters) expect(q.mode).toBe('filter')
  })

  it('never targets an empty set or the whole capture', () => {
    for (const q of filters) {
      expect(q.target.length, q.id).toBeGreaterThan(0)
      expect(q.target.length, q.id).toBeLessThan(index.packets.length)
      expect([...q.target].sort((a, b) => a - b), q.id).toEqual(q.target)
    }
  })

  it('grades the reference filter as 1 through the engine', () => {
    for (const q of filters) {
      const g = grade(q, { kind: 'filter', text: q.reference }, undefined, index)
      expect(g.score, `${q.id}: ${q.reference} -> ${g.feedback}`).toBe(1)
      expect(g.feedback).toMatch(/exact match/i)
    }
  })

  it('grades a superset filter (`frame`, matches every frame) as 0 or 0.5, never 1', () => {
    for (const q of filters) {
      const g = grade(q, { kind: 'filter', text: 'frame' }, undefined, index)
      expect([0, 0.5], `${q.id}: ${g.feedback}`).toContain(g.score)
    }
  })

  it('grades a filter matching nothing as 0', () => {
    for (const q of filters) {
      const g = grade(q, { kind: 'filter', text: 'frame.len > 99999999' }, undefined, index)
      expect(g.score, q.id).toBe(0)
      expect(g.feedback).toMatch(/0 frames/)
    }
  })

  it('returns score 0 with a message (no throw) for an invalid filter string', () => {
    for (const q of filters) {
      for (const bad of ['tcp.flags.syn ==', '((', 'nosuchfield == 1', 'dns &&']) {
        let g!: ReturnType<typeof grade>
        expect(() => (g = grade(q, { kind: 'filter', text: bad }, undefined, index)), `${q.id}: ${bad}`).not.toThrow()
        expect(g.score).toBe(0)
        expect(g.feedback.length).toBeGreaterThan(0)
      }
    }
  })

  it('scores 0 without an index or with the wrong answer kind', () => {
    for (const q of filters) {
      expect(grade(q, { kind: 'filter', text: q.reference }).score).toBe(0)
      expect(grade(q, { kind: 'text', text: q.reference }, undefined, index).score).toBe(0)
    }
  })
})

describe('gradeFilter details on web-basic', () => {
  const { index, bank } = web
  const q = bank.questions.find((x) => x.id === 'filter.dns-responses') as FilterQuestion

  it('has the expected target (the single DNS response)', () => {
    expect(q.reference).toBe('dns.flags.response == 1')
    const dnsFrames = matchSet(index, 'dns')
    expect(dnsFrames).toHaveLength(2)
    expect(q.target).toHaveLength(1)
    expect(dnsFrames).toContain(q.target[0])
    expect(matchSet(index, q.reference)).toEqual(q.target)
  })

  it('reports 1 right, 1 extra, 0 missing when the learner submits `dns` (query + response)', () => {
    const r = gradeFilter(q, index, 'dns')
    expect(r.matched).toHaveLength(2)
    expect(r.score).toBe(0) // precision 1/2 < 0.8
    expect(r.note).toBe('Matched 2 frames: 1 right, 1 extra, 0 missing.')
  })

  it('reports an exact match with correct singular/plural wording', () => {
    const r = gradeFilter(q, index, 'dns.flags.response == 1')
    expect(r.score).toBe(1)
    expect(r.matched).toEqual(q.target)
    expect(r.note).toBe('Exact match — Matched 1 frame: 1 right, 0 extra, 0 missing.')
  })

  it('reports missing frames when the filter is too narrow', () => {
    const dns = bank.questions.find((x) => x.id === 'filter.dns') as FilterQuestion
    expect(dns.target).toHaveLength(2)
    const r = gradeFilter(dns, index, 'dns.flags.response == 1')
    expect(r).toMatchObject({ score: 0, note: 'Matched 1 frame: 1 right, 0 extra, 1 missing.' }) // recall 1/2 < 0.8
  })

  it('reports wrong frames as extra and missing at once', () => {
    const r = gradeFilter(q, index, 'tcp.flags.fin == 1')
    expect(r.score).toBe(0)
    expect(r.note).toBe('Matched 2 frames: 0 right, 2 extra, 1 missing.')
  })

  // Partial credit ("Close") needs BOTH precision (right / matched) >= 0.8 AND recall (right / target) >= 0.8.
  // The old Jaccard rule (right / union >= 0.6) would have given 0.5 to several of the cases below that now score 0.
  describe('gives 0.5 ("Close") only when precision >= 0.8 AND recall >= 0.8', () => {
    const from = bank.questions.find((x) => x.id === 'filter.from:192.168.1.23') as FilterQuestion
    // Frames sent by the client: 1, 3, 5, 6, 9, 10, 12, 13, 15.
    const CLIENT = 'ip.src == 192.168.1.23'

    it('the reference question targets the 9 client frames', () => {
      expect(from.target).toEqual([1, 3, 5, 6, 9, 10, 12, 13, 15])
      expect(from.reference).toBe(CLIENT)
    })

    it('precision side: 1 or 2 extra frames out of 9 right is Close (9/10, 9/11); 3 extra (9/12 = 0.75) is not', () => {
      const one = gradeFilter(from, index, `${CLIENT} || dns.flags.response == 1`) // + frame 2
      expect(one.score).toBe(0.5)
      expect(one.note).toBe('Close — Matched 10 frames: 9 right, 1 extra, 0 missing.')
      const two = gradeFilter(from, index, `${CLIENT} || dns.flags.response == 1 || tcp.flags.syn == 1 && tcp.flags.ack == 1`) // + frames 2, 4
      expect(two.score).toBe(0.5) // 9/11 = 0.818
      expect(two.note).toBe('Close — Matched 11 frames: 9 right, 2 extra, 0 missing.')
      const three = gradeFilter(from, index, `${CLIENT} || dns.flags.response == 1 || tcp.flags.syn == 1 && tcp.flags.ack == 1 || http.response.code >= 400`) // + frame 11
      expect(three.score).toBe(0) // precision 0.75; Jaccard would have been 0.75 >= 0.6
      expect(three.note).toBe('Matched 12 frames: 9 right, 3 extra, 0 missing.')
    })

    it('recall side: 8 of 9 found is Close (0.889); 7 of 9 (0.778) is not, although its Jaccard is 0.778', () => {
      const eight = gradeFilter(from, index, `${CLIENT} && frame.number <= 13`)
      expect(eight.score).toBe(0.5)
      expect(eight.note).toBe('Close — Matched 8 frames: 8 right, 0 extra, 1 missing.')
      const seven = gradeFilter(from, index, `${CLIENT} && frame.number <= 12`)
      expect(seven.score).toBe(0)
      expect(seven.note).toBe('Matched 7 frames: 7 right, 0 extra, 2 missing.')
      expect(gradeFilter(from, index, `${CLIENT} && frame.number <= 10`).score).toBe(0) // 6 of 9 = 0.667
    })

    it('the old Jaccard example (fin question: 2 right + 1 extra) is no longer Close: precision is only 2/3', () => {
      const fin = bank.questions.find((x) => x.id === 'filter.fin') as FilterQuestion
      expect(fin.target).toHaveLength(2)
      const r = gradeFilter(fin, index, 'tcp.flags.fin == 1 || (tcp.flags.syn == 1 && tcp.flags.ack == 1)') // Jaccard 2/3 >= 0.6
      expect(r.score).toBe(0)
      expect(r.note).toBe('Matched 3 frames: 2 right, 1 extra, 0 missing.')
      expect(gradeFilter(fin, index, 'tcp.flags.fin == 1 || tcp.flags.syn == 1').score).toBe(0) // 2 right + 2 extra
      expect(gradeFilter(fin, index, 'tcp.flags.fin == 1 && ip.src == 192.168.1.23').score).toBe(0) // recall 1/2
    })

    it('the thresholds are inclusive: exactly 0.8 and 0.8 is Close, just under either is not', () => {
      const five: FilterQuestion = { ...from, id: 'synthetic', target: [1, 2, 3, 4, 5] }
      // 4 right, 1 extra (frame 9), 1 missing (frame 5): precision 4/5 and recall 4/5.
      const both = gradeFilter(five, index, 'frame.number <= 4 || frame.number == 9')
      expect(both.score).toBe(0.5)
      expect(both.note).toBe('Close — Matched 5 frames: 4 right, 1 extra, 1 missing.')
      // Precision 1.0, recall exactly 0.8.
      expect(gradeFilter(five, index, 'frame.number <= 4').score).toBe(0.5)
      // Recall exactly 0.8, precision 4/6.
      expect(gradeFilter(five, index, 'frame.number <= 4 || frame.number == 9 || frame.number == 10').score).toBe(0)
      // Precision 5/6 = 0.833 with full recall is Close; 5/7 = 0.714 is not.
      expect(gradeFilter(five, index, 'frame.number <= 6').score).toBe(0.5)
      expect(gradeFilter(five, index, 'frame.number <= 7').score).toBe(0)
      // Precision 1.0, recall 0.6.
      expect(gradeFilter(five, index, 'frame.number <= 3').score).toBe(0)
      // Matching everything: recall 1.0 but precision 5/15.
      expect(gradeFilter(five, index, 'frame').score).toBe(0)
      // Matching nothing: no division by zero, just 0.
      const none = gradeFilter(five, index, 'frame.number > 1000')
      expect(none).toMatchObject({ score: 0, matched: [] })
      expect(none.note).toBe('Matched 0 frames: 0 right, 0 extra, 5 missing.')
    })

    it('an exact match is still 1, and the engine passes the score through', () => {
      const exact = gradeFilter(from, index, CLIENT)
      expect(exact.score).toBe(1)
      expect(exact.note).toBe('Exact match — Matched 9 frames: 9 right, 0 extra, 0 missing.')
      expect(grade(from, { kind: 'filter', text: `${CLIENT} && frame.number <= 13` }, undefined, index)).toEqual({ score: 0.5, feedback: 'Close — Matched 8 frames: 8 right, 0 extra, 1 missing.' })
      expect(grade(from, { kind: 'filter', text: `${CLIENT} && frame.number <= 12` }, undefined, index).score).toBe(0)
    })
  })

  it('throws (FilterError) from gradeFilter itself on invalid syntax; the engine converts it into a grade', () => {
    expect(() => gradeFilter(q, index, 'tcp.flags.syn ==')).toThrow()
    expect(grade(q, { kind: 'filter', text: 'tcp.flags.syn ==' }, undefined, index)).toMatchObject({ score: 0 })
  })
})

// ---------------------------------------------------------------- drill

describe.each(loaded)('buildDrillWords on $sample.id', ({ index }) => {
  it('returns exactly the requested number of words (default 80, small, and larger than the pool)', () => {
    expect(buildDrillWords(index, seeded(1))).toHaveLength(80)
    expect(buildDrillWords(index, seeded(1), 1)).toHaveLength(1)
    expect(buildDrillWords(index, seeded(1), 25)).toHaveLength(25)
    expect(buildDrillWords(index, seeded(1), 500)).toHaveLength(500)
    expect(buildDrillWords(index, seeded(1), 0)).toHaveLength(0)
  })

  it('only produces non-empty, trimmed words with a known tag; terms, values and filters are 24 characters or fewer', () => {
    for (const w of buildDrillWords(index, seeded(3), 500)) {
      expect(w.text.length, JSON.stringify(w)).toBeGreaterThan(0)
      expect(w.text, JSON.stringify(w)).toBe(w.text.trim())
      expect(['term', 'field', 'value', 'filter']).toContain(w.tag)
      if (w.tag !== 'field') expect(w.text.length, `${w.tag}: ${w.text}`).toBeLessThanOrEqual(24)
    }
  })

  it('includes capture values and at least one field tag', () => {
    const words = buildDrillWords(index, seeded(5), 500)
    expect(words.some((w) => w.tag === 'field')).toBe(true)
    expect(words.some((w) => w.tag === 'value')).toBe(true)
    expect(words.some((w) => w.tag === 'term')).toBe(true)
    expect(words.some((w) => w.tag === 'filter')).toBe(true)
  })

  it('is deterministic for the same seeded rng and varies with the seed', () => {
    expect(buildDrillWords(index, seeded(7), 80)).toEqual(buildDrillWords(index, seeded(7), 80))
    expect(buildDrillWords(index, seeded(7), 80)).not.toEqual(buildDrillWords(index, seeded(8), 80))
  })
})

describe('buildDrillWords length limit', () => {
  // Regression: every drill word (including long field names) is at most 24 chars.
  it('never emits a word longer than 24 characters, including field names', () => {
    for (const { index } of loaded) for (const w of buildDrillWords(index, seeded(3), 1000)) expect(w.text.length, `${w.tag}: ${w.text}`).toBeLessThanOrEqual(24)
  })
})

describe('buildDrillWords content', () => {
  it('web-basic: contains the capture IPs and DNS name as values, and dns/tcp fields', () => {
    const words = buildDrillWords(web.index, seeded(11), 1000)
    const values = new Set(words.filter((w) => w.tag === 'value').map((w) => w.text))
    expect(values.has('93.184.216.34')).toBe(true)
    expect(values.has('192.168.1.23')).toBe(true)
    expect(values.has('www.example.com')).toBe(true)
    expect(values.has('80')).toBe(true)
    expect(values.has('GET')).toBe(true)
    const fields = new Set(words.filter((w) => w.tag === 'field').map((w) => w.text))
    expect(fields.has('tcp.flags.syn')).toBe(true)
    expect(fields.has('dns.qry.name')).toBe(true)
    expect([...fields].every((f) => f.includes('.'))).toBe(true)
  })

  it('web-basic: only offers fields for protocols present in the capture', () => {
    const fields = new Set(buildDrillWords(web.index, seeded(11), 1000).filter((w) => w.tag === 'field').map((w) => w.text))
    expect([...fields].some((f) => f.startsWith('arp.'))).toBe(false)
    expect([...fields].some((f) => f.startsWith('dhcp.'))).toBe(false)
  })

  it('https-visit: includes the SNI as a value', () => {
    const values = new Set(buildDrillWords(https.index, seeded(11), 1000).filter((w) => w.tag === 'value').map((w) => w.text))
    expect(values.has('secure.example.org')).toBe(true)
  })

  it('mixes tags within a normal 80-word round', () => {
    const tags = new Set(buildDrillWords(web.index, seeded(2), 80).map((w) => w.tag))
    expect(tags.size).toBeGreaterThanOrEqual(3)
  })
})

describe('drillStats', () => {
  it('computes WPM as correctChars / 5 per minute', () => {
    expect(drillStats(300, 300, 60, 60).wpm).toBe(60)
    expect(drillStats(150, 150, 30, 30).wpm).toBe(60) // same rate over half a minute
    expect(drillStats(600, 600, 100, 120).wpm).toBe(60)
    expect(drillStats(100, 120, 20, 60).wpm).toBe(20)
  })

  it('rounds WPM to a whole number', () => {
    expect(drillStats(101, 101, 20, 60).wpm).toBe(20) // 20.2
    expect(drillStats(103, 103, 20, 60).wpm).toBe(21) // 20.6
  })

  it('computes accuracy as correct / typed and errors as the difference', () => {
    const s = drillStats(90, 100, 18, 60)
    expect(s.accuracy).toBeCloseTo(0.9)
    expect(s.errors).toBe(10)
    expect(s.words).toBe(18)
    expect(drillStats(100, 100, 20, 60).accuracy).toBe(1)
  })

  it('has zero accuracy (not NaN) when nothing was typed', () => {
    expect(drillStats(0, 0, 0, 60)).toEqual({ wpm: 0, accuracy: 0, words: 0, errors: 0 })
  })

  it('clamps the elapsed time to at least one second', () => {
    const s = drillStats(5, 5, 1, 0)
    expect(Number.isFinite(s.wpm)).toBe(true)
    expect(s.wpm).toBe(60) // 1 word in 1 second
    expect(drillStats(5, 5, 1, -10).wpm).toBe(60)
  })
})

describe('drillXp', () => {
  const stats = (wpm: number, accuracy: number): DrillStats => ({ wpm, accuracy, words: 0, errors: 0 })

  it('is 0 when accuracy is 0, whatever the speed', () => {
    expect(drillXp(stats(0, 0))).toBe(0)
    expect(drillXp(stats(500, 0))).toBe(0)
  })

  it('is capped at 120', () => {
    expect(drillXp(stats(500, 1))).toBe(120)
    expect(drillXp(stats(151, 1))).toBe(120)
    expect(drillXp(stats(1000, 0.95))).toBe(120)
  })

  it('scales with speed and squared accuracy', () => {
    expect(drillXp(stats(100, 1))).toBe(80)
    expect(drillXp(stats(50, 1))).toBe(40)
    expect(drillXp(stats(100, 0.5))).toBe(20)
    expect(drillXp(stats(60, 0.9))).toBe(Math.round(60 * 0.81 * 0.8))
    expect(drillXp(stats(60, 0.9))).toBeLessThan(drillXp(stats(60, 1)))
    expect(drillXp(stats(30, 1))).toBeLessThan(drillXp(stats(60, 1)))
  })

  it('works end to end with drillStats', () => {
    expect(drillXp(drillStats(500, 500, 100, 60))).toBe(80) // 100 wpm at 100%
    expect(drillXp(drillStats(0, 40, 0, 60))).toBe(0)
  })
})
