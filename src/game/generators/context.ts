import type { CaptureIndex, Dissection, Field, PacketSummary } from '../../core/types'
import { Kb, KB, type Kind } from '../knowledge'
import { makeOptions } from '../options'
import type { ChoiceQuestion, Concept, Explanation, Highlight, Mode, Question, Tier } from '../types'

/** Everything a generator can look at. */
export class GenCtx {
  index: CaptureIndex
  kb: Kb
  rng: () => number
  kinds: Kind[]
  byKind = new Map<Kind, PacketSummary[]>()
  private dissector: (no: number) => Dissection

  constructor(index: CaptureIndex, dissect: (no: number) => Dissection, rng: () => number) {
    this.index = index
    this.kb = new Kb(index)
    this.rng = rng
    this.dissector = dissect
    this.kinds = index.packets.map((p) => this.kb.classify(p))
    index.packets.forEach((p, i) => {
      const k = this.kinds[i]
      let list = this.byKind.get(k)
      if (!list) this.byKind.set(k, (list = []))
      list.push(p)
    })
  }

  get packets(): PacketSummary[] {
    return this.index.packets
  }
  pkt(no: number): PacketSummary {
    return this.index.packets[no - 1]
  }
  kindOf(no: number): Kind {
    return this.kinds[no - 1]
  }
  of(kind: Kind): PacketSummary[] {
    return this.byKind.get(kind) ?? []
  }
  dissect(no: number): Dissection {
    return this.dissector(no)
  }
  /** Depth-first search for a field by key in a packet's tree. */
  findField(no: number, key: string): Field | undefined {
    const walk = (fs: Field[] | undefined): Field | undefined => {
      for (const f of fs ?? []) {
        if (f.key === key) return f
        const r = walk(f.children)
        if (r) return r
      }
      return undefined
    }
    return walk(this.dissect(no).layers)
  }
  pickOne<T>(xs: T[]): T {
    return xs[Math.floor(this.rng() * xs.length)]
  }
  explain(no: number): Explanation {
    return this.kb.explain(this.pkt(no), this.kindOf(no))
  }
  label(no: number): string {
    return this.kb.label(this.pkt(no), this.kindOf(no))
  }
}

export interface Generator {
  id: string
  mode: Mode
  /** Human description of what the capture must contain. */
  needs: string
  generate(ctx: GenCtx): Question[]
}

/** Spread-out sample of up to n items (first, middle, …) for variety without randomness bias. */
export function spread<T>(xs: T[], n: number): T[] {
  if (xs.length <= n) return xs
  const out: T[] = []
  for (let i = 0; i < n; i++) out.push(xs[Math.floor((i * xs.length) / n)])
  return out
}

export function choice(
  ctx: GenCtx,
  base: {
    id: string
    mode: Mode
    tier: Tier
    concept: Concept
    prompt: string
    hint: string
    explanation: Explanation
    highlight: Highlight[]
    focusPacket?: number
  },
  correct: string,
  distractors: string[],
): ChoiceQuestion | null {
  const o = makeOptions(correct, distractors, ctx.rng)
  if (!o) return null
  return { ...base, kind: 'choice', options: o.options, correct: o.correct }
}

/** Distractor statements for a packet kind, drawn from the kinds learners confuse it with. */
export function confusableStatements(kind: Kind): string[] {
  return KB[kind].confusables.map((k) => KB[k].statement)
}

export const tierOf: Partial<Record<Kind, Tier>> = {
  'tcp-syn': 'Recruit',
  'dns-query': 'Recruit',
  'dns-answer': 'Recruit',
  'http-request': 'Recruit',
  'http-ok': 'Recruit',
  'arp-request': 'Recruit',
  'arp-reply': 'Recruit',
  'icmp-echo-req': 'Recruit',
  'icmp-echo-reply': 'Recruit',
  'dhcp-discover': 'Recruit',
  'dhcp-offer': 'Recruit',
}
export const tierFor = (k: Kind): Tier => tierOf[k] ?? 'Analyst'

export const notNull = <T>(x: T | null | undefined): x is T => x !== null && x !== undefined
