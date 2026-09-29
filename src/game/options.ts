// Multiple-choice option helpers. All options must be similar in length and structure so the correct
// answer can't be spotted by being the longest or most detailed.

/** Max allowed ratio between the longest and shortest option. */
export const MAX_LENGTH_RATIO = 1.25

const PADS = [
  ' here',
  ' now',
  ' in this packet',
  ' at this point',
  ' in this exchange',
  ' on this connection',
  ' at this stage of the exchange',
  ' at this point in the conversation',
]

function padTo(option: string, target: number): string {
  const end = /[.?!]$/.test(option) ? option.length - 1 : option.length
  const head = option.slice(0, end)
  const tail = option.slice(end)
  let best = option
  let bestGap = target - option.length
  for (const p of PADS) {
    const cand = head + p + tail
    const gap = target - cand.length
    if (Math.abs(gap) < Math.abs(bestGap) && cand.length <= target * 1.05) {
      best = cand
      bestGap = gap
    }
  }
  return best
}

export function lengthRatio(options: string[]): number {
  const lens = options.map((o) => o.length)
  return Math.max(...lens) / Math.max(1, Math.min(...lens))
}

/**
 * Pads short options with neutral qualifiers (applied to whichever options are short — correct or not)
 * until all are within MAX_LENGTH_RATIO. Returns null if that's impossible without rewriting.
 */
export function balanceOptions(options: string[]): string[] | null {
  let out = [...options]
  for (let pass = 0; pass < 3 && lengthRatio(out) > MAX_LENGTH_RATIO; pass++) {
    const longest = Math.max(...out.map((o) => o.length))
    out = out.map((o) => (o.length < longest * 0.85 ? padTo(o, longest) : o))
  }
  return lengthRatio(out) <= MAX_LENGTH_RATIO ? out : null
}

/** True when the correct answer is no more than a few characters longer than the longest distractor. */
export function correctNotLongest(options: string[], correctIndex = 0): boolean {
  const longestOther = Math.max(...options.filter((_, i) => i !== correctIndex).map((o) => o.length))
  return options[correctIndex].length <= longestOther + 3
}

export function shuffle<T>(xs: T[], rng: () => number): T[] {
  const a = [...xs]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1))
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

/** Builds a balanced, shuffled option list. Returns null if balancing fails or options repeat. */
export function makeOptions(correct: string, distractors: string[], rng: () => number): { options: string[]; correct: number } | null {
  const uniq = [...new Set(distractors.filter((d) => d !== correct))].slice(0, 3)
  if (uniq.length < 3) return null
  const raw = [correct, ...uniq]
  let balanced = balanceOptions(raw)
  if (!balanced) return null
  // Padding only the distractors would make the one unqualified option the answer, so the correct one gets a
  // qualifier too — or the question is dropped.
  if (balanced[0] === raw[0] && balanced.some((o, i) => o !== raw[i])) {
    const longest = Math.max(...balanced.map((o) => o.length))
    balanced = [padTo(raw[0], longest), ...balanced.slice(1)]
    if (balanced[0] === raw[0] || lengthRatio(balanced) > MAX_LENGTH_RATIO) return null
  }
  // The correct answer must not stand out as the longest.
  if (!correctNotLongest(balanced)) return null
  const order = shuffle([0, 1, 2, 3], rng)
  return { options: order.map((i) => balanced[i]), correct: order.indexOf(0) }
}
