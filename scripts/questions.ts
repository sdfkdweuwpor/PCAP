// Dev aid: prints the question bank for each sample.
import { dissectFrame } from '../src/core/dissect'
import { buildIndex, frameBytes, isnMapFromSummaries } from '../src/core/index/indexer'
import { buildQuestionBank } from '../src/game/engine'
import { SAMPLES } from '../src/samples/samples'

const verbose = process.argv.includes('-v')
const only = process.argv.find((a) => SAMPLES.some((s) => s.id === a))
for (const s of SAMPLES) {
  if (only && s.id !== only) continue
  const buf = s.build()
  const idx = buildIndex(buf, s.fileName)
  const isn = isnMapFromSummaries(idx.packets)
  const dissect = (no: number) => {
    const p = idx.packets[no - 1]
    return dissectFrame(frameBytes(buf, p), { no, ts: p.ts, relTime: p.relTime, origLen: p.origLen, linkType: p.linkType }, { tcpIsn: isn })
  }
  const bank = buildQuestionBank(idx, dissect)
  const modes = new Map<string, number>()
  for (const q of bank.questions) modes.set(q.mode, (modes.get(q.mode) ?? 0) + 1)
  console.log(`\n=== ${s.id}: ${bank.questions.length} questions`, Object.fromEntries(modes), `story steps: ${bank.story.steps.length}`)
  for (const r of bank.rejected) console.log('  REJECTED', r.id, r.reason)
  if (verbose) for (const q of bank.questions) {
    console.log(`- [${q.mode}/${q.tier}/${q.concept}] ${q.prompt}`)
    if (q.kind === 'choice') q.options.forEach((o, i) => console.log(`    ${i === q.correct ? '*' : ' '} ${o} (${o.length})`))
    if (q.kind === 'pick') console.log(`    answer: ${q.answer.join(',')}`)
    if (q.kind === 'order') console.log(`    ${q.cards.map((c) => c.label).join(' | ')}`)
    if (q.kind === 'field') console.log(`    keys: ${q.targetKeys} partial: ${q.partialKeys}`)
  }
}
