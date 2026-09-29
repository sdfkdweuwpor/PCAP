// End-of-session summary: accuracy, time, best streak, XP, per-concept accuracy chart and the
// missed-question review list.

import { AnimatePresence, motion } from 'framer-motion'
import { useMemo, useState } from 'react'
import { keyFieldsFor, Kb } from '../../game/knowledge'
import { CONCEPT_LABEL, MODE_INFO, type Concept, type Question } from '../../game/types'
import { useCapture } from '../../store/capture'
import { useGame, type Result } from '../../store/game'
import { IconChevron, IconEye, IconRefresh } from '../icons'

export function SessionSummary() {
  const { results, sessionXp, sessionBest, sessionStart, playMode } = useGame()
  const correct = results.filter((r) => r.score >= 1).length
  const partial = results.filter((r) => r.score > 0 && r.score < 1).length
  const acc = results.length ? Math.round(((correct + partial * 0.5) / results.length) * 100) : 0
  const mins = (Date.now() - sessionStart) / 60000
  const missed = results.filter((r) => r.score < 1)

  const byConcept = useMemo(() => {
    const m = new Map<Concept, { n: number; s: number }>()
    for (const r of results) {
      const e = m.get(r.question.concept) ?? { n: 0, s: 0 }
      e.n++
      e.s += r.score
      m.set(r.question.concept, e)
    }
    return [...m.entries()].map(([c, e]) => ({ c, n: e.n, acc: e.s / e.n })).sort((a, b) => a.acc - b.acc)
  }, [results])

  return (
    <div className="scroll-thin flex-1 overflow-y-auto p-4">
      <motion.h2 initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} className="text-lg font-bold">
        Session complete
      </motion.h2>
      <p className="text-sm text-muted">{playMode === 'story' ? 'Story mode' : playMode === 'blitz' ? 'Blitz' : playMode === 'mixed' ? 'Mixed' : playMode ? MODE_INFO[playMode].name : ''}</p>

      <div className="mt-3 grid grid-cols-2 gap-2">
        <Stat label="Accuracy" value={`${acc}%`} sub={`${correct} right · ${partial} partial · ${results.length - correct - partial} missed`} />
        <Stat label="XP earned" value={`+${sessionXp}`} />
        <Stat label="Best streak" value={String(sessionBest)} />
        <Stat label="Time" value={mins < 1 ? `${Math.round(mins * 60)} s` : `${mins.toFixed(1)} min`} />
      </div>

      {byConcept.length > 0 && (
        <section className="mt-5">
          <h3 className="text-sm font-semibold">Accuracy by concept</h3>
          <p className="mb-2 text-xs text-muted">Weakest first. Low-scoring concepts come up more often next time.</p>
          <ConceptBars data={byConcept} />
        </section>
      )}

      {missed.length > 0 && (
        <section className="mt-5">
          <h3 className="mb-2 text-sm font-semibold">Review what you missed</h3>
          <ul className="flex flex-col gap-2">
            {missed.map((r, i) => (
              <MissedItem key={i} r={r} />
            ))}
          </ul>
        </section>
      )}

      <div className="mt-5 flex gap-2">
        {playMode && (
          <button onClick={() => useGame.getState().start(playMode)} className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-accent py-2 font-semibold text-accent-ink">
            <IconRefresh size={14} /> Play again
          </button>
        )}
        <button onClick={() => useGame.getState().toMenu()} className="flex-1 rounded-lg border border-line py-2 font-semibold">
          All modes
        </button>
      </div>
    </div>
  )
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel2 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">{label}</p>
      <motion.p initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="font-mono text-xl font-bold">
        {value}
      </motion.p>
      {sub && <p className="text-[11px] text-muted">{sub}</p>}
    </div>
  )
}

/** Single-series horizontal bar chart: one hue, rounded data-ends, values in text ink, hover tooltip. */
function ConceptBars({ data }: { data: { c: Concept; n: number; acc: number }[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const rowH = 26
  const labelW = 118
  const W = 340
  const barW = W - labelW - 46
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${data.length * rowH + 16}`} width="100%" role="img" aria-label="Accuracy by concept">
        {[0, 0.5, 1].map((t) => (
          <g key={t}>
            <line x1={labelW + t * barW} x2={labelW + t * barW} y1={0} y2={data.length * rowH} stroke="var(--line)" strokeWidth={1} />
            <text x={labelW + t * barW} y={data.length * rowH + 12} fontSize={9} textAnchor="middle" fill="var(--faint)">
              {t * 100}%
            </text>
          </g>
        ))}
        {data.map((d, i) => {
          const y = i * rowH + 6
          const w = Math.max(4, d.acc * barW)
          return (
            <g key={d.c} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
              <rect x={0} y={y - 4} width={W} height={rowH} fill={hover === i ? 'var(--panel-3)' : 'transparent'} />
              <text x={labelW - 8} y={y + 10} fontSize={11} textAnchor="end" fill="var(--fg)">
                {CONCEPT_LABEL[d.c]}
              </text>
              <motion.rect
                x={labelW}
                y={y + 1}
                height={12}
                rx={4}
                fill="var(--accent)"
                initial={{ width: 0 }}
                animate={{ width: w }}
                transition={{ delay: 0.05 * i, type: 'spring', stiffness: 140, damping: 20 }}
              />
              <text x={labelW + w + 6} y={y + 11} fontSize={10} fill="var(--muted)" fontFamily="var(--font-mono)">
                {Math.round(d.acc * 100)}%
              </text>
            </g>
          )
        })}
      </svg>
      {hover !== null && (
        <div className="pointer-events-none absolute right-0 top-0 rounded-md border border-line bg-panel px-2 py-1 text-xs shadow-lg" role="tooltip">
          <strong>{CONCEPT_LABEL[data[hover].c]}</strong>: {Math.round(data[hover].acc * 100)}% over {data[hover].n} question{data[hover].n > 1 ? 's' : ''}
        </div>
      )}
      <table className="sr-only">
        <caption>Accuracy by concept</caption>
        <tbody>
          {data.map((d) => (
            <tr key={d.c}>
              <th>{CONCEPT_LABEL[d.c]}</th>
              <td>{Math.round(d.acc * 100)}%</td>
              <td>{d.n} questions</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function answerText(q: Question): string {
  switch (q.kind) {
    case 'choice':
      return q.options[q.correct]
    case 'pick':
      return q.answer.slice(0, 4).map((n) => `#${n}`).join(', ') + (q.answer.length > 4 ? '…' : '')
    case 'field':
      return `${q.targetLabel} in packet #${q.packet}`
    case 'order':
      return q.cards.map((c) => c.label).join(' → ')
  }
}

function MissedItem({ r }: { r: Result }) {
  const [open, setOpen] = useState(false)
  const index = useCapture((s) => s.index)!
  const kb = useMemo(() => new Kb(index), [index])
  const q = r.question
  return (
    <li className="rounded-lg border border-line bg-panel2">
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} className="flex w-full items-start gap-2 p-2 text-left text-sm">
        <motion.span animate={{ rotate: open ? 90 : 0 }} className="mt-0.5 shrink-0 text-muted">
          <IconChevron size={12} />
        </motion.span>
        <span className="min-w-0 flex-1">{q.prompt}</span>
        <span className="shrink-0 text-[10px] uppercase text-muted">{CONCEPT_LABEL[q.concept]}</span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-1 px-7 pb-3 text-xs">
            <p>
              <span className="font-semibold text-good">Answer: </span>
              {answerText(q)}
            </p>
            <p className="text-muted">{q.explanation.means}</p>
            <button
              onClick={() => {
                const h = q.highlight[0]
                useCapture.getState().showMe(h.packet, h.fieldKeys?.length ? h.fieldKeys : keyFieldsFor(kb.classify(index.packets[h.packet - 1])))
              }}
              className="mt-1 flex items-center gap-1 text-accent"
            >
              <IconEye size={12} /> Show me
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </li>
  )
}
