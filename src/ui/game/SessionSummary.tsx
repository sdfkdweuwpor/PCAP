// End-of-session report: stat block, per-concept accuracy table (weakest first) and the
// missed-question review list.

import { useMemo, useState, type ReactNode } from 'react'
import { keyFieldsFor, Kb } from '../../game/knowledge'
import { CONCEPT_LABEL, MODE_INFO, type Concept, type Question } from '../../game/types'
import { useCapture } from '../../store/capture'
import { useGame, type Result } from '../../store/game'
import { Btn, Frame, Meter } from '../term'

export function SessionSummary() {
  const { results, sessionXp, sessionBest, sessionStart, playMode } = useGame()
  const correct = results.filter((r) => r.score >= 1).length
  const partial = results.filter((r) => r.score > 0 && r.score < 1).length
  const missedCount = results.length - correct - partial
  const acc = results.length ? Math.round(((correct + partial * 0.5) / results.length) * 100) : 0
  const [mins] = useState(() => (Date.now() - sessionStart) / 60000) // frozen when the report opens
  const missed = results.filter((r) => r.score < 1)
  const mode = playMode === 'story' ? 'story' : playMode === 'blitz' ? 'blitz' : playMode === 'mixed' ? 'mixed' : playMode ? MODE_INFO[playMode].name.toLowerCase() : ''

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
    <div className="scroll-thin flex-1 space-y-3 overflow-y-auto p-3 text-[12px]">
      <Frame title="session report" meta={mode || undefined} bodyClass="p-3">
        <dl className="space-y-1">
          <Line k="accuracy">
            <span className="text-accent tabular-nums">{acc}%</span>
          </Line>
          <Line k="correct">
            <span className="text-good tabular-nums">✓ {correct}</span>
            <span className="text-faint"> · </span>
            <span className="text-warn tabular-nums">~ {partial}</span> <span className="text-faint">partial</span>
            <span className="text-faint"> · </span>
            <span className="text-bad tabular-nums">✗ {missedCount}</span> <span className="text-faint">missed</span>
          </Line>
          <Line k="xp earned">
            <span className="tabular-nums">+{sessionXp}</span>
          </Line>
          <Line k="best streak">
            <span className="tabular-nums">{sessionBest}</span>
          </Line>
          <Line k="time">
            <span className="tabular-nums">{mins < 1 ? `${Math.round(mins * 60)}s` : `${mins.toFixed(1)}min`}</span>
          </Line>
        </dl>
      </Frame>

      {byConcept.length > 0 && (
        <Frame title="accuracy by concept" meta="weakest first" bodyClass="p-3">
          <table className="w-full border-collapse tabular-nums" aria-hidden>
            <tbody>
              {byConcept.map((d) => (
                <tr key={d.c}>
                  <td className="w-[10rem] truncate py-0.5 pr-3 text-muted">{CONCEPT_LABEL[d.c].toLowerCase()}</td>
                  <td className="py-0.5 pr-3">
                    <Meter value={d.acc} width={16} />
                  </td>
                  <td className="py-0.5 pr-3 text-right">{Math.round(d.acc * 100)}%</td>
                  <td className="py-0.5 text-right text-faint">n={d.n}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <table className="sr-only">
            <caption>Accuracy by concept, weakest first</caption>
            <tbody>
              {byConcept.map((d) => (
                <tr key={d.c}>
                  <th>{CONCEPT_LABEL[d.c]}</th>
                  <td>{Math.round(d.acc * 100)}%</td>
                  <td>{d.n} questions</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-[11px] text-faint"># low-scoring concepts come up more often next time.</p>
        </Frame>
      )}

      {missed.length > 0 && (
        <Frame title="review" meta={`${missed.length} missed`} bodyClass="p-1">
          <ul>
            {missed.map((r, i) => (
              <MissedItem key={i} r={r} />
            ))}
          </ul>
        </Frame>
      )}

      <div className="flex gap-2 pt-1">
        {playMode && (
          <Btn tone="primary" onClick={() => useGame.getState().start(playMode)}>
            play again
          </Btn>
        )}
        <Btn onClick={() => useGame.getState().toMenu()}>modes</Btn>
        <Btn
          onClick={() => {
            useGame.getState().toMenu()
            useCapture.getState().close()
          }}
        >
          home
        </Btn>
      </div>
    </div>
  )
}

function Line({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-2">
      <dt className="w-28 shrink-0 text-muted">{k}</dt>
      <dd className="m-0">{children}</dd>
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
    case 'text':
      return q.accept[0]
    case 'filter':
      return q.reference
  }
}

function MissedItem({ r }: { r: Result }) {
  const [open, setOpen] = useState(false)
  const index = useCapture((s) => s.index)!
  const kb = useMemo(() => new Kb(index), [index])
  const q = r.question
  return (
    <li className="border-b border-line last:border-b-0">
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} className="flex w-full items-start gap-2 px-2 py-1.5 text-left hover:bg-panel2">
        <span className="w-3 shrink-0 text-accent" aria-hidden>
          {open ? '-' : '+'}
        </span>
        <span className="min-w-0 flex-1">{q.prompt}</span>
        <span className="shrink-0 text-[11px] uppercase tracking-[0.1em] text-faint">{CONCEPT_LABEL[q.concept]}</span>
      </button>
      {open && (
        <div className="space-y-1 px-2 pb-2 pl-7">
          <p>
            <span className="text-good">answer </span>
            {answerText(q)}
          </p>
          <p className="text-muted">{q.explanation.means}</p>
          <button
            onClick={() => {
              const h = q.highlight[0]
              useCapture.getState().showMe(h.packet, h.fieldKeys?.length ? h.fieldKeys : keyFieldsFor(kb.classify(index.packets[h.packet - 1])))
            }}
            className="text-accent hover:underline"
          >
            ▸ show me
          </button>
        </div>
      )}
    </li>
  )
}
