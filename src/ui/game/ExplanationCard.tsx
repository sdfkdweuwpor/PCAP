// Graded log shown after every answer: verdict, says / means / why, "show me", flow replay, deeper dive.

import { useMemo, useState } from 'react'
import { aiAvailable, aiExplain } from '../../game/ai'
import { Kb, keyFieldsFor, maskInfo } from '../../game/knowledge'
import type { Question } from '../../game/types'
import { useCapture } from '../../store/capture'
import type { Feedback } from '../../store/game'
import { useProgress } from '../../store/progress'
import { FlowView } from '../panes/FlowView'
import { Btn } from '../term'

export function ExplanationCard({ q, feedback }: { q: Question; feedback: Feedback }) {
  const index = useCapture((s) => s.index)!
  const kb = useMemo(() => new Kb(index), [index])
  const [deep, setDeep] = useState(false)
  const [replay, setReplay] = useState(1)
  const aiOn = useProgress((s) => s.settings.aiExplain)
  const [ai, setAi] = useState<string | null>(null)
  const { score } = feedback.grade
  const verdict = score >= 1 ? 'ok' : score > 0 ? 'partial' : 'fail'
  const x = feedback.xp

  const wrongPick =
    q.kind === 'pick' && feedback.answer.kind === 'pick' && score < 1
      ? feedback.answer.packets.filter((n) => !q.answer.includes(n)).slice(0, 3).map((n) => kb.describe(index.packets[n - 1]))
      : []
  const correction =
    q.kind === 'choice' && score < 1
      ? q.options[q.correct]
      : q.kind === 'pick' && score < 1
        ? `${q.answer.length > 3 ? `any of ${q.answer.length}, e.g. ` : ''}${q.answer
            .slice(0, 3)
            .map((n) => `#${n} ${maskInfo(index.packets[n - 1]).slice(0, 44)}`)
            .join('  ')}`
        : null

  const frames = useMemo(() => {
    const hs = [...new Set(q.highlight.map((h) => h.packet))].sort((a, b) => a - b)
    const first = index.packets[hs[0] - 1]
    const conv = first && first.streamId >= 0 ? index.conversations[first.streamId] : null
    const prev = conv?.packets.filter((n) => n < hs[0]).pop()
    return (prev && hs.length < 6 ? [prev, ...hs] : hs).slice(0, 10)
  }, [q, index])

  const showMe = () => {
    const h = q.highlight[0]
    const keys = h.fieldKeys?.length ? h.fieldKeys : keyFieldsFor(kb.classify(index.packets[h.packet - 1]))
    useCapture.getState().showMe(h.packet, keys)
    setReplay((r) => r + 1)
  }

  const tone = verdict === 'ok' ? 'text-good' : verdict === 'partial' ? 'text-warn' : 'text-bad'
  const bar = verdict === 'ok' ? 'border-good' : verdict === 'partial' ? 'border-warn' : 'border-bad'

  return (
    <section className={`mt-4 border-l-2 ${bar} pl-3 text-[12.5px]`} aria-live="polite">
      <p className="type-in">
        <span className={`font-semibold ${tone}`}>{verdict === 'ok' ? '[ ok ]' : verdict === 'partial' ? '[half]' : '[fail]'}</span>{' '}
        <span className="text-muted">{feedback.grade.feedback}</span>
      </p>
      {x.total > 0 && (
        <p className="text-[11.5px] tabular-nums text-faint">
          <span className="text-accent">+{x.total}xp</span> = base {x.base}
          {x.speed > 0 && ` + speed ${x.speed}`}
          {x.streak > 0 && ` + streak ${x.streak}`}
          {x.hintPenalty > 0 && ` − hint ${x.hintPenalty}`}
        </p>
      )}
      {wrongPick.map((w) => (
        <p key={w} className="mt-1 text-[12px]">
          <span className="text-bad">you picked</span> <span className="text-muted">{w}</span>
        </p>
      ))}
      {correction && (
        <p className="mt-1 text-[12px]">
          <span className="text-good">answer</span> {correction}
        </p>
      )}

      <dl className="mt-3 grid grid-cols-[3.6rem_1fr] gap-x-2 gap-y-1.5 leading-relaxed">
        <dt className="text-faint">says</dt>
        <dd className="break-words text-[12px] text-muted">{q.explanation.says}</dd>
        <dt className="text-faint">means</dt>
        <dd>{q.explanation.means}</dd>
        <dt className="text-faint">why</dt>
        <dd>{q.explanation.matters}</dd>
      </dl>

      <div className="mt-3 flex flex-wrap gap-2">
        <Btn onClick={showMe} className="py-1">
          show me
        </Btn>
        {q.explanation.deeper && (
          <Btn onClick={() => setDeep((d) => !d)} aria-expanded={deep} className="py-1">
            {deep ? 'hide rfc' : 'rfc detail'}
          </Btn>
        )}
        {aiOn && (
          <Btn
            className="py-1"
            title={aiAvailable() ? 'Sends only the masked summary above to your configured provider' : 'No AI provider configured in this build'}
            onClick={async () => {
              setAi('…')
              try {
                setAi(await aiExplain({ question: q.prompt, context: q.explanation.says }))
              } catch (e) {
                setAi(e instanceof Error ? e.message : String(e))
              }
            }}
          >
            ai explain <span className="text-warn">(external)</span>
          </Btn>
        )}
      </div>
      {deep && <p className="mt-2 border border-line bg-panel2 p-2 text-[11.5px] leading-relaxed text-muted">{q.explanation.deeper}</p>}
      {ai && <p className="mt-2 border border-line p-2 text-[11.5px] text-muted">{ai}</p>}

      <div className="mt-3 border border-line">
        <p className="border-b border-line px-2 py-0.5 text-[10.5px] uppercase tracking-[0.12em] text-faint">replay · {frames.length} frames</p>
        <FlowView frames={frames} compact autoPlay highlight={q.highlight.map((h) => h.packet)} playToken={replay} />
      </div>
    </section>
  )
}
