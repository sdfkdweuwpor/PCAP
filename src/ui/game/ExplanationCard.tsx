// After every answer: verdict, what it says / means / why it matters, "Show me", a mini flow replay,
// and a collapsible RFC-level deeper dive.

import { AnimatePresence, motion } from 'framer-motion'
import { useMemo, useState } from 'react'
import { aiAvailable, aiExplain } from '../../game/ai'
import { Kb, keyFieldsFor, maskInfo } from '../../game/knowledge'
import type { Question } from '../../game/types'
import { useCapture } from '../../store/capture'
import type { Feedback } from '../../store/game'
import { useProgress } from '../../store/progress'
import { IconBook, IconCheck, IconChevron, IconEye, IconHalf, IconSpark, IconX } from '../icons'
import { FlowView } from '../panes/FlowView'

export function ExplanationCard({ q, feedback }: { q: Question; feedback: Feedback }) {
  const index = useCapture((s) => s.index)!
  const kb = useMemo(() => new Kb(index), [index])
  const [deep, setDeep] = useState(false)
  const [replay, setReplay] = useState(1)
  const aiOn = useProgress((s) => s.settings.aiExplain)
  const [ai, setAi] = useState<string | null>(null)
  const { score } = feedback.grade
  const verdict = score >= 1 ? 'correct' : score > 0 ? 'partial' : 'wrong'

  // Wrong pick: explain what the learner's packet actually was.
  const wrongPick =
    q.kind === 'pick' && feedback.answer.kind === 'pick' && score < 1
      ? feedback.answer.packets.filter((n) => !q.answer.includes(n)).slice(0, 3).map((n) => kb.describe(index.packets[n - 1]))
      : []
  const correctText =
    q.kind === 'choice' && score < 1
      ? `Correct answer: ${q.options[q.correct]}`
      : q.kind === 'pick' && score < 1
        ? `Correct: ${q.answer.length > 3 ? `any of ${q.answer.length} packets, e.g. ` : ''}${q.answer
            .slice(0, 3)
            .map((n) => `#${n} (${maskInfo(index.packets[n - 1]).slice(0, 48)})`)
            .join(', ')}`
        : null

  const frames = useMemo(() => {
    const hs = [...new Set(q.highlight.map((h) => h.packet))].sort((a, b) => a - b)
    // Give a little context: one packet before the first highlight, within the same conversation.
    const first = index.packets[hs[0] - 1]
    const conv = first && first.streamId >= 0 ? index.conversations[first.streamId] : null
    const prev = conv?.packets.filter((n) => n < hs[0]).pop()
    return (prev && hs.length < 6 ? [prev, ...hs] : hs).slice(0, 10)
  }, [q, index])

  const showMe = () => {
    const cap = useCapture.getState()
    const h = q.highlight[0]
    const keys = h.fieldKeys?.length ? h.fieldKeys : keyFieldsFor(kb.classify(index.packets[h.packet - 1]))
    cap.showMe(h.packet, keys)
    setReplay((r) => r + 1)
  }

  const Icon = verdict === 'correct' ? IconCheck : verdict === 'partial' ? IconHalf : IconX
  const color = verdict === 'correct' ? 'var(--good)' : verdict === 'partial' ? 'var(--warn)' : 'var(--bad)'
  const label = verdict === 'correct' ? 'Correct!' : verdict === 'partial' ? 'Partly right' : 'Not quite'

  return (
    <motion.section
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.15, type: 'spring', stiffness: 260, damping: 26 }}
      className="mt-4 overflow-hidden rounded-xl border bg-panel2"
      style={{ borderColor: `color-mix(in srgb, ${color} 55%, transparent)` }}
      aria-live="polite"
    >
      <div className="flex items-center gap-2 px-3 py-2" style={{ background: `color-mix(in srgb, ${color} 14%, transparent)` }}>
        <Icon size={18} style={{ color }} />
        <strong style={{ color }}>{label}</strong>
        <span className="text-sm text-muted">{feedback.grade.feedback}</span>
        {feedback.xp.total > 0 && <span className="ml-auto font-mono text-xs font-semibold text-accent">+{feedback.xp.total} XP</span>}
      </div>
      <div className="space-y-3 p-3 text-sm">
        {wrongPick.map((w) => (
          <p key={w} className="rounded-md border border-bad/30 bg-bad/5 p-2 text-xs">
            <span className="font-semibold text-bad">You picked </span>
            {w}
          </p>
        ))}
        {correctText && <p className="text-xs font-semibold">{correctText}</p>}
        <Section title="What it says">
          <span className="font-mono text-xs">{q.explanation.says}</span>
        </Section>
        <Section title="What it means">{q.explanation.means}</Section>
        <Section title="Why it matters">{q.explanation.matters}</Section>

        <div className="flex flex-wrap gap-2">
          <button onClick={showMe} className="flex items-center gap-1.5 rounded-lg border border-accent/60 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/10">
            <IconEye size={14} /> Show me
          </button>
          {aiOn && (
            <button
              onClick={async () => {
                setAi('…')
                try {
                  setAi(await aiExplain({ question: q.prompt, context: q.explanation.says }))
                } catch (e) {
                  setAi(e instanceof Error ? e.message : String(e))
                }
              }}
              className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-muted hover:text-fg"
              title={aiAvailable() ? 'Sends only the masked summary above to your configured AI provider' : 'No AI provider configured'}
            >
              <IconSpark size={14} /> AI explain <span className="rounded bg-warn/20 px-1 text-[9px] font-bold uppercase text-warn">external</span>
            </button>
          )}
        </div>
        {ai && <p className="rounded-md border border-line p-2 text-xs text-muted">{ai}</p>}

        <div className="overflow-hidden rounded-lg border border-line bg-panel">
          <p className="border-b border-line px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-muted">Flow replay</p>
          <FlowView frames={frames} compact autoPlay highlight={q.highlight.map((h) => h.packet)} playToken={replay} />
        </div>

        {q.explanation.deeper && (
          <div>
            <button onClick={() => setDeep((d) => !d)} aria-expanded={deep} className="flex items-center gap-1 text-xs text-muted hover:text-fg">
              <motion.span animate={{ rotate: deep ? 90 : 0 }}>
                <IconChevron size={12} />
              </motion.span>
              <IconBook size={13} /> Deeper dive
            </button>
            <AnimatePresence>
              {deep && (
                <motion.p initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="mt-1 rounded-md bg-panel3 p-2 text-xs leading-relaxed text-muted">
                  {q.explanation.deeper}
                </motion.p>
              )}
            </AnimatePresence>
          </div>
        )}
      </div>
    </motion.section>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-muted">{title}</h3>
      <p className="mt-0.5 leading-relaxed">{children}</p>
    </div>
  )
}
