// One question: header (mode, tier, progress, timer), prompt, the mode-specific answer UI, hint,
// then the explanation card.

import { AnimatePresence, motion, Reorder } from 'framer-motion'
import { useEffect, useMemo, useState } from 'react'
import { maskInfo } from '../../game/knowledge'
import { shuffle } from '../../game/options'
import { CONCEPT_LABEL, MODE_INFO, type ChoiceQuestion, type FieldQuestion, type OrderQuestion, type PickQuestion } from '../../game/types'
import { seeded } from '../../game/engine'
import { useCapture } from '../../store/capture'
import { BLITZ_SECONDS, useGame } from '../../store/game'
import { useProgress } from '../../store/progress'
import { useTicker } from '../hooks'
import { IconBulb, IconCheck, IconDown, IconGrip, IconTarget, IconUp, IconX } from '../icons'
import { ExplanationCard } from './ExplanationCard'
import { XpFloat } from './XpFloat'

const TIER_COLOR = { Recruit: 'var(--good)', Analyst: 'var(--accent)', Hunter: 'var(--bad)' }

export function QuestionView() {
  const { deck, idx, phase, hintUsed, questionStart, blitzEndsAt, playMode, feedback } = useGame()
  const q = deck[idx]
  const showTimer = useProgress((s) => s.settings.showTimer)
  const now = useTicker(phase === 'question', 250)

  // Blitz: end the session when time runs out.
  useEffect(() => {
    if (blitzEndsAt && now >= blitzEndsAt && phase === 'question') useGame.getState().finish()
  }, [now, blitzEndsAt, phase])

  // Keyboard: 1–4 for choices, Enter/→ for next.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement) return
      const g = useGame.getState()
      if (g.phase === 'feedback' && (e.key === 'n' || e.key === 'N')) {
        e.preventDefault()
        g.next()
      }
      const cur = g.deck[g.idx]
      if (g.phase === 'question' && cur?.kind === 'choice' && /^[1-4]$/.test(e.key)) g.submit({ kind: 'choice', index: Number(e.key) - 1 })
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  if (!q) return null
  const elapsed = Math.max(0, Math.floor(((phase === 'question' ? now : Date.now()) - questionStart) / 1000))
  const blitzLeft = blitzEndsAt ? Math.max(0, (blitzEndsAt - now) / 1000) : null

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 border-b border-line px-4 pb-2 pt-3">
        <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide">
          <span className="rounded bg-accent/15 px-1.5 py-0.5 text-accent">
            {MODE_INFO[q.mode === 'story' ? 'says' : q.mode].letter} · {MODE_INFO[q.mode].name}
          </span>
          <span style={{ color: TIER_COLOR[q.tier] }}>{q.tier}</span>
          <span className="truncate text-muted">{CONCEPT_LABEL[q.concept]}</span>
          <span className="ml-auto shrink-0 text-muted">
            {playMode === 'blitz' ? `#${idx + 1}` : `${idx + 1}/${deck.length}`}
          </span>
        </div>
        <div className="mt-2 flex items-center gap-2">
          <div className="h-1 flex-1 overflow-hidden rounded-full bg-panel3" aria-hidden>
            {blitzLeft !== null ? (
              <motion.div className="h-full origin-left rounded-full" style={{ background: blitzLeft < 10 ? 'var(--bad)' : 'var(--warn)', scaleX: blitzLeft / BLITZ_SECONDS }} />
            ) : (
              <motion.div className="h-full origin-left rounded-full bg-accent" animate={{ scaleX: (idx + (phase === 'feedback' ? 1 : 0)) / deck.length }} />
            )}
          </div>
          {blitzLeft !== null ? (
            <span className={`font-mono text-xs ${blitzLeft < 10 ? 'text-bad' : 'text-warn'}`} aria-live="off">
              {blitzLeft.toFixed(0)}s
            </span>
          ) : (
            showTimer && <span className="font-mono text-xs text-muted">{elapsed}s</span>
          )}
          <button onClick={() => useGame.getState().finish()} className="text-xs text-muted underline-offset-2 hover:text-fg hover:underline">
            End
          </button>
        </div>
      </div>

      <div className="scroll-thin relative min-h-0 flex-1 overflow-y-auto px-4 py-3">
        <AnimatePresence mode="wait">
          <motion.div key={q.id} initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ type: 'spring', stiffness: 300, damping: 30 }}>
            <h2 className="text-[15px] font-semibold leading-snug" id="q-prompt">
              {q.prompt}
            </h2>
            <div className="mt-3">
              {q.kind === 'pick' && <PickBody q={q} />}
              {q.kind === 'choice' && <ChoiceBody q={q} />}
              {q.kind === 'field' && <FieldBody q={q} />}
              {q.kind === 'order' && <OrderBody q={q} />}
            </div>
            {phase === 'question' && (
              <div className="mt-3">
                {hintUsed ? (
                  <motion.p initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} className="flex gap-2 rounded-lg border border-warn/40 bg-warn/10 p-2 text-sm">
                    <IconBulb size={16} className="mt-0.5 shrink-0 text-warn" /> {q.hint}
                  </motion.p>
                ) : (
                  <button onClick={() => useGame.getState().useHint()} className="flex items-center gap-1 text-xs text-muted hover:text-warn">
                    <IconBulb size={14} /> Hint (halves XP)
                  </button>
                )}
              </div>
            )}
            {phase === 'feedback' && feedback && <ExplanationCard q={q} feedback={feedback} />}
          </motion.div>
        </AnimatePresence>
        <XpFloat />
      </div>

      {phase === 'feedback' && (
        <div className="shrink-0 border-t border-line p-3">
          <button
            autoFocus
            onClick={() => useGame.getState().next()}
            className="w-full rounded-lg bg-accent py-2 font-semibold text-accent-ink hover:brightness-110"
          >
            {idx + 1 >= deck.length ? 'See session summary' : 'Next question'} <span className="text-xs opacity-70">(N)</span>
          </button>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------- Mode A

function PickBody({ q }: { q: PickQuestion }) {
  const selected = useCapture((s) => s.selected)
  const multi = useCapture((s) => s.multi)
  const index = useCapture((s) => s.index)!
  const reveal = useCapture((s) => s.revealSecrets)
  const phase = useGame((s) => s.phase)
  const p = selected ? index.packets[selected - 1] : null
  if (phase !== 'question') return null
  return (
    <div className="rounded-lg border border-line bg-panel2 p-3 text-sm">
      <p className="flex items-center gap-2 text-xs text-muted">
        <IconTarget size={14} />
        {q.multi
          ? 'Click each matching row in the packet list (click again to unselect), then submit.'
          : 'Click a row in the packet list, then submit — or double-click the row / press Enter.'}
      </p>
      {q.multi ? (
        <div className="mt-2 flex min-h-7 flex-wrap gap-1">
          {multi.length === 0 && <span className="text-xs text-faint">Nothing selected yet.</span>}
          {[...multi].sort((a, b) => a - b).map((n) => (
            <button key={n} onClick={() => useCapture.getState().toggleMulti(n)} className="rounded-full border border-accent/60 bg-accent/10 px-2 py-0.5 font-mono text-xs" aria-label={`Remove packet ${n}`}>
              #{n} ✕
            </button>
          ))}
        </div>
      ) : (
        <p className="mt-2 truncate font-mono text-xs">{p ? `#${p.no}  ${p.protocol}  ${reveal ? p.info : maskInfo(p)}` : <span className="text-faint">No packet selected.</span>}</p>
      )}
      <button
        disabled={q.multi ? multi.length === 0 : !selected}
        onClick={() => useGame.getState().submit({ kind: 'pick', packets: q.multi ? multi : [selected!] })}
        className="mt-3 w-full rounded-lg bg-accent py-2 font-semibold text-accent-ink disabled:opacity-40"
      >
        {q.multi ? `Submit ${multi.length} packet${multi.length === 1 ? '' : 's'}` : selected ? `Submit packet #${selected}` : 'Select a packet'}
      </button>
    </div>
  )
}

// ---------------------------------------------------------------- Modes B, C, F

export function ChoiceBody({ q, chosen, onChoose, locked }: { q: ChoiceQuestion; chosen?: number | null; onChoose?: (i: number) => void; locked?: boolean }) {
  const phase = useGame((s) => s.phase)
  const feedback = useGame((s) => s.feedback)
  const answered = onChoose ? chosen !== null && chosen !== undefined : phase === 'feedback'
  const pick = onChoose ? chosen : feedback?.answer.kind === 'choice' ? feedback.answer.index : null
  return (
    <div role="radiogroup" aria-labelledby="q-prompt" className="flex flex-col gap-2">
      {q.options.map((o, i) => {
        const isCorrect = i === q.correct
        const isPicked = pick === i
        const state = !answered ? 'idle' : isCorrect ? 'correct' : isPicked ? 'wrong' : 'dim'
        return (
          <motion.button
            key={i}
            role="radio"
            aria-checked={isPicked}
            disabled={answered || locked}
            onClick={() => (onChoose ? onChoose(i) : useGame.getState().submit({ kind: 'choice', index: i }))}
            animate={state === 'wrong' ? { x: [0, -6, 5, -3, 0] } : state === 'correct' ? { scale: [1, 1.02, 1] } : {}}
            transition={{ duration: 0.4 }}
            className={`flex items-start gap-2 rounded-lg border p-2.5 text-left text-sm transition-colors ${
              state === 'correct'
                ? 'border-good bg-good/15'
                : state === 'wrong'
                  ? 'border-bad bg-bad/15'
                  : state === 'dim'
                    ? 'border-line opacity-60'
                    : 'border-line bg-panel2 hover:border-accent'
            }`}
          >
            <span className="mt-px grid h-5 w-5 shrink-0 place-items-center rounded border border-line font-mono text-[11px] text-muted">
              {state === 'correct' ? <IconCheck size={12} className="text-good" /> : state === 'wrong' ? <IconX size={12} className="text-bad" /> : i + 1}
            </span>
            <span>
              {o}
              {state === 'correct' && <span className="sr-only"> (correct answer)</span>}
              {state === 'wrong' && <span className="sr-only"> (your answer, incorrect)</span>}
            </span>
          </motion.button>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------- Mode D

function FieldBody({ q }: { q: FieldQuestion }) {
  const pick = useGame((s) => s.fieldPick)
  const phase = useGame((s) => s.phase)
  if (phase !== 'question') return null
  return (
    <div className="rounded-lg border border-line bg-panel2 p-3 text-sm">
      <p className="flex items-center gap-2 text-xs text-muted">
        <IconTarget size={14} /> Packet #{q.packet} is locked in the viewer. Click the field in the details tree, or its bytes in the hex pane.
      </p>
      <p className="mt-2 text-xs">
        Your pick:{' '}
        {pick ? (
          <span className="font-mono">
            {pick.name} <span className="text-muted">({pick.via === 'hex' ? `byte ${pick.offset}` : 'tree'})</span>
          </span>
        ) : (
          <span className="text-faint">nothing yet</span>
        )}
      </p>
      <button
        disabled={!pick}
        onClick={() => pick && useGame.getState().submit({ kind: 'field', key: pick.key, offset: pick.offset, via: pick.via })}
        className="mt-3 w-full rounded-lg bg-accent py-2 font-semibold text-accent-ink disabled:opacity-40"
      >
        Submit field
      </button>
    </div>
  )
}

// ---------------------------------------------------------------- Mode E

function OrderBody({ q }: { q: OrderQuestion }) {
  const phase = useGame((s) => s.phase)
  const feedback = useGame((s) => s.feedback)
  const initial = useMemo(() => {
    const rng = seeded(q.id.length * 7919 + q.cards.length)
    let s = shuffle(q.cards, rng)
    // Never start already solved.
    if (s.every((c, i) => c.id === q.cards[i].id)) s = [...s.slice(1), s[0]]
    return s
  }, [q])
  const [items, setItems] = useState(initial)
  const submitted = feedback?.answer.kind === 'order' ? feedback.answer.ids : null

  // On submit, cards glide into the correct order.
  useEffect(() => {
    if (phase === 'feedback') {
      const t = setTimeout(() => setItems(q.cards), 350)
      return () => clearTimeout(t)
    }
  }, [phase, q.cards])

  const move = (i: number, d: number) => {
    const j = i + d
    if (j < 0 || j >= items.length) return
    const next = [...items]
    ;[next[i], next[j]] = [next[j], next[i]]
    setItems(next)
  }

  return (
    <div>
      <p className="mb-2 text-xs text-muted">{phase === 'question' ? 'Drag the cards (or use the arrows) so the first packet on the wire is at the top.' : 'The real order on the wire:'}</p>
      <Reorder.Group axis="y" values={items} onReorder={setItems} className="flex flex-col gap-1.5" aria-label="Cards to order">
        {items.map((c, i) => {
          const wasAt = submitted ? submitted.indexOf(c.id) : -1
          const right = submitted ? wasAt === q.cards.findIndex((x) => x.id === c.id) : null
          return (
            <Reorder.Item
              key={c.id}
              value={c}
              dragListener={phase === 'question'}
              className={`flex select-none items-center gap-2 rounded-lg border px-2 py-2 text-sm ${
                right === null ? 'border-line bg-panel2' : right ? 'border-good/70 bg-good/10' : 'border-bad/70 bg-bad/10'
              } ${phase === 'question' ? 'cursor-grab active:cursor-grabbing' : ''}`}
              whileDrag={{ scale: 1.03, boxShadow: 'var(--shadow)' }}
            >
              {phase === 'question' ? <IconGrip size={14} className="shrink-0 text-muted" /> : <span className="w-4 shrink-0 text-center font-mono text-xs text-muted">{i + 1}</span>}
              <span className="min-w-0 flex-1 truncate font-mono text-xs">{c.label}</span>
              {right !== null && (right ? <IconCheck size={14} className="text-good" aria-label="was in the right place" /> : <IconX size={14} className="text-bad" aria-label="was in the wrong place" />)}
              {phase === 'question' && (
                <span className="flex shrink-0 gap-0.5">
                  <button onClick={() => move(i, -1)} disabled={i === 0} className="rounded p-0.5 text-muted hover:text-fg disabled:opacity-30" aria-label={`Move ${c.label} up`}>
                    <IconUp size={14} />
                  </button>
                  <button onClick={() => move(i, 1)} disabled={i === items.length - 1} className="rounded p-0.5 text-muted hover:text-fg disabled:opacity-30" aria-label={`Move ${c.label} down`}>
                    <IconDown size={14} />
                  </button>
                </span>
              )}
            </Reorder.Item>
          )
        })}
      </Reorder.Group>
      {phase === 'question' && (
        <button onClick={() => useGame.getState().submit({ kind: 'order', ids: items.map((c) => c.id) })} className="mt-3 w-full rounded-lg bg-accent py-2 font-semibold text-accent-ink">
          Submit order
        </button>
      )}
    </div>
  )
}
