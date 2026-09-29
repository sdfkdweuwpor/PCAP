// Mode G: narrated walkthrough. Each step highlights a packet, replays it in the flow view,
// explains it, and sometimes asks a quick check before moving on.

import { AnimatePresence, motion } from 'framer-motion'
import { useEffect } from 'react'
import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'
import { IconArrowLeft, IconArrowRight, IconBook } from '../icons'
import { FlowView } from '../panes/FlowView'
import { ChoiceBody } from './QuestionView'

export function StoryPlayer() {
  const story = useCapture((s) => s.bank?.story)!
  const idx = useGame((s) => s.storyIdx)
  const checked = useGame((s) => s.storyChecked)
  const { storyGo, storyCheck, finish, toMenu } = useGame.getState()
  const step = story.steps[idx]
  const needsCheck = !!step?.check && checked === null
  const last = idx >= story.steps.length - 1

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) return
      if (e.key === 'ArrowRight' && !needsCheck) {
        if (last) finish()
        else storyGo(idx + 1)
      }
      if (e.key === 'ArrowLeft' && idx > 0) storyGo(idx - 1)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [idx, needsCheck, last, storyGo, finish])

  if (!step)
    return (
      <div className="p-4 text-sm text-muted">
        This capture has nothing to narrate.{' '}
        <button className="text-accent underline" onClick={toMenu}>
          Back
        </button>
      </div>
    )

  const frames = story.steps.slice(0, idx + 1).map((s) => s.packet)
  const uniq = [...new Set(frames)].sort((a, b) => a - b).slice(-10)

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 border-b border-line px-4 pb-2 pt-3">
        <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide">
          <span className="flex items-center gap-1 rounded bg-accent/15 px-1.5 py-0.5 text-accent">
            <IconBook size={12} /> G · Story mode
          </span>
          <span className="ml-auto text-muted">
            Step {idx + 1}/{story.steps.length}
          </span>
          <button onClick={finish} className="text-xs normal-case text-muted hover:text-fg">
            End
          </button>
        </div>
        <div className="mt-2 flex gap-0.5" aria-hidden>
          {story.steps.map((_, i) => (
            <motion.span key={i} className="h-1 flex-1 rounded-full" animate={{ backgroundColor: i <= idx ? 'var(--accent)' : 'var(--panel-3)' }} />
          ))}
        </div>
      </div>

      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-4 py-3">
        <AnimatePresence mode="wait">
          <motion.div key={idx} initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -24 }} transition={{ type: 'spring', stiffness: 300, damping: 30 }}>
            <h2 className="font-mono text-sm font-semibold text-accent">{step.title}</h2>
            <p className="mt-2 text-[15px] leading-relaxed">{step.narration}</p>
            <div className="mt-3 overflow-hidden rounded-lg border border-line bg-panel">
              <FlowView key={idx} frames={uniq} compact autoPlay startAt={Math.max(0, uniq.indexOf(step.packet))} highlight={[step.packet]} />
            </div>
            {step.check && (
              <div className="mt-4 rounded-xl border border-accent/40 bg-accent/5 p-3">
                <p id="q-prompt" className="mb-2 text-sm font-semibold">
                  {step.check.prompt}
                </p>
                <ChoiceBody q={step.check} chosen={checked} onChoose={storyCheck} />
                {checked !== null && (
                  <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className={`mt-2 text-xs ${checked === step.check.correct ? 'text-good' : 'text-bad'}`}>
                    {checked === step.check.correct ? '✓ Right — ' : '✗ Not quite — '}
                    {step.check.explanation.matters}
                  </motion.p>
                )}
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      <div className="flex shrink-0 gap-2 border-t border-line p-3">
        <button disabled={idx === 0} onClick={() => storyGo(idx - 1)} className="flex items-center gap-1 rounded-lg border border-line px-3 py-2 text-sm disabled:opacity-40" aria-label="Previous step">
          <IconArrowLeft size={14} />
        </button>
        <button
          disabled={needsCheck}
          onClick={() => (last ? finish() : storyGo(idx + 1))}
          className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-accent py-2 font-semibold text-accent-ink disabled:opacity-40"
        >
          {needsCheck ? 'Answer the check to continue' : last ? 'Finish walkthrough' : 'Next packet'} {!needsCheck && <IconArrowRight size={14} />}
        </button>
      </div>
    </div>
  )
}
