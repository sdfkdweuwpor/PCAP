// Mode G: narrated walkthrough. Each step selects a packet, replays it in a mini flow graph and explains it;
// some steps pose a quick check before you can continue.

import { useEffect } from 'react'
import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'
import { FlowView } from '../panes/FlowView'
import { Btn, Kbd } from '../term'
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
      if (step?.check && checked === null && /^[1-4]$/.test(e.key)) storyCheck(Number(e.key) - 1)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [idx, needsCheck, last, storyGo, finish, step, checked, storyCheck])

  if (!step)
    return (
      <p className="p-3 text-[12px] text-muted">
        -- nothing to narrate in this capture --{' '}
        <button className="text-accent underline" onClick={toMenu}>
          back
        </button>
      </p>
    )

  const frames = [...new Set(story.steps.slice(0, idx + 1).map((s) => s.packet))].sort((a, b) => a - b).slice(-10)

  return (
    <div className="flex min-h-0 flex-1 flex-col text-[12.5px]">
      <div className="shrink-0 border-b border-line px-3 py-1.5 text-[11px]">
        <div className="flex items-center gap-2 uppercase tracking-[0.1em]">
          <span className="text-accent">g walkthrough</span>
          <span className="ml-auto normal-case tracking-normal tabular-nums text-muted">
            step {idx + 1}/{story.steps.length}
          </span>
          <button onClick={finish} className="normal-case tracking-normal text-faint hover:text-fg">
            end
          </button>
        </div>
        <p className="mt-0.5 tracking-tight" aria-hidden>
          {story.steps.map((_, i) => (
            <span key={i} className={i < idx ? 'text-accent' : i === idx ? 'text-fg' : 'text-faint'}>
              {i < idx ? '■' : i === idx ? '▣' : '□'}
            </span>
          ))}
        </p>
      </div>

      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-3 py-3">
        <div key={idx}>
          <h2 className="type-in font-semibold text-accent">{step.title}</h2>
          <p className="mt-1.5 leading-relaxed">{step.narration}</p>
          <div className="mt-3 border border-line">
            <FlowView key={idx} frames={frames} compact autoPlay startAt={Math.max(0, frames.indexOf(step.packet))} highlight={[step.packet]} />
          </div>
          {step.check && (
            <div className="mt-4">
              <p id="q-prompt" className="mb-1.5">
                <span className="text-accent">check&gt;</span> {step.check.prompt.replace(/^Quick check: /, '')}
              </p>
              <ChoiceBody q={step.check} chosen={checked} onChoose={storyCheck} />
              {checked !== null && (
                <p className={`mt-1.5 text-[12px] ${checked === step.check.correct ? 'text-good' : 'text-bad'}`}>
                  {checked === step.check.correct ? '[ ok ] ' : '[fail] '}
                  <span className="text-muted">{step.check.explanation.matters}</span>
                </p>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="flex shrink-0 gap-2 border-t border-line p-2">
        <Btn disabled={idx === 0} onClick={() => storyGo(idx - 1)} aria-label="Previous step">
          ←
        </Btn>
        <Btn tone="primary" className="flex-1" disabled={needsCheck} onClick={() => (last ? finish() : storyGo(idx + 1))}>
          {needsCheck ? 'answer the check' : last ? 'finish' : 'next packet'}
          {!needsCheck && <Kbd>→</Kbd>}
        </Btn>
      </div>
    </div>
  )
}
