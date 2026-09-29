import { AnimatePresence, motion } from 'framer-motion'
import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'
import { Frame } from '../term'
import { Confetti } from './Confetti'
import { DrillView } from './DrillView'
import { ModeMenu } from './ModeMenu'
import { QuestionView } from './QuestionView'
import { SessionNav } from './SessionNav'
import { SessionSummary } from './SessionSummary'
import { StoryPlayer } from './StoryPlayer'

const PHASE_LABEL = { menu: 'idle', question: 'awaiting answer', feedback: 'graded', summary: 'report', story: 'walkthrough', drill: 'drill' }

export function GamePanel({ onToggleWide, wide }: { onToggleWide?: () => void; wide?: boolean }) {
  const bank = useCapture((s) => s.bank)
  const phase = useGame((s) => s.phase)
  const milestone = useGame((s) => s.milestone)

  return (
    <Frame
      title="console"
      meta={PHASE_LABEL[phase]}
      className="relative h-full"
      bodyClass="flex flex-col"
      actions={
        onToggleWide && (
          <button onClick={onToggleWide} className="normal-case tracking-normal text-faint hover:text-accent" aria-label={wide ? 'Narrow console' : 'Widen console'} title={wide ? 'Narrow' : 'Widen'}>
            {wide ? '⇥' : '⇤'}
          </button>
        )
      }
    >
      {!bank ? (
        <p className="p-3 text-[12px] text-muted" aria-live="polite">
          <span className="text-faint">$</span> generating exercises from capture… <span className="cursor-block" aria-hidden />
        </p>
      ) : (
        <>
          <SessionNav onModes={phase === 'menu'} />
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={phase === 'feedback' ? 'question' : phase}
              className="flex min-h-0 flex-1 flex-col"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.1 }}
            >
              {phase === 'menu' && <ModeMenu />}
              {(phase === 'question' || phase === 'feedback') && <QuestionView />}
              {phase === 'summary' && <SessionSummary />}
              {phase === 'story' && <StoryPlayer />}
              {phase === 'drill' && <DrillView />}
            </motion.div>
          </AnimatePresence>
        </>
      )}
      <Confetti trigger={milestone} badge />
    </Frame>
  )
}
