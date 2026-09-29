import { AnimatePresence, motion } from 'framer-motion'
import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'
import { Confetti } from './Confetti'
import { ModeMenu } from './ModeMenu'
import { QuestionView } from './QuestionView'
import { SessionSummary } from './SessionSummary'
import { StoryPlayer } from './StoryPlayer'

export function GamePanel({ onToggleWide, wide }: { onToggleWide?: () => void; wide?: boolean }) {
  const bank = useCapture((s) => s.bank)
  const phase = useGame((s) => s.phase)
  const milestone = useGame((s) => s.milestone)

  return (
    <div className="relative flex h-full min-h-0 flex-col">
      {onToggleWide && (
        <button
          onClick={onToggleWide}
          className="absolute -left-3 top-1/2 z-20 grid h-10 w-3 -translate-y-1/2 place-items-center rounded-l-md border border-r-0 border-line bg-panel2 text-[10px] text-faint hover:text-fg"
          aria-label={wide ? 'Narrow game panel' : 'Widen game panel'}
          title={wide ? 'Narrow game panel' : 'Widen game panel'}
        >
          {wide ? '›' : '‹'}
        </button>
      )}
      {!bank ? (
        <div className="grid flex-1 place-items-center p-6 text-center text-sm text-muted" aria-live="polite">
          <div>
            <motion.div
              className="mx-auto mb-3 h-8 w-8 rounded-full border-2 border-accent border-t-transparent"
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 0.9, ease: 'linear' }}
            />
            Generating questions from this capture…
          </div>
        </div>
      ) : (
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={phase === 'feedback' ? 'question' : phase}
            className="flex min-h-0 flex-1 flex-col"
            initial={{ opacity: 0, x: 24 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -24 }}
            transition={{ type: 'spring', stiffness: 320, damping: 30 }}
          >
            {phase === 'menu' && <ModeMenu />}
            {(phase === 'question' || phase === 'feedback') && <QuestionView />}
            {phase === 'summary' && <SessionSummary />}
            {phase === 'story' && <StoryPlayer />}
          </motion.div>
        </AnimatePresence>
      )}
      <Confetti trigger={milestone} />
    </div>
  )
}
