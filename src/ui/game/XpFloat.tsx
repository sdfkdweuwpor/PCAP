import { AnimatePresence, motion } from 'framer-motion'
import { useGame } from '../../store/game'

/** "+N XP" that floats up after a correct answer. */
export function XpFloat() {
  const feedback = useGame((s) => s.feedback)
  const idx = useGame((s) => s.idx)
  const xp = feedback?.xp.total ?? 0
  return (
    <AnimatePresence>
      {xp > 0 && (
        <motion.div
          key={idx}
          className="pointer-events-none absolute right-6 top-6 font-mono text-lg font-bold text-accent"
          style={{ textShadow: '0 0 12px var(--accent)' }}
          initial={{ opacity: 0, y: 10, scale: 0.8 }}
          animate={{ opacity: [0, 1, 1, 0], y: [10, -10, -30, -50], scale: [0.8, 1.15, 1, 1] }}
          transition={{ duration: 1.4, times: [0, 0.2, 0.7, 1] }}
          aria-hidden
        >
          +{xp} XP
          {feedback && feedback.xp.streak > 0 && <span className="block text-right text-[10px] text-warn">streak bonus</span>}
        </motion.div>
      )}
    </AnimatePresence>
  )
}
