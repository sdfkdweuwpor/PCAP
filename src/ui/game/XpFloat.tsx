import { AnimatePresence, motion } from 'framer-motion'
import { useGame } from '../../store/game'

/** "+N xp" that drifts up and fades after a scored answer. */
export function XpFloat() {
  const feedback = useGame((s) => s.feedback)
  const idx = useGame((s) => s.idx)
  const xp = feedback?.xp.total ?? 0
  return (
    <AnimatePresence>
      {xp > 0 && (
        <motion.div
          key={idx}
          className="pointer-events-none absolute right-4 top-3 text-[13px] font-semibold tabular-nums text-accent glow"
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: [0, 1, 1, 0], y: [6, -4, -14, -26] }}
          transition={{ duration: 1.3, times: [0, 0.15, 0.7, 1], ease: 'linear' }}
          aria-hidden
        >
          +{xp}xp
        </motion.div>
      )}
    </AnimatePresence>
  )
}
