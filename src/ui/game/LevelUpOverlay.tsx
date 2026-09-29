import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useRef } from 'react'
import { MODE_INFO, type Mode } from '../../game/types'
import { useGame } from '../../store/game'
import { Confetti } from './Confetti'

export function LevelUpOverlay() {
  const rank = useGame((s) => s.levelUp)
  const btn = useRef<HTMLButtonElement>(null)
  const dismiss = useGame((s) => s.dismissLevelUp)

  useEffect(() => {
    if (!rank) return
    btn.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && dismiss()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [rank, dismiss])

  return (
    <AnimatePresence>
      {rank && (
        <motion.div
          className="fixed inset-0 z-[100] grid place-items-center bg-bg/80 p-4 backdrop-blur-sm"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          role="dialog"
          aria-modal="true"
          aria-labelledby="lvl-title"
          onClick={dismiss}
        >
          <motion.div
            className="relative w-full max-w-sm overflow-hidden rounded-2xl border border-accent/60 bg-panel p-6 text-center shadow-[var(--shadow)]"
            initial={{ scale: 0.7, y: 30, opacity: 0 }}
            animate={{ scale: 1, y: 0, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 260, damping: 18 }}
            onClick={(e) => e.stopPropagation()}
          >
            <motion.div
              className="pointer-events-none absolute inset-0 opacity-30"
              style={{ background: 'radial-gradient(circle at 50% 0%, var(--accent), transparent 60%)' }}
              animate={{ opacity: [0.15, 0.4, 0.25] }}
              transition={{ duration: 1.6 }}
            />
            <p className="relative text-xs font-semibold uppercase tracking-[0.2em] text-muted">Rank up</p>
            <motion.h2
              id="lvl-title"
              className="relative mt-1 text-3xl font-black text-accent"
              initial={{ letterSpacing: '0.4em', opacity: 0 }}
              animate={{ letterSpacing: '0em', opacity: 1 }}
              transition={{ delay: 0.15, duration: 0.5 }}
            >
              {rank.name}
            </motion.h2>
            <p className="relative mt-2 text-sm text-muted">{rank.blurb}</p>
            {rank.unlocks.length > 0 && (
              <div className="relative mt-4 rounded-lg border border-line bg-panel2 p-3 text-left text-sm">
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted">Unlocked</p>
                {rank.unlocks.map((m) => (
                  <motion.p key={m} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }} className="font-semibold">
                    {m === 'blitz' ? 'Blitz — 60-second speed round' : `${MODE_INFO[m as Mode].letter} · ${MODE_INFO[m as Mode].name}`}
                  </motion.p>
                ))}
              </div>
            )}
            <button ref={btn} onClick={dismiss} className="relative mt-5 w-full rounded-lg bg-accent py-2 font-semibold text-accent-ink">
              Continue
            </button>
            <Confetti trigger={1} badge={false} />
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
