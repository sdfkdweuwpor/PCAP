// Rank-up screen: a bordered clearance notice with a short typewriter reveal (no confetti).

import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useRef } from 'react'
import { MODE_INFO, type Mode } from '../../game/types'
import { useGame } from '../../store/game'
import { useReduced } from '../motion'
import { Btn } from '../term'

const UNLOCK_TEXT: Record<string, string> = { blitz: 'blitz · 60s speed round' }
const unlockLine = (m: string) => UNLOCK_TEXT[m] ?? `${MODE_INFO[m as Mode].letter.toLowerCase()} · ${MODE_INFO[m as Mode].name.toLowerCase()}`

export function LevelUpOverlay() {
  const rank = useGame((s) => s.levelUp)
  const box = useRef<HTMLDivElement>(null)
  const dismiss = useGame((s) => s.dismissLevelUp)
  const reduced = useReduced()

  useEffect(() => {
    if (!rank) return
    box.current?.querySelector('button')?.focus()
    const onKey = (e: KeyboardEvent) => (e.key === 'Escape' || e.key === 'Enter') && dismiss()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [rank, dismiss])

  // Each line types in after the previous one; nothing animates when motion is reduced.
  const type = (n: number) => (reduced ? {} : { animationDelay: `${n * 260}ms` })
  const cls = reduced ? '' : 'type-in'

  return (
    <AnimatePresence>
      {rank && (
        <motion.div
          className="fixed inset-0 z-[100] grid place-items-center bg-bg/70 p-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: reduced ? 0 : 0.1 }}
          role="dialog"
          aria-modal="true"
          aria-labelledby="lvl-title"
          onClick={dismiss}
        >
          <div ref={box} className="w-full max-w-sm border border-accent bg-panel p-5 text-[12px] shadow-[var(--shadow)]" onClick={(e) => e.stopPropagation()}>
            <p className={`text-center text-[11px] text-faint ${cls}`} style={type(0)}>
              -- clearance upgraded --
            </p>
            <h2 id="lvl-title" className={`mt-3 text-center font-display text-[56px] leading-none text-accent glow ${cls}`} style={type(1)}>
              {rank.name.toLowerCase()}
            </h2>
            <p className={`mt-3 text-center text-muted ${cls}`} style={type(2)}>
              {rank.blurb}
            </p>
            {rank.unlocks.length > 0 && (
              <div className="mt-4 border-t border-line pt-3">
                <p className="mb-1 text-[11px] uppercase tracking-[0.12em] text-faint">unlocked</p>
                <ul>
                  {rank.unlocks.map((m, i) => (
                    <li key={m} className={`text-fg ${cls}`} style={type(3 + i)}>
                      <span className="text-good" aria-hidden>
                        +{' '}
                      </span>
                      {unlockLine(m)}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="mt-5 flex justify-center">
              <Btn tone="primary" hotkey="↵" onClick={dismiss}>
                continue
              </Btn>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
