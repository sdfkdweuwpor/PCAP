import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useMemo, useState } from 'react'
import { seeded } from '../../game/engine'
import { useReduced } from '../motion'

const GLYPHS = ['*', '+', '·', '×', '░']
const COUNT = 16

/** Restrained ASCII burst (transform/opacity only, ~700ms) with an optional bordered text badge. Reduced motion shows the badge only. */
export function Confetti({ trigger, label, badge = true }: { trigger: number | null; label?: string; badge?: boolean }) {
  const reduced = useReduced()
  const [shown, setShown] = useState<number | null>(null)
  useEffect(() => {
    if (trigger === null) return
    setShown(trigger)
    const t = setTimeout(() => setShown(null), 1600)
    return () => clearTimeout(t)
  }, [trigger])
  const bits = useMemo(() => {
    const rnd = seeded((shown ?? 0) + 7)
    return Array.from({ length: COUNT }, (_, i) => {
      const angle = (i / COUNT) * Math.PI * 2 + rnd() * 0.4
      const dist = 36 + rnd() * 44
      return { x: Math.cos(angle) * dist * 1.4, y: Math.sin(angle) * dist, g: GLYPHS[Math.floor(rnd() * GLYPHS.length)], c: i % 3 === 0 ? 'text-warn' : 'text-accent' }
    })
  }, [shown])
  return (
    <AnimatePresence>
      {shown !== null && (
        <motion.div className="pointer-events-none absolute inset-x-0 top-1/3 z-50 flex justify-center" initial={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }} aria-live="polite">
          {badge && (
            <div className="border border-warn bg-panel px-2 py-0.5 text-[12px] font-semibold uppercase tracking-[0.1em] text-warn">{label ?? `streak ×${shown}`}</div>
          )}
          {!reduced &&
            bits.map((b, i) => (
              <motion.span
                key={i}
                aria-hidden
                className={`absolute left-1/2 top-2 -ml-1 text-[14px] leading-none ${b.c}`}
                initial={{ x: 0, y: 0, opacity: 1 }}
                animate={{ x: b.x, y: b.y, opacity: [1, 1, 0] }}
                transition={{ duration: 0.7, ease: 'easeOut', opacity: { times: [0, 0.6, 1], duration: 0.7 } }}
              >
                {b.g}
              </motion.span>
            ))}
        </motion.div>
      )}
    </AnimatePresence>
  )
}
