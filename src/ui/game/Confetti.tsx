import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useMemo, useState } from 'react'
import { seeded } from '../../game/engine'
import { useReduced } from '../motion'

const COLORS = ['var(--accent)', 'var(--good)', 'var(--warn)', 'var(--p-tls)', 'var(--p-icmp)', 'var(--p-dhcp)']

/** Small confetti burst (transform/opacity only). Reduced motion shows a static badge instead. */
export function Confetti({ trigger, label, badge = true }: { trigger: number | null; label?: string; badge?: boolean }) {
  const reduced = useReduced()
  const [shown, setShown] = useState<number | null>(null)
  useEffect(() => {
    if (trigger === null) return
    setShown(trigger)
    const t = setTimeout(() => setShown(null), 1800)
    return () => clearTimeout(t)
  }, [trigger])
  const bits = useMemo(() => {
    const rnd = seeded((shown ?? 0) + 7)
    return Array.from({ length: 36 }, (_, i) => ({
      x: (rnd() - 0.5) * 360,
      y: -120 - rnd() * 200,
      r: rnd() * 540 - 270,
      c: COLORS[i % COLORS.length],
      d: 0.9 + rnd() * 0.6,
      w: 5 + rnd() * 5,
    }))
  }, [shown])
  return (
    <AnimatePresence>
      {shown !== null && (
        <motion.div className="pointer-events-none absolute inset-x-0 top-1/3 z-50 flex justify-center" initial={{ opacity: 1 }} exit={{ opacity: 0 }} aria-live="polite">
          {badge && <motion.div
            initial={{ scale: 0.6, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="rounded-full border border-warn bg-panel px-3 py-1 text-sm font-bold text-warn shadow-lg"
          >
            {label ?? `🔥 ${shown} in a row!`}
          </motion.div>}
          {!reduced &&
            bits.map((b, i) => (
              <motion.span
                key={i}
                className="absolute top-3 rounded-sm"
                style={{ width: b.w, height: b.w * 0.5, background: b.c }}
                initial={{ x: 0, y: 0, rotate: 0, opacity: 1 }}
                animate={{ x: b.x, y: [0, b.y, b.y + 260], rotate: b.r, opacity: [1, 1, 0] }}
                transition={{ duration: b.d * 1.4, ease: 'easeOut' }}
              />
            ))}
        </motion.div>
      )}
    </AnimatePresence>
  )
}
