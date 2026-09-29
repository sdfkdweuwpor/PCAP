import { useReducedMotion } from 'framer-motion'
import { useProgress } from '../store/progress'

/** True when motion should be reduced: in-app setting wins, otherwise the OS preference. */
export function useReduced(): boolean {
  const pref = useProgress((s) => s.settings.reduceMotion)
  const system = useReducedMotion() ?? false
  return pref === 'on' ? true : pref === 'off' ? false : system
}

export const spring = { type: 'spring', stiffness: 380, damping: 32, mass: 0.8 } as const
export const softSpring = { type: 'spring', stiffness: 220, damping: 28 } as const
