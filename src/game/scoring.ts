// XP, streak multipliers, ranks and mode unlocks.

import type { Mode, Tier } from './types'

export const BASE_XP: Record<Tier, number> = { Recruit: 10, Analyst: 20, Hunter: 35 }

export interface XpInput {
  tier: Tier
  score: number
  seconds: number
  streak: number
  hintUsed: boolean
}

export interface XpBreakdown {
  total: number
  base: number
  speed: number
  streak: number
  hintPenalty: number
}

/** XP scales with difficulty, speed (bonus under 20 s) and streak; hints halve it. */
export function xpFor({ tier, score, seconds, streak, hintUsed }: XpInput): XpBreakdown {
  if (score <= 0) return { total: 0, base: 0, speed: 0, streak: 0, hintPenalty: 0 }
  const base = BASE_XP[tier] * score
  const speedMult = seconds < 20 ? 1 + 0.5 * (1 - seconds / 20) : 1
  const streakMult = 1 + Math.min(streak, 10) * 0.1
  const raw = base * speedMult * streakMult
  const withHint = hintUsed ? raw * 0.5 : raw
  return {
    total: Math.round(withHint),
    base: Math.round(base),
    speed: Math.round(base * (speedMult - 1)),
    streak: Math.round(base * speedMult * (streakMult - 1)),
    hintPenalty: hintUsed ? Math.round(raw - withHint) : 0,
  }
}

export interface Rank {
  name: 'Recruit' | 'Analyst' | 'Hunter' | 'Threat Hunter'
  minXp: number
  unlocks: (Mode | 'blitz')[]
  blurb: string
}

export const RANKS: Rank[] = [
  { name: 'Recruit', minXp: 0, unlocks: ['pick', 'says', 'order', 'story', 'type', 'drill'], blurb: 'Identify protocols, directions, requests and responses.' },
  { name: 'Analyst', minXp: 250, unlocks: ['means', 'field', 'filter'], blurb: 'Read flags, handshakes, record types and status codes.' },
  { name: 'Hunter', minXp: 700, unlocks: ['anomaly', 'blitz'], blurb: 'Hunt anomalies and attack patterns.' },
  { name: 'Threat Hunter', minXp: 1500, unlocks: [], blurb: 'You read captures like a seasoned SOC analyst.' },
]

export function rankFor(xp: number): Rank {
  let r = RANKS[0]
  for (const x of RANKS) if (xp >= x.minXp) r = x
  return r
}

export function nextRank(xp: number): Rank | null {
  return RANKS.find((r) => r.minXp > xp) ?? null
}

export function unlockedModes(xp: number, unlockAll = false): Set<Mode | 'blitz'> {
  const s = new Set<Mode | 'blitz'>()
  for (const r of RANKS) if (unlockAll || xp >= r.minXp) r.unlocks.forEach((m) => s.add(m))
  return s
}

export const STREAK_MILESTONES = [5, 10, 25]
