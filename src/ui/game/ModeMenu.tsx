import { motion } from 'framer-motion'
import { useMemo } from 'react'
import { conceptWeight } from '../../game/engine'
import { RANKS, unlockedModes } from '../../game/scoring'
import { CONCEPT_LABEL, MODE_INFO, type Concept, type Mode } from '../../game/types'
import { useCapture } from '../../store/capture'
import { useGame, type PlayMode } from '../../store/game'
import { useProgress } from '../../store/progress'
import { IconBook, IconClock, IconLock, IconSpark } from '../icons'

const ORDER: Mode[] = ['pick', 'says', 'means', 'field', 'order', 'anomaly', 'story']

export function ModeMenu() {
  const bank = useCapture((s) => s.bank)!
  const index = useCapture((s) => s.index)!
  const xp = useProgress((s) => s.xp)
  const unlockAll = useProgress((s) => s.settings.unlockAll)
  const concepts = useProgress((s) => s.concepts)
  const unlocked = unlockedModes(xp, unlockAll)
  const start = useGame((s) => s.start)

  const counts = useMemo(() => {
    const m = new Map<Mode, number>()
    for (const q of bank.questions) m.set(q.mode, (m.get(q.mode) ?? 0) + 1)
    m.set('story', bank.story.steps.length)
    return m
  }, [bank])

  const weak = (Object.entries(concepts) as [Concept, { seen: number; correct: number }][])
    .filter(([, s]) => s.seen >= 2)
    .sort((a, b) => conceptWeight(b[1]) - conceptWeight(a[1]))
    .slice(0, 3)
    .filter(([, s]) => s.correct / s.seen < 0.75)

  const lockReason = (m: PlayMode) => {
    const r = RANKS.find((x) => x.unlocks.includes(m as Mode | 'blitz'))
    return r ? `Unlocks at ${r.name} (${r.minXp} XP)` : ''
  }

  const card = (m: PlayMode, title: string, blurb: string, badge: string, n: number, icon?: React.ReactNode) => {
    const isLocked = m !== 'mixed' && !unlocked.has(m as Mode | 'blitz')
    const empty = n === 0
    return (
      <motion.li key={m} variants={{ hidden: { opacity: 0, y: 8 }, show: { opacity: 1, y: 0 } }}>
        <button
          disabled={isLocked || empty}
          onClick={() => start(m)}
          className="group flex w-full items-start gap-3 rounded-xl border border-line bg-panel2 p-3 text-left transition hover:border-accent/70 disabled:cursor-not-allowed disabled:opacity-50"
          aria-describedby={`mode-${m}`}
        >
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent/15 font-mono text-sm font-bold text-accent">{icon ?? badge}</span>
          <span className="min-w-0 flex-1">
            <span className="flex items-center justify-between gap-2">
              <span className="font-semibold">{title}</span>
              <span className="shrink-0 text-[11px] text-muted">
                {isLocked ? (
                  <span className="flex items-center gap-1">
                    <IconLock size={11} /> locked
                  </span>
                ) : empty ? (
                  'none in this capture'
                ) : m === 'story' ? (
                  `${n} steps`
                ) : (
                  `${n} Qs`
                )}
              </span>
            </span>
            <span id={`mode-${m}`} className="mt-0.5 block text-xs text-muted">
              {isLocked ? lockReason(m) : blurb}
            </span>
          </span>
        </button>
      </motion.li>
    )
  }

  const total = bank.questions.length
  return (
    <div className="scroll-thin flex-1 overflow-y-auto p-4">
      <h2 className="text-lg font-bold">Choose a challenge</h2>
      <p className="mb-3 text-sm text-muted">
        {total} questions were generated from <span className="font-mono">{index.fileName}</span>
        {index.anomalies.length ? `, including ${index.anomalies.length} detected anomal${index.anomalies.length > 1 ? 'ies' : 'y'} to hunt.` : '.'}
      </p>
      {weak.length > 0 && (
        <p className="mb-3 rounded-lg border border-warn/40 bg-warn/10 p-2 text-xs">
          <strong>Focus areas:</strong> {weak.map(([c]) => CONCEPT_LABEL[c]).join(', ')} — these come up more often until your accuracy improves.
        </p>
      )}
      <motion.ul className="flex flex-col gap-2" initial="hidden" animate="show" variants={{ show: { transition: { staggerChildren: 0.035 } } }}>
        {card('mixed', 'Mixed session', '12 questions across every unlocked mode, easiest first.', '★', total, <IconSpark size={16} />)}
        {ORDER.map((m) => card(m, MODE_INFO[m].name, MODE_INFO[m].blurb, MODE_INFO[m].letter, counts.get(m) ?? 0, m === 'story' ? <IconBook size={16} /> : undefined))}
        {card('blitz', 'Blitz', `${60} seconds. As many as you can. Speed bonus applies.`, 'B', total, <IconClock size={16} />)}
      </motion.ul>
    </div>
  )
}
