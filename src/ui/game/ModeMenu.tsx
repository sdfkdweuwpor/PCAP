// Exercise picker: a keyed table, not a card grid. Letter keys start a mode.

import { useEffect, useMemo } from 'react'
import { conceptWeight } from '../../game/engine'
import { RANKS, unlockedModes } from '../../game/scoring'
import { CONCEPT_LABEL, MODE_INFO, type Concept, type Mode } from '../../game/types'
import { useCapture } from '../../store/capture'
import { useGame, type PlayMode } from '../../store/game'
import { useProgress } from '../../store/progress'
import { Kbd } from '../term'

interface Row {
  mode: PlayMode
  key: string
  name: string
  blurb: string
  count: number | null
  unit: string
}

const ORDER: Mode[] = ['pick', 'says', 'means', 'field', 'order', 'anomaly', 'story', 'type', 'filter', 'drill']

export function ModeMenu() {
  const bank = useCapture((s) => s.bank)!
  const index = useCapture((s) => s.index)!
  const xp = useProgress((s) => s.xp)
  const unlockAll = useProgress((s) => s.settings.unlockAll)
  const concepts = useProgress((s) => s.concepts)
  const bestWpm = useProgress((s) => s.drill.bestWpm)
  const unlocked = unlockedModes(xp, unlockAll)
  const start = useGame((s) => s.start)

  const rows = useMemo<Row[]>(() => {
    const counts = new Map<Mode, number>()
    for (const q of bank.questions) counts.set(q.mode, (counts.get(q.mode) ?? 0) + 1)
    return [
      { mode: 'mixed', key: 'm', name: 'mixed session', blurb: '12 questions from every unlocked mode, easiest first', count: bank.questions.length, unit: 'qs' },
      ...ORDER.map((m) => ({
        mode: m,
        key: MODE_INFO[m].letter.toLowerCase(),
        name: MODE_INFO[m].name.toLowerCase(),
        blurb: MODE_INFO[m].blurb,
        count: m === 'story' ? bank.story.steps.length : m === 'drill' ? null : (counts.get(m) ?? 0),
        unit: m === 'story' ? 'steps' : 'qs',
      })),
      { mode: 'blitz', key: 'z', name: 'blitz', blurb: '60 seconds, as many as you can; speed bonus applies', count: bank.questions.length, unit: 'qs' },
    ]
  }, [bank])

  const isLocked = (m: PlayMode) => m !== 'mixed' && !unlocked.has(m as Mode | 'blitz')
  const lockReason = (m: PlayMode) => {
    const r = RANKS.find((x) => x.unlocks.includes(m as Mode | 'blitz'))
    return r ? `unlocks at ${r.name.toLowerCase()} (${r.minXp}xp)` : ''
  }
  const playable = (r: Row) => !isLocked(r.mode) && r.count !== 0

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
      const r = rows.find((x) => x.key === e.key.toLowerCase())
      if (r && playable(r)) {
        e.preventDefault()
        start(r.mode)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  const weak = (Object.entries(concepts) as [Concept, { seen: number; correct: number }][])
    .filter(([, s]) => s.seen >= 2 && s.correct / s.seen < 0.75)
    .sort((a, b) => conceptWeight(b[1]) - conceptWeight(a[1]))
    .slice(0, 3)

  return (
    <div className="scroll-thin flex-1 overflow-y-auto p-3 text-[12.5px]">
      <p className="text-muted">
        <span className="text-faint">$</span> pktq exercises --from {index.fileName}
      </p>
      <p className="mb-2 text-faint">
        {bank.questions.length} questions generated · {bank.story.steps.length}-step walkthrough ·{' '}
        {index.anomalies.length ? `${index.anomalies.length} anomal${index.anomalies.length > 1 ? 'ies' : 'y'} detected (hidden)` : 'no anomalies detected'}
      </p>
      {weak.length > 0 && (
        <p className="mb-2 border-l-2 border-warn pl-2 text-[12px]">
          <span className="text-warn">focus</span> <span className="text-muted">{weak.map(([c]) => CONCEPT_LABEL[c].toLowerCase()).join(', ')} — weighted up until accuracy improves</span>
        </p>
      )}
      <ul className="border-t border-line" role="list">
        {rows.map((r) => {
          const locked = isLocked(r.mode)
          const empty = r.count === 0
          return (
            <li key={r.mode} className="border-b border-line">
              <button
                disabled={!playable(r)}
                onClick={() => start(r.mode)}
                aria-describedby={`mode-${r.mode}`}
                className="group grid w-full grid-cols-[2.2rem_1fr_auto] items-baseline gap-x-2 px-1 py-1.5 text-left enabled:hover:bg-accent enabled:hover:text-accent-ink disabled:cursor-not-allowed"
              >
                <span className={locked || empty ? 'opacity-40' : ''}>
                  <Kbd>{r.key}</Kbd>
                </span>
                <span className={`min-w-0 ${locked || empty ? 'text-faint' : ''}`}>
                  <span className="font-semibold">{r.name}</span>
                  <span id={`mode-${r.mode}`} className={`block truncate text-[11.5px] ${locked || empty ? '' : 'text-muted group-hover:text-inherit'}`}>
                    {locked ? lockReason(r.mode) : empty ? 'nothing in this capture for this mode' : r.blurb}
                  </span>
                </span>
                <span className={`text-right text-[11px] tabular-nums ${locked || empty ? 'text-faint' : 'text-muted group-hover:text-inherit'}`}>
                  {locked ? 'locked' : r.mode === 'drill' ? (bestWpm ? `best ${bestWpm}wpm` : '60s') : `${r.count} ${r.unit}`}
                </span>
              </button>
            </li>
          )
        })}
      </ul>
      <p className="mt-2 text-[11px] text-faint">press a key or click · unlock everything in cfg → unlock all modes</p>
    </div>
  )
}
