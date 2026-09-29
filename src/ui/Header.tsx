import { motion } from 'framer-motion'
import { useRef, useState, type KeyboardEvent } from 'react'
import { nextRank, rankFor } from '../game/scoring'
import { MODE_INFO } from '../game/types'
import { useCapture } from '../store/capture'
import { useGame } from '../store/game'
import { useProgress, type Settings } from '../store/progress'
import { SettingsDialog } from './game/SettingsDialog'
import { Kbd, Meter } from './term'

export function ThemeSwitch() {
  const theme = useProgress((s) => s.settings.theme)
  const set = useProgress((s) => s.setSettings)
  const opts: Settings['theme'][] = ['amber', 'green', 'paper']
  const refs = useRef<(HTMLButtonElement | null)[]>([])

  // Radio-group keyboard pattern: arrows move the checked radio (roving tabindex, wraps around).
  const onKeyDown = (e: KeyboardEvent) => {
    const i = opts.indexOf(theme)
    let j: number
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') j = (i + 1) % opts.length
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') j = (i - 1 + opts.length) % opts.length
    else return
    e.preventDefault()
    e.stopPropagation()
    set({ theme: opts[j] })
    refs.current[j]?.focus()
  }

  return (
    <div role="radiogroup" aria-label="Screen" onKeyDown={onKeyDown} className="flex border border-line text-[11px] uppercase tracking-[0.1em]">
      {opts.map((t, i) => (
        <button
          key={t}
          ref={(el) => {
            refs.current[i] = el
          }}
          role="radio"
          aria-checked={theme === t}
          tabIndex={theme === t ? 0 : -1}
          onClick={() => set({ theme: t })}
          className={`px-2 py-0.5 ${theme === t ? 'bg-accent text-accent-ink' : 'text-muted hover:text-fg'}`}
        >
          {t}
        </button>
      ))}
    </div>
  )
}

export function Header() {
  const fileName = useCapture((s) => s.fileName)
  const index = useCapture((s) => s.index)!
  const reveal = useCapture((s) => s.revealSecrets)
  const hasCreds = index.packets.some((p) => p.facts.creds)
  const [settings, setSettings] = useState(false)

  return (
    <header className="flex min-w-0 items-center gap-3 border-b border-line bg-panel2 px-3 py-1.5 text-[12px]">
      <button
        onClick={() => {
          useGame.getState().toMenu()
          useCapture.getState().close()
        }}
        className="shrink-0 font-display text-[22px] leading-none text-accent glow hover:brightness-125"
        aria-label="Close capture and return to the load screen"
        title="Close capture"
      >
        PKTQ
      </button>
      <span className="text-faint" aria-hidden>
        ://
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate font-semibold" title={fileName}>
          {fileName}
        </p>
        <p className="truncate text-[11px] text-faint">
          {index.format} · {index.packets.length.toLocaleString()} frames · {index.conversations.length} streams · {index.duration.toFixed(3)}s
          {index.warnings.length > 0 && <span className="text-warn"> · warn: {index.warnings[0]}</span>}
        </p>
      </div>
      {hasCreds && (
        <button
          onClick={() => useCapture.getState().setReveal(!reveal)}
          aria-pressed={reveal}
          className={`hidden shrink-0 border px-2 py-0.5 text-[11px] uppercase tracking-[0.1em] sm:block ${reveal ? 'border-[var(--p-clear)] bg-[var(--p-clear)] text-bg' : 'border-line text-muted hover:text-fg'}`}
          title="Cleartext secrets are masked by default"
        >
          secrets: {reveal ? 'shown' : 'masked'}
        </button>
      )}
      <RankReadout />
      <div className="hidden lg:block">
        <ThemeSwitch />
      </div>
      <button className="shrink-0 border border-line px-2 py-0.5 text-[11px] uppercase tracking-[0.1em] text-muted hover:text-fg" onClick={() => setSettings(true)}>
        cfg
      </button>
      <SettingsDialog open={settings} onClose={() => setSettings(false)} />
    </header>
  )
}

export function RankReadout() {
  const xp = useProgress((s) => s.xp)
  const streak = useGame((s) => s.streak)
  const rank = rankFor(xp)
  const next = nextRank(xp)
  const frac = next ? (xp - rank.minXp) / (next.minXp - rank.minXp) : 1
  return (
    <div role="group" className="flex shrink-0 items-center gap-3 text-[11px]" aria-label={`Rank ${rank.name}, ${xp} XP, streak ${streak}`}>
      <span className="hidden md:inline">
        <span className="text-faint">rank</span> <span className="text-accent">{rank.name.toLowerCase()}</span>
      </span>
      <span className="hidden sm:inline">
        <Meter value={frac} width={10} label="Progress to next rank" />{' '}
        <motion.span key={xp} initial={{ opacity: 0.3 }} animate={{ opacity: 1 }} className="tabular-nums text-fg">
          {xp}xp
        </motion.span>
      </span>
      <StreakReadout streak={streak} />
    </div>
  )
}

/** Streak as five pips; fills past five show as a count. */
export function StreakReadout({ streak }: { streak: number }) {
  const pips = Math.min(streak, 5)
  return (
    <span className="whitespace-nowrap" title={`Streak ${streak}`}>
      <span className="text-faint">stk </span>
      <motion.span key={streak} initial={{ opacity: 0.2 }} animate={{ opacity: 1 }} className={streak >= 5 ? 'text-warn' : 'text-accent'}>
        {'▮'.repeat(pips)}
      </motion.span>
      <span className="text-faint">{'▯'.repeat(5 - pips)}</span>
      {streak > 5 && <span className="text-warn"> ×{streak}</span>}
    </span>
  )
}

/** vim/tmux-style status line along the bottom. */
export function StatusBar() {
  const selected = useCapture((s) => s.selected)
  const index = useCapture((s) => s.index)!
  const visible = useCapture((s) => s.visible)
  const filter = useCapture((s) => s.filterText)
  const field = useCapture((s) => s.selectedField)
  const playMode = useGame((s) => s.playMode)
  const phase = useGame((s) => s.phase)
  const p = selected ? index.packets[selected - 1] : null
  const modeLabel =
    playMode === 'mixed' ? 'MIXED' : playMode === 'blitz' ? 'BLITZ' : playMode ? `${MODE_INFO[playMode].letter}:${MODE_INFO[playMode].name.toUpperCase()}` : 'IDLE'
  return (
    <footer className="flex h-6 shrink-0 items-center gap-4 overflow-hidden border-t border-line bg-panel2 px-3 text-[11px] text-muted" aria-label="Status">
      <span className={`shrink-0 px-1.5 ${phase === 'menu' ? 'bg-panel3 text-muted' : 'bg-accent text-accent-ink'}`}>{modeLabel}</span>
      <span className="shrink-0 tabular-nums">
        frm {p ? `${p.no}/${index.packets.length}` : `–/${index.packets.length}`}
      </span>
      {p && (
        <span className="hidden min-w-0 truncate md:inline">
          {p.protocol} {p.origLen}B {p.facts.tcp ? 'tcp.stream' : p.facts.udp ? 'udp.stream' : 'stream'} {p.protoStream ?? (p.streamId >= 0 ? p.streamId : '–')}
          {field && <span className="text-fg"> · {field.key ?? field.name} @{field.offset}+{field.length}</span>}
        </span>
      )}
      <span className="ml-auto hidden min-w-0 truncate lg:inline">{filter ? `filter: ${filter} (${visible?.length ?? 0})` : 'no filter'}</span>
      <span className="hidden shrink-0 xl:inline">
        <Kbd>/</Kbd> filter <Kbd>↑↓</Kbd> move <Kbd>↵</Kbd> answer <Kbd>n</Kbd> next
      </span>
    </footer>
  )
}
