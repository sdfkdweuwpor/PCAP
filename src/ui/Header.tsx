import { AnimatePresence, motion } from 'framer-motion'
import { useState } from 'react'
import { nextRank, rankFor } from '../game/scoring'
import { useCapture } from '../store/capture'
import { useGame } from '../store/game'
import { useProgress } from '../store/progress'
import { SettingsDialog } from './game/SettingsDialog'
import { IconArrowLeft, IconEye, IconEyeOff, IconFlame, IconGear, IconLogo, IconMoon, IconSun } from './icons'

export function Header() {
  const fileName = useCapture((s) => s.fileName)
  const index = useCapture((s) => s.index)!
  const reveal = useCapture((s) => s.revealSecrets)
  const hasCreds = index.packets.some((p) => p.facts.creds)
  const [settings, setSettings] = useState(false)
  const theme = useProgress((s) => s.settings.theme)
  const setS = useProgress((s) => s.setSettings)

  return (
    <header className="flex min-w-0 items-center gap-2 border-b border-line bg-panel px-3 py-2">
      <button
        onClick={() => {
          useGame.getState().toMenu()
          useCapture.getState().close()
        }}
        className="flex shrink-0 items-center gap-2 rounded-lg p-1 hover:bg-panel3"
        aria-label="Close capture and return to start"
        title="Load another capture"
      >
        <IconArrowLeft size={14} className="text-muted" />
        <IconLogo size={26} />
        <span className="hidden font-bold tracking-tight xl:inline">PacketQuest</span>
      </button>
      <div className="min-w-0 flex-1 px-1">
        <p className="truncate font-mono text-sm" title={fileName}>
          {fileName}
        </p>
        <p className="truncate text-[11px] text-muted">
          {index.format.toUpperCase()} · {index.packets.length.toLocaleString()} packets · {index.conversations.length} conversations ·{' '}
          {index.duration.toFixed(2)} s
          {index.warnings.length > 0 && <span className="text-warn"> · {index.warnings[0]}</span>}
        </p>
      </div>
      {hasCreds && (
        <button
          onClick={() => useCapture.getState().setReveal(!reveal)}
          aria-pressed={reveal}
          className={`flex shrink-0 items-center gap-1 rounded-lg border px-2 py-1 text-xs ${reveal ? 'border-[var(--p-clear)] text-[var(--p-clear)]' : 'border-line text-muted hover:text-fg'}`}
          title="Cleartext secrets are masked by default"
        >
          {reveal ? <IconEyeOff size={14} /> : <IconEye size={14} />}
          <span className="hidden md:inline">{reveal ? 'Hide secrets' : 'Reveal secrets'}</span>
        </button>
      )}
      <XpBar />
      <button
        className="shrink-0 rounded-lg border border-line p-1.5 text-muted hover:text-fg"
        onClick={() => setS({ theme: theme === 'dark' ? 'light' : 'dark' })}
        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      >
        {theme === 'dark' ? <IconSun size={15} /> : <IconMoon size={15} />}
      </button>
      <button className="shrink-0 rounded-lg border border-line p-1.5 text-muted hover:text-fg" onClick={() => setSettings(true)} aria-label="Settings and progress">
        <IconGear size={15} />
      </button>
      <SettingsDialog open={settings} onClose={() => setSettings(false)} />
    </header>
  )
}

export function XpBar() {
  const xp = useProgress((s) => s.xp)
  const streak = useGame((s) => s.streak)
  const rank = rankFor(xp)
  const next = nextRank(xp)
  const frac = next ? (xp - rank.minXp) / (next.minXp - rank.minXp) : 1
  return (
    <div className="flex shrink-0 items-center gap-2" aria-label={`Rank ${rank.name}, ${xp} XP${next ? `, ${next.minXp - xp} to ${next.name}` : ''}, streak ${streak}`}>
      <StreakFlame streak={streak} />
      <div className="hidden w-32 sm:block">
        <div className="flex justify-between text-[10px] font-semibold uppercase tracking-wide">
          <span className="text-accent">{rank.name}</span>
          <motion.span key={xp} initial={{ opacity: 0.4 }} animate={{ opacity: 1 }} className="text-muted">
            {xp} XP
          </motion.span>
        </div>
        <div className="mt-0.5 h-1.5 overflow-hidden rounded-full bg-panel3">
          <motion.div className="h-full origin-left rounded-full bg-accent" animate={{ scaleX: Math.max(0.02, frac) }} transition={{ type: 'spring', stiffness: 120, damping: 20 }} />
        </div>
      </div>
    </div>
  )
}

export function StreakFlame({ streak }: { streak: number }) {
  const scale = 1 + Math.min(streak, 15) * 0.05
  return (
    <div className="relative flex items-center gap-0.5" title={`Streak: ${streak}`}>
      <motion.span
        animate={{ scale: streak ? scale : 0.9, opacity: streak ? 1 : 0.35 }}
        transition={{ type: 'spring', stiffness: 400, damping: 15 }}
        className={streak >= 5 ? 'text-warn' : streak ? 'text-[var(--p-dhcp)]' : 'text-muted'}
        style={{ filter: streak >= 5 ? 'drop-shadow(0 0 6px var(--warn))' : undefined }}
      >
        <IconFlame size={18} />
      </motion.span>
      <AnimatePresence mode="popLayout">
        <motion.span
          key={streak}
          initial={{ y: -8, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: 8, opacity: 0 }}
          className="min-w-3 font-mono text-xs font-semibold"
        >
          {streak}
        </motion.span>
      </AnimatePresence>
    </div>
  )
}
