// Console navigation: the mode list, the start page, and settings. Shown on the mode list and in every session.
// Leaving a session keeps the XP of answers already given; only the session report is skipped.

import { useState } from 'react'
import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'
import { SettingsDialog } from './SettingsDialog'

const btn = 'flex items-center gap-1.5 border px-3 py-1 text-[12px] lowercase'
const idle = `${btn} border-line-strong text-muted hover:border-accent hover:text-fg`
const here = `${btn} border-accent bg-accent text-accent-ink`

export function SessionNav({ onModes = false }: { onModes?: boolean }) {
  const [settings, setSettings] = useState(false)
  return (
    <nav aria-label="Console" className="flex shrink-0 items-center gap-2 border-b border-line bg-panel2 px-2 py-1.5">
      <button
        className={onModes ? here : idle}
        aria-current={onModes ? 'page' : undefined}
        disabled={onModes}
        onClick={() => useGame.getState().toMenu()}
        title="Back to the list of modes and questions"
      >
        <span aria-hidden>‹</span> modes
      </button>
      <button
        className={idle}
        onClick={() => {
          useGame.getState().toMenu()
          useCapture.getState().close()
        }}
        title="Close this capture and go back to the start page"
      >
        <span aria-hidden>⌂</span> home
      </button>
      <button className={`${idle} ml-auto`} onClick={() => setSettings(true)} title="Theme, shortcuts, progress">
        <span aria-hidden>⚙</span> settings
      </button>
      <SettingsDialog open={settings} onClose={() => setSettings(false)} />
    </nav>
  )
}
