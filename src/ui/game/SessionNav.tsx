// Way out of any running session: back to the mode list, or close the capture and return to the start page.
// Answers already given keep their XP; only the session report is skipped.

import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'

const link = 'flex items-center gap-1 px-1 text-muted hover:bg-panel3 hover:text-fg'

export function SessionNav() {
  return (
    <nav aria-label="Session" className="flex shrink-0 items-center gap-2 border-b border-line bg-panel2 px-2 py-0.5 text-[11px] lowercase">
      <button className={link} onClick={() => useGame.getState().toMenu()} title="Back to the list of modes and questions">
        <span aria-hidden>‹</span> modes
      </button>
      <span className="text-faint" aria-hidden>
        |
      </span>
      <button
        className={link}
        onClick={() => {
          useGame.getState().toMenu()
          useCapture.getState().close()
        }}
        title="Close this capture and go back to the start page"
      >
        <span aria-hidden>⌂</span> home
      </button>
    </nav>
  )
}
