import { MotionConfig } from 'framer-motion'
import { Component, useEffect, type ReactNode } from 'react'
import { useCapture } from '../store/capture'
import { useProgress } from '../store/progress'
import { LevelUpOverlay } from './game/LevelUpOverlay'
import { useReduced } from './motion'
import { UploadScreen } from './UploadScreen'
import { Workspace } from './Workspace'

const THEME_COLOR = { dark: '#0b0906', paper: '#ece5d4' }

export default function App() {
  const status = useCapture((s) => s.status)
  const hasIndex = useCapture((s) => s.index !== null)
  const theme = useProgress((s) => s.settings.theme)
  const crt = useProgress((s) => s.settings.crt)
  const motionPref = useProgress((s) => s.settings.reduceMotion)
  const reduced = useReduced()

  useEffect(() => {
    const root = document.documentElement
    root.dataset.screen = theme
    root.dataset.crt = crt && theme !== 'paper' ? 'on' : 'off'
    root.dataset.motion = motionPref === 'on' ? 'reduced' : motionPref === 'off' ? 'full' : 'system'
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', THEME_COLOR[theme])
  }, [theme, crt, motionPref])

  // No exit animation between the two screens: the workspace must unmount the moment its capture is cleared,
  // otherwise it re-renders against a null index while fading out.
  return (
    <MotionConfig reducedMotion={reduced ? 'always' : 'never'}>
      <ErrorBoundary>{status === 'ready' && hasIndex ? <Workspace key="ws" /> : <UploadScreen key="up" />}</ErrorBoundary>
      <LevelUpOverlay />
    </MotionConfig>
  )
}

/** Last line of defence: a render error shows a recoverable message instead of a blank page. */
class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }
  static getDerivedStateFromError(error: Error) {
    return { error }
  }
  componentDidCatch(error: Error) {
    console.error('PacketQuest render error:', error)
  }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <main className="mx-auto max-w-2xl px-4 py-10 text-[13px]" role="alert">
        <p className="font-display text-[32px] text-accent">PKTQ</p>
        <p className="mt-3">
          <span className="font-semibold text-bad">ERR</span> the interface hit an unexpected error: <span className="text-muted">{this.state.error.message}</span>
        </p>
        <p className="mt-2 text-muted">Your progress is saved. Go back to the load screen and try again; if it keeps happening, reset progress in cfg.</p>
        <button
          className="mt-4 border border-accent bg-accent px-3 py-1.5 text-[12px] font-semibold uppercase tracking-[0.1em] text-accent-ink"
          onClick={() => {
            useCapture.getState().close()
            this.setState({ error: null })
          }}
        >
          [ back to load screen ]
        </button>
      </main>
    )
  }
}
