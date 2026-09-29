import { AnimatePresence, MotionConfig } from 'framer-motion'
import { useEffect } from 'react'
import { useCapture } from '../store/capture'
import { useProgress } from '../store/progress'
import { LevelUpOverlay } from './game/LevelUpOverlay'
import { useReduced } from './motion'
import { UploadScreen } from './UploadScreen'
import { Workspace } from './Workspace'

const THEME_COLOR = { amber: '#0b0906', green: '#040a06', paper: '#ece5d4' }

export default function App() {
  const status = useCapture((s) => s.status)
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

  return (
    <MotionConfig reducedMotion={reduced ? 'always' : 'never'}>
      <AnimatePresence mode="wait">{status === 'ready' ? <Workspace key="ws" /> : <UploadScreen key="up" />}</AnimatePresence>
      <LevelUpOverlay />
    </MotionConfig>
  )
}
