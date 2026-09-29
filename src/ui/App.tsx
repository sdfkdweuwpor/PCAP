import { AnimatePresence, MotionConfig } from 'framer-motion'
import { useEffect } from 'react'
import { useCapture } from '../store/capture'
import { useProgress } from '../store/progress'
import { LevelUpOverlay } from './game/LevelUpOverlay'
import { useReduced } from './motion'
import { UploadScreen } from './UploadScreen'
import { Workspace } from './Workspace'

export default function App() {
  const status = useCapture((s) => s.status)
  const theme = useProgress((s) => s.settings.theme)
  const motionPref = useProgress((s) => s.settings.reduceMotion)
  const reduced = useReduced()

  useEffect(() => {
    const root = document.documentElement
    root.dataset.theme = theme
    root.dataset.motion = motionPref === 'on' ? 'reduced' : motionPref === 'off' ? 'full' : 'system'
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#0a0f15' : '#eef2f6')
  }, [theme, motionPref])

  return (
    <MotionConfig reducedMotion={reduced ? 'always' : 'never'}>
      <AnimatePresence mode="wait">
        {status === 'ready' ? <Workspace key="ws" /> : <UploadScreen key="up" />}
      </AnimatePresence>
      <LevelUpOverlay />
    </MotionConfig>
  )
}
