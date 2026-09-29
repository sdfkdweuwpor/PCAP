// Main layout. Desktop: Wireshark-style panes + game panel on the right. Mobile: tabs for each pane
// and the game as a draggable bottom sheet.

import { AnimatePresence, motion, useDragControls } from 'framer-motion'
import { useState, type ReactNode } from 'react'
import { useCapture, type Tab } from '../store/capture'
import { useGame } from '../store/game'
import { GamePanel } from './game/GamePanel'
import { Header } from './Header'
import { useMediaQuery } from './hooks'
import { IconUp } from './icons'
import { softSpring } from './motion'
import { ConversationsTable } from './panes/ConversationsTable'
import { FilterBar } from './panes/FilterBar'
import { FlowView } from './panes/FlowView'
import { HexPane } from './panes/HexPane'
import { PacketDetails } from './panes/PacketDetails'
import { PacketList } from './panes/PacketList'
import { StreamView } from './panes/StreamView'
import { SplitStack } from './SplitStack'

const DESKTOP_TABS: { id: Tab; label: string }[] = [
  { id: 'packets', label: 'Packets' },
  { id: 'flow', label: 'Flow' },
  { id: 'conversations', label: 'Conversations' },
  { id: 'stream', label: 'Follow Stream' },
]

type MobileTab = 'list' | 'details' | 'bytes' | 'flow' | 'conversations' | 'stream'
const MOBILE_TABS: { id: MobileTab; label: string }[] = [
  { id: 'list', label: 'List' },
  { id: 'details', label: 'Details' },
  { id: 'bytes', label: 'Bytes' },
  { id: 'flow', label: 'Flow' },
  { id: 'conversations', label: 'Convs' },
  { id: 'stream', label: 'Stream' },
]

export function Workspace() {
  const desktop = useMediaQuery('(min-width: 1024px)')
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex h-full flex-col overflow-hidden">
      <Header />
      {desktop ? <DesktopLayout /> : <MobileLayout />}
    </motion.div>
  )
}

function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div role="tablist" className="scroll-thin flex gap-1 overflow-x-auto">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={`relative shrink-0 rounded-md px-3 py-1.5 text-sm font-medium ${value === t.id ? 'text-fg' : 'text-muted hover:text-fg'}`}
        >
          {value === t.id && <motion.span layoutId="tab-pill" className="absolute inset-0 rounded-md bg-panel3" transition={softSpring} />}
          <span className="relative">{t.label}</span>
        </button>
      ))}
    </div>
  )
}

function DesktopLayout() {
  const tab = useCapture((s) => s.tab)
  const setTab = useCapture((s) => s.setTab)
  const [gameWide, setGameWide] = useState(false)
  return (
    <div className="flex min-h-0 flex-1">
      <div className="flex min-w-0 flex-1 flex-col gap-2 p-2">
        <FilterBar />
        <Tabs tabs={DESKTOP_TABS} value={tab} onChange={setTab} />
        <div className="min-h-0 flex-1 overflow-hidden rounded-lg border border-line">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={tab}
              className="h-full"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              {tab === 'packets' && (
                <SplitStack defaults={[0.46, 0.32, 0.22]} labels={['Packet list', 'Packet details', 'Packet bytes']}>
                  <PacketList />
                  <PacketDetails />
                  <HexPane />
                </SplitStack>
              )}
              {tab === 'flow' && <FlowView />}
              {tab === 'conversations' && <ConversationsTable />}
              {tab === 'stream' && <StreamView />}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
      <motion.aside
        aria-label="Game panel"
        className="flex min-h-0 shrink-0 flex-col border-l border-line bg-panel"
        animate={{ width: gameWide ? 520 : 400 }}
        transition={softSpring}
        initial={false}
      >
        <GamePanel onToggleWide={() => setGameWide((w) => !w)} wide={gameWide} />
      </motion.aside>
    </div>
  )
}

function MobileLayout() {
  const [tab, setTab] = useState<MobileTab>('list')
  const desktopTab = useCapture((s) => s.tab)
  // Keep mobile tabs in sync when the game switches panes (e.g. "Show me").
  const [lastDesktop, setLastDesktop] = useState(desktopTab)
  if (desktopTab !== lastDesktop) {
    setLastDesktop(desktopTab)
    if (desktopTab === 'flow' || desktopTab === 'conversations' || desktopTab === 'stream') setTab(desktopTab)
  }
  const panes: Record<MobileTab, ReactNode> = {
    list: <PacketList />,
    details: <PacketDetails />,
    bytes: <HexPane />,
    flow: <FlowView />,
    conversations: <ConversationsTable />,
    stream: <StreamView />,
  }
  return (
    <div className="relative flex min-h-0 flex-1 flex-col gap-2 p-2 pb-24">
      <FilterBar />
      <Tabs tabs={MOBILE_TABS} value={tab} onChange={setTab} />
      <div className="min-h-0 flex-1 overflow-hidden rounded-lg border border-line bg-panel">{panes[tab]}</div>
      <GameSheet />
    </div>
  )
}

function GameSheet() {
  const [open, setOpen] = useState(true)
  const phase = useGame((s) => s.phase)
  const controls = useDragControls()
  return (
    <motion.div
      className="fixed inset-x-0 bottom-0 z-40 flex max-h-[62vh] flex-col rounded-t-2xl border-t border-line bg-panel shadow-[var(--shadow)]"
      animate={{ y: open ? 0 : 'calc(100% - 64px)' }}
      transition={softSpring}
      drag="y"
      dragListener={false}
      dragControls={controls}
      dragConstraints={{ top: 0, bottom: 0 }}
      dragElastic={0.2}
      onDragEnd={(_, info) => {
        if (info.offset.y > 60) setOpen(false)
        else if (info.offset.y < -40) setOpen(true)
      }}
      style={{ height: '62vh' }}
      aria-label="Game panel"
    >
      <button
        onPointerDown={(e) => controls.start(e)}
        onClick={() => setOpen((o) => !o)}
        className="flex shrink-0 touch-none flex-col items-center gap-1 px-4 pb-2 pt-2"
        aria-expanded={open}
        aria-label={open ? 'Collapse game panel' : 'Expand game panel'}
      >
        <span className="h-1 w-10 rounded-full bg-muted/60" />
        <span className="flex items-center gap-1 text-xs text-muted">
          <motion.span animate={{ rotate: open ? 180 : 0 }}>
            <IconUp size={12} />
          </motion.span>
          {phase === 'question' ? 'Question in progress' : phase === 'feedback' ? 'See explanation' : 'Game'}
        </span>
      </button>
      <div className="min-h-0 flex-1 overflow-hidden">
        <GamePanel />
      </div>
    </motion.div>
  )
}
