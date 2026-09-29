// Main layout. Desktop: Wireshark-style panes + game panel on the right. Mobile: tabs for each pane
// and the game as a draggable bottom sheet.

import { AnimatePresence, motion, useDragControls } from 'framer-motion'
import { useEffect, useState, type ReactNode } from 'react'
import { useCapture, type Tab } from '../store/capture'
import { useGame } from '../store/game'
import { GamePanel } from './game/GamePanel'
import { Header, StatusBar } from './Header'
import { setConsoleVisible } from './hotkeys'
import { useMediaQuery } from './hooks'
import { softSpring } from './motion'
import { ConversationsTable } from './panes/ConversationsTable'
import { FilterBar } from './panes/FilterBar'
import { FlowView } from './panes/FlowView'
import { HexPane } from './panes/HexPane'
import { PacketDetails } from './panes/PacketDetails'
import { PacketList } from './panes/PacketList'
import { StreamView } from './panes/StreamView'
import { SplitStack } from './SplitStack'
import { Frame } from './term'

const DESKTOP_TABS: { id: Tab; label: string }[] = [
  { id: 'packets', label: 'packets' },
  { id: 'flow', label: 'flow graph' },
  { id: 'conversations', label: 'conversations' },
  { id: 'stream', label: 'follow stream' },
]

type MobileTab = 'list' | 'details' | 'bytes' | 'flow' | 'conversations' | 'stream'
const MOBILE_TABS: { id: MobileTab; label: string }[] = [
  { id: 'list', label: 'list' },
  { id: 'details', label: 'tree' },
  { id: 'bytes', label: 'hex' },
  { id: 'flow', label: 'flow' },
  { id: 'conversations', label: 'convs' },
  { id: 'stream', label: 'stream' },
]

export function Workspace() {
  const desktop = useMediaQuery('(min-width: 1024px)')
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex h-full flex-col overflow-hidden">
      <Header />
      {desktop ? <DesktopLayout /> : <MobileLayout />}
      {desktop && <StatusBar />}
    </motion.div>
  )
}

function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div role="tablist" className="scroll-thin flex overflow-x-auto border-b border-line text-[12px]">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={`relative shrink-0 border-r border-line px-3 py-1 lowercase ${value === t.id ? 'bg-panel text-accent' : 'text-muted hover:bg-panel3 hover:text-fg'}`}
        >
          {value === t.id && <motion.span layoutId="tab-mark" className="absolute inset-x-0 -bottom-px h-0.5 bg-accent" transition={softSpring} />}
          {t.label}
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
        <div className="flex min-h-0 flex-1 flex-col border border-line">
          <Tabs tabs={DESKTOP_TABS} value={tab} onChange={setTab} />
          <div className="min-h-0 flex-1 overflow-hidden">
            <AnimatePresence mode="wait" initial={false}>
              <motion.div key={tab} className="h-full" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.08 }}>
                {tab === 'packets' && <PacketsPanes />}
                {tab === 'flow' && <FlowView />}
                {tab === 'conversations' && <ConversationsTable />}
                {tab === 'stream' && <StreamView />}
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </div>
      <motion.aside aria-label="Game console" className="flex min-h-0 shrink-0 flex-col py-2 pr-2" animate={{ width: gameWide ? 540 : 420 }} transition={softSpring} initial={false}>
        <GamePanel onToggleWide={() => setGameWide((w) => !w)} wide={gameWide} />
      </motion.aside>
    </div>
  )
}

function PacketsPanes() {
  const shown = useCapture((s) => s.visible?.length ?? s.index?.packets.length ?? 0)
  const selected = useCapture((s) => s.selected)
  const len = useCapture((s) => (s.selected && s.index ? s.index.packets[s.selected - 1].capLen : 0))
  return (
    <SplitStack defaults={[0.46, 0.32, 0.22]} labels={['Packet list', 'Packet details', 'Packet bytes']}>
      <Frame title="packet list" meta={`${shown} shown`} className="h-full border-0">
        <PacketList />
      </Frame>
      <Frame title="details" meta={selected ? `frame ${selected}` : '—'} className="h-full border-0">
        <PacketDetails />
      </Frame>
      <Frame title="bytes" meta={selected ? `${len} bytes` : '—'} className="h-full border-0">
        <HexPane />
      </Frame>
    </SplitStack>
  )
}

const PACKET_PANES: MobileTab[] = ['list', 'details', 'bytes']

function MobileLayout() {
  const [tab, setTabState] = useState<MobileTab>('list')
  const desktopTab = useCapture((s) => s.tab)
  // Keep mobile tabs in sync when the game switches panes (e.g. "Show me"). The store's "packets" tab covers
  // list, tree and hex, so it only moves the view when another pane is showing.
  const [lastDesktop, setLastDesktop] = useState(desktopTab)
  if (desktopTab !== lastDesktop) {
    setLastDesktop(desktopTab)
    if (desktopTab !== 'packets') setTabState(desktopTab)
    else if (!PACKET_PANES.includes(tab)) setTabState('list')
  }
  // Tell the store too, so the next game-driven switch to the same pane still registers as a change.
  const setTab = (t: MobileTab) => {
    setTabState(t)
    const store: Tab = PACKET_PANES.includes(t) ? 'packets' : (t as Tab)
    setLastDesktop(store)
    useCapture.getState().setTab(store)
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
    <div className="relative flex min-h-0 flex-1 flex-col gap-2 p-2 pb-10">
      <FilterBar />
      <Tabs tabs={MOBILE_TABS} value={tab} onChange={setTab} />
      <div className="min-h-0 flex-1 overflow-hidden border border-line bg-panel">{panes[tab]}</div>
      <GameSheet />
    </div>
  )
}

function GameSheet() {
  const [open, setOpen] = useState(true)
  const phase = useGame((s) => s.phase)
  const controls = useDragControls()
  // Console shortcuts (answer keys, n for next) must not fire while the sheet is collapsed.
  useEffect(() => {
    setConsoleVisible(open)
    return () => setConsoleVisible(true)
  }, [open])
  return (
    <motion.div
      className="fixed inset-x-0 bottom-0 z-40 flex max-h-[62vh] flex-col border-t-2 border-accent bg-panel"
      animate={{ y: open ? 0 : 'calc(100% - 34px)' }}
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
      aria-label="Game console"
    >
      <button
        onPointerDown={(e) => controls.start(e)}
        onClick={() => setOpen((o) => !o)}
        className="flex h-[32px] shrink-0 touch-none items-center justify-between px-3 text-[11px] uppercase tracking-[0.12em] text-muted"
        aria-expanded={open}
        aria-label={open ? 'Collapse game console' : 'Expand game console'}
      >
        <span>
          <span className="text-accent">console</span> · {phase === 'question' ? 'question open' : phase === 'feedback' ? 'answered' : phase}
        </span>
        <span aria-hidden>{open ? '▼ hide' : '▲ show'}</span>
      </button>
      <div className="min-h-0 flex-1 overflow-hidden px-2 pb-[max(0.5rem,env(safe-area-inset-bottom))]" inert={!open}>
        <GamePanel />
      </div>
    </motion.div>
  )
}
