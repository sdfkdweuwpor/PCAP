// Vertical stack of resizable panes. Dragging resizes directly; double-clicking a handle springs
// the layout back to its defaults.

import { motion } from 'framer-motion'
import { Children, useRef, useState, type ReactNode } from 'react'
import { softSpring } from './motion'

export function SplitStack({ defaults, labels, children }: { defaults: number[]; labels: string[]; children: ReactNode }) {
  const [sizes, setSizes] = useState(defaults)
  const [dragging, setDragging] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  const kids = Children.toArray(children)

  const startDrag = (i: number) => (e: React.PointerEvent) => {
    e.preventDefault()
    const el = box.current
    if (!el) return
    const total = el.getBoundingClientRect().height
    const startY = e.clientY
    const start = [...sizes]
    setDragging(true)
    const move = (ev: PointerEvent) => {
      const delta = (ev.clientY - startY) / total
      const a = Math.max(0.08, Math.min(start[i] + start[i + 1] - 0.08, start[i] + delta))
      const next = [...start]
      next[i + 1] = start[i] + start[i + 1] - a
      next[i] = a
      setSizes(next)
    }
    const up = () => {
      setDragging(false)
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  const nudge = (i: number, d: number) => {
    const next = [...sizes]
    const a = Math.max(0.08, Math.min(next[i] + next[i + 1] - 0.08, next[i] + d))
    next[i + 1] = next[i] + next[i + 1] - a
    next[i] = a
    setSizes(next)
  }

  return (
    <div ref={box} className="flex h-full min-h-0 flex-col">
      {kids.map((child, i) => (
        <div key={i} className="contents">
          <motion.section
            aria-label={labels[i]}
            className="min-h-0 overflow-hidden bg-panel"
            animate={{ flexGrow: sizes[i] }}
            initial={false}
            transition={dragging ? { duration: 0 } : softSpring}
            style={{ flexBasis: 0, flexShrink: 1 }}
          >
            {child}
          </motion.section>
          {i < kids.length - 1 && (
            <div
              role="separator"
              aria-orientation="horizontal"
              aria-label={`Resize ${labels[i]} and ${labels[i + 1]}`}
              aria-valuenow={Math.round(sizes[i] * 100)}
              tabIndex={0}
              onPointerDown={startDrag(i)}
              onDoubleClick={() => setSizes(defaults)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowUp') nudge(i, -0.03)
                else if (e.key === 'ArrowDown') nudge(i, 0.03)
              }}
              className="group relative h-1.5 shrink-0 cursor-row-resize bg-line/60 hover:bg-accent/50"
            >
              <span className="absolute left-1/2 top-1/2 h-0.5 w-8 -translate-x-1/2 -translate-y-1/2 rounded bg-muted/60 group-hover:bg-accent" />
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
