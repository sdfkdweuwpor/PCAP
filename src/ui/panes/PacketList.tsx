// Packet list: virtualized, Wireshark-style columns and coloring, keyboard navigable.

import { useVirtualizer } from '@tanstack/react-virtual'
import { useEffect, useMemo, useRef } from 'react'
import { maskInfo } from '../../game/knowledge'
import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'
import { protoVar } from '../colors'
import { IconCheck, IconX } from '../icons'

const ROW_H = 24

export function PacketList() {
  const index = useCapture((s) => s.index)!
  const visible = useCapture((s) => s.visible)
  const selected = useCapture((s) => s.selected)
  const multi = useCapture((s) => s.multi)
  const flash = useCapture((s) => s.flash)
  const lockedTo = useCapture((s) => s.lockedTo)
  const reveal = useCapture((s) => s.revealSecrets)
  const { select, toggleMulti } = useCapture.getState()
  const q = useGame((s) => (s.phase === 'question' ? s.deck[s.idx] : null))
  const multiMode = q?.kind === 'pick' && q.multi
  const pickMode = q?.kind === 'pick'

  const rows = useMemo(() => visible ?? index.packets.map((p) => p.no), [visible, index])
  const parent = useRef<HTMLDivElement>(null)
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current, estimateSize: () => ROW_H, overscan: 20 })

  // Keep the selected row in view (keyboard nav, "show me", glide-to-answer).
  useEffect(() => {
    if (selected === null) return
    const i = rows.indexOf(selected)
    if (i >= 0) v.scrollToIndex(i, { align: 'auto' })
  }, [selected, rows, v])

  const onKey = (e: React.KeyboardEvent) => {
    const i = selected === null ? -1 : rows.indexOf(selected)
    const go = (j: number) => {
      const n = rows[Math.max(0, Math.min(rows.length - 1, j))]
      if (n !== undefined) select(n)
    }
    if (e.key === 'ArrowDown') go(i + 1)
    else if (e.key === 'ArrowUp') go(i - 1)
    else if (e.key === 'PageDown') go(i + 20)
    else if (e.key === 'PageUp') go(i - 20)
    else if (e.key === 'Home') go(0)
    else if (e.key === 'End') go(rows.length - 1)
    else if (e.key === ' ' && multiMode && selected !== null) toggleMulti(selected)
    else if (e.key === 'Enter' && pickMode) {
      const g = useGame.getState()
      if (multiMode) {
        if (multi.length) g.submit({ kind: 'pick', packets: multi })
      } else if (selected !== null) g.submit({ kind: 'pick', packets: [selected] })
    } else return
    e.preventDefault()
  }

  const flashFor = (no: number) => (flash && flash.frames.includes(no) ? flash : null)

  return (
    <div className="flex h-full min-h-0 flex-col font-mono text-[12px]">
      <div className="grid shrink-0 grid-cols-[3.5rem_5.5rem_minmax(7rem,1fr)_minmax(7rem,1fr)_5rem_3.5rem_minmax(12rem,3fr)] gap-x-2 border-b border-line bg-panel2 px-2 py-1 font-sans text-[11px] font-semibold uppercase tracking-wide text-muted max-md:grid-cols-[3rem_minmax(6rem,1fr)_4.5rem_minmax(8rem,2fr)]">
        <span>No.</span>
        <span className="max-md:hidden">Time</span>
        <span>Source</span>
        <span className="max-md:hidden">Destination</span>
        <span>Protocol</span>
        <span className="max-md:hidden">Length</span>
        <span>Info</span>
      </div>
      <div
        ref={parent}
        tabIndex={0}
        role="grid"
        aria-label={`Packet list, ${rows.length} packets. Use arrow keys to move${pickMode ? ', Enter to answer' : ''}${multiMode ? ', Space to toggle a packet' : ''}.`}
        aria-rowcount={rows.length}
        onKeyDown={onKey}
        className="scroll-thin relative min-h-0 flex-1 overflow-auto outline-none"
      >
        {rows.length === 0 && <p className="p-4 font-sans text-sm text-muted">No packets match this filter.</p>}
        <div style={{ height: v.getTotalSize(), position: 'relative', minWidth: '100%' }}>
          {v.getVirtualItems().map((vi) => {
            const no = rows[vi.index]
            const p = index.packets[no - 1]
            const isSel = selected === no
            const inMulti = multi.includes(no)
            const f = flashFor(no)
            const dim = lockedTo !== null && lockedTo !== no
            const pulse = f?.kind === 'correct' ? 'var(--good)' : f?.kind === 'wrong' ? 'var(--bad)' : f?.kind === 'answer' ? 'var(--good)' : undefined
            return (
              <div
                key={`${no}-${f?.token ?? 0}`}
                role="row"
                aria-rowindex={vi.index + 1}
                aria-selected={isSel || inMulti}
                onClick={(e) => {
                  if (multiMode || e.metaKey || e.ctrlKey) {
                    if (multiMode) toggleMulti(no)
                  }
                  select(no)
                  parent.current?.focus({ preventScroll: true })
                }}
                onDoubleClick={() => pickMode && !multiMode && useGame.getState().submit({ kind: 'pick', packets: [no] })}
                className={`absolute left-0 right-0 grid cursor-default grid-cols-[3.5rem_5.5rem_minmax(7rem,1fr)_minmax(7rem,1fr)_5rem_3.5rem_minmax(12rem,3fr)] items-center gap-x-2 whitespace-nowrap px-2 max-md:grid-cols-[3rem_minmax(6rem,1fr)_4.5rem_minmax(8rem,2fr)] rc-${p.color} ${
                  isSel ? 'bg-accent! text-accent-ink!' : 'row-tint hover:brightness-125'
                } ${f?.kind === 'wrong' ? 'row-shake' : ''} ${pulse ? 'row-pulse' : ''} ${dim ? 'opacity-40' : ''}`}
                style={{ top: vi.start, height: ROW_H, ['--pulse' as string]: pulse, borderLeft: `3px solid var(--rc)` }}
              >
                <span className="flex items-center gap-1">
                  {multiMode && (
                    <span
                      className={`grid h-3.5 w-3.5 place-items-center rounded-sm border ${inMulti ? 'border-accent bg-accent text-accent-ink' : 'border-muted'}`}
                      aria-hidden
                    >
                      {inMulti && <IconCheck size={10} strokeWidth={3} />}
                    </span>
                  )}
                  {f?.kind === 'correct' || f?.kind === 'answer' ? <IconCheck size={12} className="text-good" aria-label="correct" /> : null}
                  {f?.kind === 'wrong' ? <IconX size={12} className="text-bad" aria-label="incorrect" /> : null}
                  {no}
                </span>
                <span className="max-md:hidden">{p.relTime.toFixed(6)}</span>
                <span className="truncate">{p.src}</span>
                <span className="truncate max-md:hidden">{p.dst}</span>
                <span className="truncate font-semibold" style={isSel ? undefined : { color: protoVar(p.protocol) }}>
                  {p.protocol}
                </span>
                <span className="max-md:hidden">{p.origLen}</span>
                <span className="truncate">{reveal ? p.info : maskInfo(p)}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
