// Packet list: virtualized, Wireshark-style columns and coloring, keyboard navigable.

import { useVirtualizer } from '@tanstack/react-virtual'
import { useEffect, useMemo, useRef } from 'react'
import { maskInfo } from '../../game/knowledge'
import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'
import { protoVar } from '../colors'

const ROW_H = 22
const HEADER_H = 24 // sticky column header, sits inside the scroll container above the virtual rows

/**
 * Column sets follow the pane's own width (container queries), not the viewport: the packet list is anywhere from a
 * 358px phone screen to ~580px beside the game console at 1024px, up to full width. Every flexible column is
 * minmax(0, …) so Source/Destination/Info truncate instead of pushing the row past the edge; secondary columns drop out
 * as space runs low (No. Source Protocol Info -> + Destination -> + Time -> + Length).
 */
const COLS =
  'grid grid-cols-[3.5rem_minmax(0,1.2fr)_4rem_minmax(0,1.5fr)] ' +
  '@lg:grid-cols-[3.5rem_minmax(0,1fr)_minmax(0,1fr)_4rem_minmax(0,1.6fr)] ' +
  '@[46rem]:grid-cols-[4rem_5.5rem_minmax(0,1.2fr)_minmax(0,1.2fr)_4.5rem_minmax(0,2fr)] ' +
  '@[56rem]:grid-cols-[4rem_5.5rem_minmax(0,1.2fr)_minmax(0,1.2fr)_4.5rem_3.5rem_minmax(0,2.5fr)]'
const HIDE_DST = 'hidden @lg:block'
const HIDE_TIME = 'hidden @[46rem]:block'
const HIDE_LEN = 'hidden @[56rem]:block'

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
  const v = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_H,
    overscan: 20,
    // The header lives inside the scroll element, so offset the list by it and keep scrolled-to rows clear of it.
    scrollMargin: HEADER_H,
    scrollPaddingStart: HEADER_H,
  })

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
    <div className="@container h-full min-h-0 text-[12px]">
      <div
        ref={parent}
        tabIndex={0}
        role="grid"
        aria-label={`Packet list, ${rows.length} packets. Use arrow keys to move${pickMode ? ', Enter to answer' : ''}${multiMode ? ', Space to toggle a packet' : ''}.`}
        aria-rowcount={rows.length + 1}
        onKeyDown={onKey}
        className="focus-inset scroll-thin relative h-full overflow-auto"
      >
        {/* One scroll context for header and rows, so they can never drift apart. */}
        <div className="min-w-[300px]">
          <div
            role="row"
            aria-rowindex={1}
            className={`${COLS} sticky top-0 z-10 items-center gap-x-2 border-b border-line bg-panel px-2 text-[10.5px] uppercase tracking-[0.12em] text-faint`}
            style={{ height: HEADER_H, borderLeft: '2px solid transparent' }}
          >
            <span role="columnheader">No.</span>
            <span role="columnheader" className={HIDE_TIME}>
              Time
            </span>
            <span role="columnheader">Source</span>
            <span role="columnheader" className={HIDE_DST}>
              Destination
            </span>
            <span role="columnheader">Protocol</span>
            <span role="columnheader" className={HIDE_LEN}>
              Length
            </span>
            <span role="columnheader">Info</span>
          </div>
          {rows.length === 0 && <p className="p-3 text-[12px] text-muted">-- 0 frames match this filter --</p>}
          <div style={{ height: v.getTotalSize(), position: 'relative' }}>
            {v.getVirtualItems().map((vi) => {
              const no = rows[vi.index]
              const p = index.packets[no - 1]
              const isSel = selected === no
              const inMulti = multi.includes(no)
              const f = flashFor(no)
              const dim = lockedTo !== null && lockedTo !== no
              const pulse = f?.kind === 'correct' ? 'var(--good)' : f?.kind === 'wrong' ? 'var(--bad)' : f?.kind === 'answer' ? 'var(--good)' : undefined
              const info = reveal ? p.info : maskInfo(p)
              return (
                <div
                  key={`${no}-${f?.token ?? 0}`}
                  role="row"
                  aria-rowindex={vi.index + 2}
                  aria-selected={isSel || inMulti}
                  onClick={(e) => {
                    if (multiMode || e.metaKey || e.ctrlKey) {
                      if (multiMode) toggleMulti(no)
                    }
                    select(no)
                    parent.current?.focus({ preventScroll: true })
                  }}
                  onDoubleClick={() => pickMode && !multiMode && useGame.getState().submit({ kind: 'pick', packets: [no] })}
                  className={`${COLS} absolute inset-x-0 cursor-default items-center gap-x-2 whitespace-nowrap px-2 rc-${p.color} ${
                    isSel ? 'bg-accent! text-accent-ink!' : 'row-tint hover:bg-panel3'
                  } ${f?.kind === 'wrong' ? 'row-shake' : ''} ${pulse ? 'row-pulse' : ''} ${dim ? 'opacity-35' : ''}`}
                  style={{ top: vi.start - HEADER_H, height: ROW_H, ['--pulse' as string]: pulse, borderLeft: `2px solid var(--rc)` }}
                >
                  <span role="gridcell" className="flex items-center gap-1 tabular-nums">
                    {multiMode && (
                      <span aria-hidden className={inMulti ? 'text-inherit' : 'text-faint'}>
                        {inMulti ? '[x]' : '[ ]'}
                      </span>
                    )}
                    {f?.kind === 'correct' || f?.kind === 'answer' ? (
                      <span className={isSel ? '' : 'text-good'} aria-label="correct">
                        ✓
                      </span>
                    ) : null}
                    {f?.kind === 'wrong' ? (
                      <span className={isSel ? '' : 'text-bad'} aria-label="incorrect">
                        ✗
                      </span>
                    ) : null}
                    {!multiMode && !f && <span aria-hidden className="w-2">{isSel ? '▸' : ''}</span>}
                    {no}
                  </span>
                  <span role="gridcell" className={`tabular-nums ${HIDE_TIME}`}>
                    {p.relTime.toFixed(6)}
                  </span>
                  <span role="gridcell" className="truncate" title={p.src}>
                    {p.src}
                  </span>
                  <span role="gridcell" className={`truncate ${HIDE_DST}`} title={p.dst}>
                    {p.dst}
                  </span>
                  <span role="gridcell" className="truncate font-semibold" style={isSel ? undefined : { color: protoVar(p.protocol) }}>
                    {p.protocol}
                  </span>
                  <span role="gridcell" className={`tabular-nums ${HIDE_LEN}`}>
                    {p.origLen}
                  </span>
                  <span role="gridcell" className="truncate" title={info}>
                    {info}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
