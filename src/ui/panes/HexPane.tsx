// Packet bytes: hex + ASCII dump. Hovering bytes highlights the owning field; hovering a field
// highlights its bytes; "Show me" sweeps across the target bytes. The pane is also keyboard operable:
// focus it, move a byte cursor with the arrow keys / Home / End, and press Enter or Space to select the field.

import { useEffect, useMemo, useRef, useState } from 'react'
import { printable } from '../../core/bytes'
import type { Field } from '../../core/types'
import { fieldAtOffset, findByKey } from '../../game/engine'
import { getDissection, getFrameBytes, useCapture } from '../../store/capture'
import { useGame } from '../../store/game'

function secretRanges(layers: Field[], telnetPass: boolean): [number, number][] {
  const out: [number, number][] = []
  const walk = (fs: Field[]) =>
    fs.forEach((f) => {
      if ((f.secret || (telnetPass && f.key === 'telnet.data')) && f.length > 0) out.push([f.offset, f.offset + f.length])
      if (f.children) walk(f.children)
    })
  walk(layers)
  return out
}

const ROW_BYTES = 16

export function HexPane() {
  const selected = useCapture((s) => s.selected)
  const hover = useCapture((s) => s.hover)
  const selField = useCapture((s) => s.selectedField)
  const sweep = useCapture((s) => s.sweep)
  const reveal = useCapture((s) => s.revealSecrets)
  const fieldMode = useGame((s) => s.phase === 'question' && s.deck[s.idx]?.kind === 'field')
  const bytes = useMemo(() => (selected ? getFrameBytes(selected) : new Uint8Array()), [selected])
  const d = selected ? getDissection(selected) : null
  const [cur, setCur] = useState<{ frame: number | null; i: number }>({ frame: selected, i: 0 })
  const [focused, setFocused] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  // The cursor belongs to one frame; selecting another frame starts it back at byte 0.
  const cursor = cur.frame === selected ? Math.min(cur.i, Math.max(0, bytes.length - 1)) : 0
  const telnetPass = selected ? useCapture.getState().index?.packets[selected - 1].facts.creds?.kind === 'pass' : false
  const secrets = useMemo(() => (d && !reveal ? secretRanges(d.layers, telnetPass) : []), [d, reveal, telnetPass])
  const sweepRanges = useMemo(() => {
    if (!d || !sweep || sweep.packet !== selected) return [] as [number, number][]
    return sweep.fieldKeys
      .map((k) => findByKey(d.layers, k))
      .filter((f): f is Field => !!f && f.length > 0)
      .map((f) => [f.offset, f.offset + f.length] as [number, number])
  }, [d, sweep, selected])

  // Keep the cursor byte inside the scroll viewport while moving with the keyboard.
  useEffect(() => {
    const el = box.current
    const cell = focused ? el?.querySelector<HTMLElement>(`[data-kind="hex"][data-off="${cursor}"]`) : null
    if (!el || !cell) return
    const a = el.getBoundingClientRect()
    const b = cell.getBoundingClientRect()
    if (b.top < a.top) el.scrollTop -= a.top - b.top
    else if (b.bottom > a.bottom) el.scrollTop += b.bottom - a.bottom
    if (b.left < a.left) el.scrollLeft -= a.left - b.left
    else if (b.right > a.right) el.scrollLeft += b.right - a.right
  }, [cursor, focused, selected])

  if (!selected || !d) return <p className="p-3 text-[12px] text-faint">-- no frame selected --</p>

  const inR = (i: number, r: { offset: number; length: number } | null) => !!r && i >= r.offset && i < r.offset + r.length
  const inAny = (i: number, rs: [number, number][]) => rs.some(([a, b]) => i >= a && i < b)
  const sweepIndex = (i: number) => {
    let n = 0
    for (const [a, b] of sweepRanges) {
      if (i >= a && i < b) return n + (i - a)
      n += b - a
    }
    return 0
  }

  const onHover = (i: number | null) => {
    if (i === null) return useCapture.getState().setHover(null)
    const f = fieldAtOffset(d.layers, i)
    if (f) useCapture.getState().setHover({ offset: f.offset, length: f.length }, f.key ?? null)
  }
  const onClick = (i: number) => {
    const f = fieldAtOffset(d.layers, i)
    if (!f) return
    useCapture.getState().selectField({ offset: f.offset, length: f.length, key: f.key, name: f.name })
    if (fieldMode) useGame.getState().setFieldPick({ offset: i, key: f.key, via: 'hex', name: f.name })
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.altKey || e.metaKey || !bytes.length) return
    const last = bytes.length - 1
    const rowStart = cursor - (cursor % ROW_BYTES)
    let next: number
    if (e.key === 'ArrowLeft') next = cursor - 1
    else if (e.key === 'ArrowRight') next = cursor + 1
    else if (e.key === 'ArrowUp') next = cursor >= ROW_BYTES ? cursor - ROW_BYTES : cursor
    else if (e.key === 'ArrowDown') next = cursor + ROW_BYTES <= last ? cursor + ROW_BYTES : rowStart + ROW_BYTES <= last ? last : cursor // last row is partial: land on its final byte
    else if (e.key === 'Home') next = e.ctrlKey ? 0 : rowStart
    else if (e.key === 'End') next = e.ctrlKey ? last : rowStart + ROW_BYTES - 1
    else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      e.stopPropagation()
      onClick(cursor) // exactly what clicking the byte does
      return
    } else return
    e.preventDefault()
    e.stopPropagation()
    setCur({ frame: selected, i: Math.max(0, Math.min(last, next)) })
  }

  // Spoken position for screen readers (secret bytes are never read out).
  const curField = fieldAtOffset(d.layers, cursor)
  const curSecret = inAny(cursor, secrets) || (!!curField && !reveal && !!(curField.secret || (telnetPass && curField.key === 'telnet.data')))
  const announce = focused && bytes.length
    ? `byte ${cursor}, offset 0x${cursor.toString(16)}, ${curSecret ? 'masked' : `value 0x${bytes[cursor].toString(16).padStart(2, '0')}${curField ? `, ${curField.name}` : ''}`}`
    : ''

  const rows = Math.ceil(bytes.length / ROW_BYTES)
  const cell = (i: number, kind: 'hex' | 'ascii') => {
    const b = bytes[i]
    const masked = inAny(i, secrets)
    const hl = inR(i, hover)
    const sel = inR(i, selField)
    const sw = inAny(i, sweepRanges)
    const txt = masked ? (kind === 'hex' ? '••' : '•') : kind === 'hex' ? b.toString(16).padStart(2, '0') : printable(b)
    const isCursor = focused && i === cursor
    return (
      <span
        key={`${kind}${i}-${sw ? sweep?.token : 0}`}
        data-off={i}
        data-kind={kind}
        onMouseEnter={() => onHover(i)}
        onClick={() => {
          setCur({ frame: selected, i })
          onClick(i)
        }}
        className={`relative cursor-pointer ${kind === 'hex' ? 'px-[3px]' : ''} ${
          sel ? 'bg-accent text-accent-ink' : hl ? 'bg-accent/30' : ''
        } ${masked ? 'text-[var(--p-clear)]' : ''} ${sw ? 'byte-sweep' : ''} ${isCursor ? 'z-10 outline outline-1 outline-fg' : ''}`}
        style={sw ? ({ ['--i' as string]: sweepIndex(i) } as React.CSSProperties) : undefined}
      >
        {txt}
      </span>
    )
  }

  return (
    <div
      ref={box}
      role="group"
      tabIndex={0}
      className="focus-inset scroll-thin relative h-full overflow-auto px-2 py-1 text-[12px] leading-[1.5]"
      onMouseLeave={() => onHover(null)}
      onKeyDown={onKeyDown}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      aria-label={`Packet ${selected} bytes, ${bytes.length} bytes. Click a byte or use the arrow keys, then Enter, to select its field.`}
    >
      <span className="sr-only" aria-live="polite">
        {announce}
      </span>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex gap-3 whitespace-nowrap">
          <span className="select-none text-faint">{(r * ROW_BYTES).toString(16).padStart(4, '0')}</span>
          <span className="flex">
            {Array.from({ length: ROW_BYTES }, (_, c) => {
              const i = r * ROW_BYTES + c
              if (i >= bytes.length) return <span key={c} className="px-[3px] text-transparent">00</span>
              return (
                <span key={c} className={c === 8 ? 'ml-2' : ''}>
                  {cell(i, 'hex')}
                </span>
              )
            })}
          </span>
          <span className="text-muted">
            {Array.from({ length: Math.min(ROW_BYTES, bytes.length - r * ROW_BYTES) }, (_, c) => cell(r * ROW_BYTES + c, 'ascii'))}
          </span>
        </div>
      ))}
    </div>
  )
}
