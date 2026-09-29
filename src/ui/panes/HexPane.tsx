// Packet bytes: hex + ASCII dump. Hovering bytes highlights the owning field; hovering a field
// highlights its bytes; "Show me" sweeps across the target bytes.

import { useMemo } from 'react'
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

export function HexPane() {
  const selected = useCapture((s) => s.selected)
  const hover = useCapture((s) => s.hover)
  const selField = useCapture((s) => s.selectedField)
  const sweep = useCapture((s) => s.sweep)
  const reveal = useCapture((s) => s.revealSecrets)
  const fieldMode = useGame((s) => s.phase === 'question' && s.deck[s.idx]?.kind === 'field')
  const bytes = useMemo(() => (selected ? getFrameBytes(selected) : new Uint8Array()), [selected])
  const d = selected ? getDissection(selected) : null
  const telnetPass = selected ? useCapture.getState().index?.packets[selected - 1].facts.creds?.kind === 'pass' : false
  const secrets = useMemo(() => (d && !reveal ? secretRanges(d.layers, telnetPass) : []), [d, reveal, telnetPass])
  const sweepRanges = useMemo(() => {
    if (!d || !sweep || sweep.packet !== selected) return [] as [number, number][]
    return sweep.fieldKeys
      .map((k) => findByKey(d.layers, k))
      .filter((f): f is Field => !!f && f.length > 0)
      .map((f) => [f.offset, f.offset + f.length] as [number, number])
  }, [d, sweep, selected])

  if (!selected || !d) return <p className="p-4 text-sm text-muted">Packet bytes appear here.</p>

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

  const rows = Math.ceil(bytes.length / 16)
  const cell = (i: number, kind: 'hex' | 'ascii') => {
    const b = bytes[i]
    const masked = inAny(i, secrets)
    const hl = inR(i, hover)
    const sel = inR(i, selField)
    const sw = inAny(i, sweepRanges)
    const txt = masked ? (kind === 'hex' ? '••' : '•') : kind === 'hex' ? b.toString(16).padStart(2, '0') : printable(b)
    return (
      <span
        key={`${kind}${i}-${sw ? sweep?.token : 0}`}
        data-off={i}
        onMouseEnter={() => onHover(i)}
        onClick={() => onClick(i)}
        className={`relative cursor-pointer rounded-[3px] ${kind === 'hex' ? 'px-[3px]' : ''} ${
          sel ? 'bg-accent text-accent-ink' : hl ? 'bg-accent/30' : ''
        } ${masked ? 'text-[var(--p-clear)]' : ''} ${sw ? 'byte-sweep' : ''}`}
        style={sw ? ({ ['--i' as string]: sweepIndex(i) } as React.CSSProperties) : undefined}
      >
        {txt}
      </span>
    )
  }

  return (
    <div
      className="scroll-thin h-full overflow-auto p-2 font-mono text-[12px] leading-[1.55]"
      onMouseLeave={() => onHover(null)}
      aria-label={`Packet ${selected} bytes, ${bytes.length} bytes. Click a byte to select its field.`}
    >
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex gap-3 whitespace-nowrap">
          <span className="select-none text-faint">{(r * 16).toString(16).padStart(4, '0')}</span>
          <span className="flex">
            {Array.from({ length: 16 }, (_, c) => {
              const i = r * 16 + c
              if (i >= bytes.length) return <span key={c} className="px-[3px] text-transparent">00</span>
              return (
                <span key={c} className={c === 8 ? 'ml-2' : ''}>
                  {cell(i, 'hex')}
                </span>
              )
            })}
          </span>
          <span className="text-muted">
            {Array.from({ length: Math.min(16, bytes.length - r * 16) }, (_, c) => cell(r * 16 + c, 'ascii'))}
          </span>
        </div>
      ))}
    </div>
  )
}
