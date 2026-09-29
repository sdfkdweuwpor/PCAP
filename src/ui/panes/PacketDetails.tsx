// Packet details: collapsible protocol tree. Hovering a field highlights its bytes; clicking selects
// it (and, in Field Hunt, stages it as the answer).

import { AnimatePresence, motion } from 'framer-motion'
import { memo, useEffect, useMemo, useState } from 'react'
import type { Field } from '../../core/types'
import { getDissection, useCapture } from '../../store/capture'
import { useGame } from '../../store/game'

const MASK = '••••••••'

/** Paths (index chains) to fields whose key matches, used to auto-expand for "Show me". */
function pathsTo(layers: Field[], keys: string[]): string[] {
  const out: string[] = []
  const walk = (fs: Field[], prefix: string) =>
    fs.forEach((f, i) => {
      const id = prefix ? `${prefix}.${i}` : `${i}`
      if (f.key && keys.includes(f.key)) out.push(id)
      if (f.children) walk(f.children, id)
    })
  walk(layers, '')
  return out
}

export function PacketDetails() {
  const selected = useCapture((s) => s.selected)
  const sweep = useCapture((s) => s.sweep)
  const reveal = useCapture((s) => s.revealSecrets)
  const d = selected ? getDissection(selected) : null
  const [open, setOpen] = useState<Set<string>>(new Set())

  // Default: expand the top-most protocol layer, like a focused Wireshark view.
  useEffect(() => {
    if (!d) return
    const s = new Set<string>()
    if (d.layers.length > 1) s.add(String(d.layers.length - 1))
    setOpen(s)
  }, [d])

  const target = useMemo(() => {
    if (!d || !sweep || sweep.packet !== selected || !sweep.fieldKeys.length) return [] as string[]
    return pathsTo(d.layers, sweep.fieldKeys)
  }, [d, sweep, selected])

  useEffect(() => {
    if (!target.length) return
    setOpen((prev) => {
      const s = new Set(prev)
      for (const id of target) {
        const parts = id.split('.')
        for (let i = 1; i < parts.length; i++) s.add(parts.slice(0, i).join('.'))
      }
      return s
    })
  }, [target])

  const hasSecret = useMemo(() => (d ? JSON.stringify(d.layers).includes('"secret":true') : false), [d])
  const telnetCred = selected ? useCapture.getState().index?.packets[selected - 1].facts.creds : undefined

  if (!d) return <p className="p-3 text-[12px] text-faint">-- select a frame to decode it --</p>

  const toggle = (id: string) =>
    setOpen((prev) => {
      const s = new Set(prev)
      if (s.has(id)) s.delete(id)
      else s.add(id)
      return s
    })

  return (
    <div className="scroll-thin h-full overflow-auto p-1 text-[12px] leading-[1.45]" role="tree" aria-label={`Packet ${selected} details`}>
      {(hasSecret || telnetCred?.secret) && (
        <div className="mb-1 flex items-center justify-between gap-2 border-l-2 border-[var(--p-clear)] bg-[var(--p-clear)]/10 px-2 py-0.5 text-[11.5px]">
          <span>
            <span className="text-[var(--p-clear)]">!! cleartext credential</span> <span className="text-muted">— anyone on the path can read these bytes</span>
          </span>
          <button className="shrink-0 border border-line px-2 text-[11px] uppercase tracking-[0.08em] hover:border-accent" onClick={() => useCapture.getState().setReveal(!reveal)} aria-pressed={reveal}>
            {reveal ? 'mask' : 'reveal'}
          </button>
        </div>
      )}
      {d.layers.map((f, i) => (
        <Node
          key={`${selected}-${i}`}
          f={f}
          id={String(i)}
          depth={0}
          open={open}
          toggle={toggle}
          target={target}
          sweepToken={sweep?.token ?? 0}
          reveal={reveal}
          telnetSecret={telnetCred?.kind === 'pass'}
        />
      ))}
    </div>
  )
}

interface NodeProps {
  f: Field
  id: string
  depth: number
  open: Set<string>
  toggle: (id: string) => void
  target: string[]
  sweepToken: number
  reveal: boolean
  telnetSecret: boolean
}

const Node = memo(function Node({ f, id, depth, open, toggle, target, sweepToken, reveal, telnetSecret }: NodeProps) {
  const hoverKey = useCapture((s) => s.hoverKey)
  const hover = useCapture((s) => s.hover)
  const selField = useCapture((s) => s.selectedField)
  const fieldMode = useGame((s) => s.phase === 'question' && s.deck[s.idx]?.kind === 'field')
  const isOpen = open.has(id)
  const hasKids = !!f.children?.length
  const isTarget = target.includes(id)
  const isSel = selField?.offset === f.offset && selField.length === f.length && selField.name === f.name
  const isHover = hover && f.length > 0 && hover.offset === f.offset && hover.length === f.length && (hoverKey === null || hoverKey === f.key)
  const secret = (f.secret || (telnetSecret && f.key === 'telnet.data')) && !reveal
  const value = f.value !== undefined ? (secret ? MASK : f.value) : undefined
  const name = secret && f.key === 'http.authorization' ? 'Authorization: Basic ' + MASK : f.name

  const onSelect = () => {
    const cap = useCapture.getState()
    cap.selectField({ offset: f.offset, length: f.length, key: f.key, name: f.name })
    if (fieldMode) useGame.getState().setFieldPick({ key: f.key, via: 'tree', name: f.name })
  }

  return (
    <div role="treeitem" aria-expanded={hasKids ? isOpen : undefined} aria-level={depth + 1} aria-selected={isSel}>
      <div
        className={`group relative flex cursor-default items-start gap-1 px-1 ${
          isSel ? 'bg-accent text-accent-ink' : isHover ? 'bg-accent/15' : 'hover:bg-panel3'
        } ${f.warn && !isSel ? 'text-[var(--p-clear)]' : ''}`}
        style={{ paddingLeft: depth * 14 + 4 }}
        onMouseEnter={() => f.length > 0 && useCapture.getState().setHover({ offset: f.offset, length: f.length }, f.key ?? null)}
        onMouseLeave={() => useCapture.getState().setHover(null)}
        onClick={onSelect}
        onDoubleClick={() => hasKids && toggle(id)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            onSelect()
          } else if (e.key === 'ArrowRight' && hasKids && !isOpen) toggle(id)
          else if (e.key === 'ArrowLeft' && hasKids && isOpen) toggle(id)
        }}
        tabIndex={0}
      >
        {isTarget && (
          <motion.span
            key={sweepToken}
            className="pointer-events-none absolute inset-0 bg-accent/40"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 1, 0.35] }}
            transition={{ duration: 1.1, times: [0, 0.3, 1] }}
          />
        )}
        <button
          className={`w-3 shrink-0 text-left ${isSel ? '' : 'text-faint'} ${hasKids ? '' : 'invisible'}`}
          onClick={(e) => {
            e.stopPropagation()
            toggle(id)
          }}
          aria-label={isOpen ? 'Collapse' : 'Expand'}
          tabIndex={-1}
        >
          {isOpen ? '-' : '+'}
        </button>
        <span className={`relative break-all ${depth === 0 ? 'font-semibold' : ''}`}>
          {name}
          {value !== undefined && value !== '' && (
            <>
              <span className={isSel ? '' : 'text-faint'}>: </span>
              <span className={secret && !isSel ? 'tracking-widest text-[var(--p-clear)]' : ''}>{value}</span>
            </>
          )}
        </span>
      </div>
      <AnimatePresence initial={false}>
        {isOpen && hasKids && (
          <motion.div
            role="group"
            initial={{ opacity: 0, y: -3 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, transition: { duration: 0.06 } }}
            transition={{ duration: 0.14 }}
          >
            {f.children!.map((c, i) => (
              <Node
                key={i}
                f={c}
                id={`${id}.${i}`}
                depth={depth + 1}
                open={open}
                toggle={toggle}
                target={target}
                sweepToken={sweepToken}
                reveal={reveal}
                telnetSecret={telnetSecret}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
})
