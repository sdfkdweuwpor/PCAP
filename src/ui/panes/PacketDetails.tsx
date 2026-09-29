// Packet details: collapsible protocol tree. Hovering a field highlights its bytes; clicking selects
// it (and, in Field Hunt, stages it as the answer). Keyboard: one Tab stop for the whole tree (roving
// tabindex), Up/Down/Home/End move, Right/Left expand/collapse or step to the first child/parent
// (WAI-ARIA tree pattern), Enter/Space select.

import { AnimatePresence, motion } from 'framer-motion'
import { memo, useId, useMemo, useRef, useState } from 'react'
import type { Dissection, Field } from '../../core/types'
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

/** Every ancestor path of the given paths ("1.2.0" -> "1", "1.2"). */
function withAncestors(base: Set<string>, ids: string[]): Set<string> {
  const s = new Set(base)
  for (const id of ids) {
    const parts = id.split('.')
    for (let i = 1; i < parts.length; i++) s.add(parts.slice(0, i).join('.'))
  }
  return s
}

interface Row {
  id: string
  parent: string | null
  hasKids: boolean
}

/** The rows currently on screen, in order (children of collapsed nodes are skipped). */
function visibleRows(layers: Field[], open: Set<string>): Row[] {
  const out: Row[] = []
  const walk = (fs: Field[], prefix: string, parent: string | null) =>
    fs.forEach((f, i) => {
      const id = prefix ? `${prefix}.${i}` : `${i}`
      const hasKids = !!f.children?.length
      out.push({ id, parent, hasKids })
      if (hasKids && open.has(id)) walk(f.children!, id, id)
    })
  walk(layers, '', null)
  return out
}

export function PacketDetails() {
  const selected = useCapture((s) => s.selected)
  const d = selected ? getDissection(selected) : null
  if (!selected || !d) return <p className="p-3 text-[12px] text-faint">-- select a frame to decode it --</p>
  // Keyed by frame: choosing another packet remounts the tree, which resets what is expanded and the tab stop.
  return <DetailsTree key={selected} selected={selected} d={d} />
}

function DetailsTree({ selected, d }: { selected: number; d: Dissection }) {
  const sweep = useCapture((s) => s.sweep)
  const reveal = useCapture((s) => s.revealSecrets)
  const base = useId()
  const box = useRef<HTMLDivElement>(null)

  const target = useMemo(() => {
    if (!sweep || sweep.packet !== selected || !sweep.fieldKeys.length) return [] as string[]
    return pathsTo(d.layers, sweep.fieldKeys)
  }, [d, sweep, selected])

  // Default: expand the top-most protocol layer, like a focused Wireshark view (plus the path to a "Show me" target).
  const [open, setOpen] = useState<Set<string>>(() => {
    const s = new Set<string>()
    if (d.layers.length > 1) s.add(String(d.layers.length - 1))
    return withAncestors(s, target)
  })
  // A new "Show me" sweep on this frame expands the path to its fields (adjusted during render, not in an effect).
  const sweepToken = sweep?.token ?? 0
  const [seenSweep, setSeenSweep] = useState(sweepToken)
  if (sweepToken !== seenSweep) {
    setSeenSweep(sweepToken)
    if (target.length) setOpen((prev) => withAncestors(prev, target))
  }

  const [activeId, setActiveId] = useState('0')
  const rows = useMemo(() => visibleRows(d.layers, open), [d, open])
  // If the tab stop's row got hidden (an ancestor collapsed), it falls back to the closest visible ancestor.
  const active = useMemo(() => {
    const visible = new Set(rows.map((r) => r.id))
    let id = activeId
    while (!visible.has(id) && id.includes('.')) id = id.slice(0, id.lastIndexOf('.'))
    return visible.has(id) ? id : (rows[0]?.id ?? '')
  }, [rows, activeId])

  const hasSecret = useMemo(() => JSON.stringify(d.layers).includes('"secret":true'), [d])
  const telnetCred = useCapture.getState().index?.packets[selected - 1].facts.creds

  const toggle = (id: string) =>
    setOpen((prev) => {
      const s = new Set(prev)
      if (s.has(id)) s.delete(id)
      else s.add(id)
      return s
    })

  const focusRow = (id: string) => {
    setActiveId(id)
    box.current?.querySelector<HTMLElement>(`[data-node="${id}"]`)?.focus()
  }

  // Arrow-key navigation for the focused tree item (Enter/Space are handled by the item itself).
  const onNav = (e: React.KeyboardEvent, id: string) => {
    const i = rows.findIndex((r) => r.id === id)
    const row = rows[i]
    if (!row) return
    let go: string | undefined
    if (e.key === 'ArrowDown') go = rows[Math.min(rows.length - 1, i + 1)].id
    else if (e.key === 'ArrowUp') go = rows[Math.max(0, i - 1)].id
    else if (e.key === 'Home') go = rows[0].id
    else if (e.key === 'End') go = rows[rows.length - 1].id
    else if (e.key === 'ArrowRight') {
      if (row.hasKids && !open.has(id)) toggle(id)
      else if (row.hasKids) go = rows[i + 1].id // open: first child
    } else if (e.key === 'ArrowLeft') {
      if (row.hasKids && open.has(id)) toggle(id)
      else if (row.parent) go = row.parent
    } else return
    e.preventDefault()
    e.stopPropagation()
    if (go !== undefined) focusRow(go)
  }

  return (
    <div ref={box} className="scroll-thin h-full overflow-auto p-1 text-[12px] leading-[1.45]">
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
      <div role="tree" aria-label={`Packet ${selected} details`}>
        {d.layers.map((f, i) => (
          <Node
            key={`${selected}-${i}`}
            f={f}
            id={String(i)}
            depth={0}
            open={open}
            toggle={toggle}
            target={target}
            sweepToken={sweepToken}
            reveal={reveal}
            telnetSecret={telnetCred?.kind === 'pass'}
            idBase={base}
            activeId={active}
            onActive={setActiveId}
            onNav={onNav}
          />
        ))}
      </div>
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
  idBase: string
  activeId: string
  onActive: (id: string) => void
  onNav: (e: React.KeyboardEvent, id: string) => void
}

const Node = memo(function Node({ f, id, depth, open, toggle, target, sweepToken, reveal, telnetSecret, idBase, activeId, onActive, onNav }: NodeProps) {
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
  const rowId = `${idBase}-${id}`

  const onSelect = () => {
    const cap = useCapture.getState()
    cap.selectField({ offset: f.offset, length: f.length, key: f.key, name: f.name })
    if (fieldMode) useGame.getState().setFieldPick({ key: f.key, via: 'tree', name: f.name })
  }

  return (
    // The treeitem itself is the focus target (roving tabindex); it is named by its own row, not by its nested children.
    <div
      role="treeitem"
      data-node={id}
      className="tree-item"
      aria-labelledby={rowId}
      aria-expanded={hasKids ? isOpen : undefined}
      aria-level={depth + 1}
      aria-selected={isSel}
      tabIndex={activeId === id ? 0 : -1}
      onFocus={(e) => e.target === e.currentTarget && onActive(id)}
      onKeyDown={(e) => {
        // Keys from nested items bubble up through their ancestors' treeitems; only the focused item acts.
        if (e.target !== e.currentTarget || e.altKey || e.ctrlKey || e.metaKey) return
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          e.stopPropagation()
          onSelect()
        } else onNav(e, id)
      }}
    >
      <div
        id={rowId}
        className={`tree-row group relative flex cursor-default items-start gap-1 px-1 ${
          isSel ? 'bg-accent text-accent-ink' : isHover ? 'bg-accent/15' : 'hover:bg-panel3'
        } ${f.warn && !isSel ? 'text-[var(--p-clear)]' : ''}`}
        style={{ paddingLeft: depth * 14 + 4 }}
        onMouseEnter={() => f.length > 0 && useCapture.getState().setHover({ offset: f.offset, length: f.length }, f.key ?? null)}
        onMouseLeave={() => useCapture.getState().setHover(null)}
        onClick={onSelect}
        onDoubleClick={() => hasKids && toggle(id)}
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
          // Keep focus on the tree item: the +/- is a mouse affordance, the arrow keys do the same from the keyboard.
          onMouseDown={(e) => e.preventDefault()}
          onClick={(e) => {
            e.stopPropagation()
            toggle(id)
          }}
          aria-label={isOpen ? 'Collapse' : 'Expand'}
          aria-hidden
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
                idBase={idBase}
                activeId={activeId}
                onActive={onActive}
                onNav={onNav}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
})
