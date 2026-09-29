// Animated ladder (sequence) diagram: hosts are vertical lanes, packets are arrows in time order.
// Glowing markers travel along arrows during playback; TCP handshakes lock together like a zipper and
// the connection band fades on FIN or snaps on RST. Scrubbable timeline with speed control.

import { motion } from 'framer-motion'
import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CaptureIndex, PacketSummary } from '../../core/types'
import { Kb } from '../../game/knowledge'
import { useCapture } from '../../store/capture'
import { protoVar } from '../colors'
import { useReduced } from '../motion'

const MAX_ARROWS = 250
const MAX_LANES = 6

interface Props {
  /** Explicit frames to draw (compact / embedded use). Defaults to the scope picker. */
  frames?: number[]
  compact?: boolean
  autoPlay?: boolean
  highlight?: number[]
  /** Change to restart playback. */
  playToken?: number
  /** Arrow index playback (re)starts from; earlier arrows are drawn immediately. */
  startAt?: number
}

function laneKey(p: PacketSummary, side: 'src' | 'dst'): string {
  if (p.facts.ip) return side === 'src' ? p.facts.ip.src : p.facts.ip.dst
  return side === 'src' ? p.src : p.dst
}

function arrowLabel(kb: Kb, p: PacketSummary): string {
  const kind = kb.classify(p)
  const label = kb.label(p, kind)
  if (kind === 'other' || kind === 'tcp-data' || kind === 'tcp-ack') {
    const t = p.facts.tcp
    if (t) return t.payloadLen ? `${p.protocol === 'TCP' ? 'data' : p.protocol} (${t.payloadLen} B)` : `[${t.flagStr}]`
    return p.protocol
  }
  return label
}

export function FlowView(props: Props) {
  const index = useCapture((s) => s.index)!
  const flowConv = useCapture((s) => s.flowConv)
  const selected = useCapture((s) => s.selected)
  const sweep = useCapture((s) => s.sweep)
  const [scope, setScope] = useState<'conv' | 'all'>('conv')
  const kb = useMemo(() => new Kb(index), [index])

  const frames = useMemo(() => {
    if (props.frames) return props.frames.slice(0, MAX_ARROWS)
    if (scope === 'all' || flowConv === null) return index.packets.slice(0, MAX_ARROWS).map((p) => p.no)
    return index.conversations[flowConv]?.packets.slice(0, MAX_ARROWS) ?? []
  }, [props.frames, scope, flowConv, index])

  return (
    <div className="flex h-full min-h-0 flex-col">
      {!props.compact && (
        <div className="flex flex-wrap items-center gap-2 border-b border-line bg-panel2 px-2 py-1 text-[11px]">
          <label className="flex items-center gap-2">
            <span className="text-[10.5px] uppercase tracking-[0.12em] text-faint">show</span>
            <select
              className="max-w-[22rem] border border-line-strong bg-panel px-1 py-0.5 text-[11px] text-fg"
              value={scope === 'all' ? 'all' : String(flowConv ?? 'all')}
              onChange={(e) => {
                if (e.target.value === 'all') setScope('all')
                else {
                  setScope('conv')
                  useCapture.getState().setFlowConv(Number(e.target.value))
                }
              }}
              aria-label="Conversation to draw"
            >
              <option value="all">whole capture (first {Math.min(MAX_ARROWS, index.packets.length)} packets)</option>
              {index.conversations.slice(0, 300).map((c) => (
                <option key={c.id} value={c.id}>
                  #{c.id} {c.app} {c.a.addr}
                  {c.a.port !== undefined ? `:${c.a.port}` : ''} ⇄ {c.b.addr}
                  {c.b.port !== undefined ? `:${c.b.port}` : ''} ({c.packets.length})
                </option>
              ))}
            </select>
          </label>
          <span className="ml-auto text-faint">click an arrow to inspect that packet</span>
        </div>
      )}
      <Ladder
        key={frames.join(',')}
        index={index}
        kb={kb}
        frames={frames}
        compact={!!props.compact}
        autoPlay={props.autoPlay ?? !props.compact}
        highlight={props.highlight ?? []}
        selected={selected}
        playToken={props.playToken ?? 0}
        startAt={props.startAt ?? 0}
        focus={!props.compact && sweep ? { packet: sweep.packet, token: sweep.token } : null}
      />
    </div>
  )
}

interface LadderProps {
  index: CaptureIndex
  kb: Kb
  frames: number[]
  compact: boolean
  autoPlay: boolean
  highlight: number[]
  selected: number | null
  playToken: number
  startAt: number
  focus: { packet: number; token: number } | null
}

function Ladder({ index, kb, frames, compact, autoPlay, highlight, selected, playToken, startAt, focus }: LadderProps) {
  const reduced = useReduced()
  const packets = frames.map((n) => index.packets[n - 1]).filter(Boolean)
  const n = packets.length
  const [head, setHead] = useState(autoPlay ? startAt : n)
  const [playing, setPlaying] = useState(autoPlay)
  const [speed, setSpeed] = useState(1)
  const stopAt = useRef<number | null>(null)

  // Lanes in order of first appearance; overflow collapses into "other".
  const lanes = useMemo(() => {
    const order: string[] = []
    for (const p of packets) for (const k of [laneKey(p, 'src'), laneKey(p, 'dst')]) if (!order.includes(k)) order.push(k)
    if (order.length <= MAX_LANES) return order
    return [...order.slice(0, MAX_LANES - 1), '(other)']
  }, [packets])
  const laneOf = useCallback((k: string) => (lanes.includes(k) ? lanes.indexOf(k) : lanes.length - 1), [lanes])

  // Compact views render near 1:1 in a ~360px panel, so text stays readable.
  const W = compact ? 380 : 760
  const rowH = compact ? 30 : 36
  const top = 44
  const left = compact ? 12 : 78
  const right = compact ? 12 : 24
  const laneW = compact ? 104 : 128
  const inset = compact ? 52 : 40
  const laneX = (i: number) => (lanes.length === 1 ? (left + W - right) / 2 : left + inset + (i * (W - left - right - inset * 2)) / (lanes.length - 1))
  const H = top + n * rowH + 16

  // Restart playback when asked.
  useEffect(() => {
    if (!playToken) return
    setHead(startAt)
    setPlaying(true)
    stopAt.current = null
  }, [playToken, startAt])

  // "Show me": jump to just before the packet and play that single arrow.
  useEffect(() => {
    if (!focus) return
    const i = frames.indexOf(focus.packet)
    if (i < 0) return
    setHead(i)
    stopAt.current = i + 1
    setPlaying(true)
  }, [focus, frames])

  // Playback loop. Reduced motion: discrete steps, no travelling pill.
  useEffect(() => {
    if (!playing) return
    if (reduced) {
      const id = setInterval(() => {
        setHead((h) => {
          const target = stopAt.current ?? n
          const next = Math.min(target, Math.floor(h) + 1)
          if (next >= target) setPlaying(false)
          return next
        })
      }, 600 / speed)
      return () => clearInterval(id)
    }
    let raf = 0
    let last = performance.now()
    const tick = (t: number) => {
      const dt = (t - last) / 1000
      last = t
      let done = false
      setHead((h) => {
        const target = stopAt.current ?? n
        const next = Math.min(target, h + dt * 1.6 * speed)
        if (next >= target) done = true
        return next
      })
      if (done) {
        setPlaying(false)
        stopAt.current = null
      } else raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [playing, speed, n, reduced])

  // TCP connections drawn in this view: handshake zipper + lifetime band.
  const conns = useMemo(() => {
    const out: { id: number; syn: number; synAck: number; ack: number; end: number; closedBy?: 'fin' | 'rst'; a: number; b: number }[] = []
    const seen = new Set<number>()
    for (const p of packets) {
      if (p.streamId < 0 || seen.has(p.streamId)) continue
      seen.add(p.streamId)
      const c = index.conversations[p.streamId]
      const hs = c.handshake
      if (!hs?.syn || !hs.synAck || !hs.ack) continue
      const syn = frames.indexOf(hs.syn)
      const synAck = frames.indexOf(hs.synAck)
      const ack = frames.indexOf(hs.ack)
      if (syn < 0 || synAck < 0 || ack < 0) continue
      const inView = c.packets.map((x) => frames.indexOf(x)).filter((i) => i >= 0)
      const closeIdx = c.packets
        .map((x) => frames.indexOf(x))
        .filter((i) => i >= 0 && (packets[i].facts.tcp?.flags.fin || packets[i].facts.tcp?.flags.rst))
      const end = c.closedBy && closeIdx.length ? (c.closedBy === 'rst' ? closeIdx.find((i) => packets[i].facts.tcp!.flags.rst)! : closeIdx[closeIdx.length - 1]) : Math.max(...inView)
      out.push({ id: c.id, syn, synAck, ack, end, closedBy: c.closedBy, a: laneOf(c.a.addr), b: laneOf(c.b.addr) })
    }
    return out.slice(0, 12)
  }, [packets, frames, index, laneOf])

  const rowY = (i: number) => top + i * rowH + rowH / 2
  const active = Math.floor(head)
  const frac = head - active

  if (!n) return <p className="p-3 text-[12px] text-faint">-- no packets to draw · select a packet or pick a conversation --</p>

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className={`scroll-thin min-h-0 flex-1 overflow-auto ${compact ? 'max-h-64' : ''}`}>
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ minWidth: compact ? 300 : 560 }} role="img" aria-label={`Flow diagram of ${n} packets between ${lanes.join(', ')}`}>
          <defs>
            {/* userSpaceOnUse: a horizontal line has a zero-height bbox, which would clip a bbox-relative filter to nothing. */}
            <filter id="glow" filterUnits="userSpaceOnUse" x={0} y={0} width={W} height={H}>
              <feGaussianBlur stdDeviation="3" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {/* Connection lifetime bands */}
          {conns.map((c) => {
            const x1 = Math.min(laneX(c.a), laneX(c.b))
            const x2 = Math.max(laneX(c.a), laneX(c.b))
            const y1 = rowY(c.ack)
            const y2 = rowY(c.end)
            const established = head > c.ack + 0.99
            const closed = head > c.end + 0.99
            return (
              <g key={`band-${c.id}`} aria-hidden>
                <motion.rect
                  x={x1}
                  width={x2 - x1}
                  y={y1}
                  height={Math.max(0, y2 - y1)}
                  fill="var(--accent)"
                  initial={false}
                  animate={{ opacity: !established ? 0 : closed ? (c.closedBy === 'rst' ? 0 : 0.03) : 0.08 }}
                  transition={{ duration: closed && c.closedBy === 'rst' ? 0.08 : 0.6 }}
                />
                {closed && c.closedBy === 'rst' && (
                  <motion.path
                    d={`M${x1} ${y2} l12 -6 l10 10 l12 -8 l10 8 l12 -6 L${x2} ${y2}`}
                    stroke="var(--bad)"
                    strokeWidth={2}
                    fill="none"
                    initial={{ opacity: 0, x: -4 }}
                    animate={{ opacity: [0, 1, 0.8], x: [-4, 4, 0] }}
                    transition={{ duration: 0.35 }}
                  />
                )}
              </g>
            )
          })}
          {/* Lanes */}
          {lanes.map((l, i) => (
            <g key={l}>
              <line x1={laneX(i)} x2={laneX(i)} y1={top - 6} y2={H - 8} stroke="var(--line)" strokeWidth={2} strokeDasharray="4 5" />
              <rect x={laneX(i) - laneW / 2} y={6} width={laneW} height={24} rx={0} fill="var(--panel-3)" stroke="var(--line)" />
              <text x={laneX(i)} y={22} textAnchor="middle" fontSize={compact ? 10 : 11} fontFamily="var(--font-mono)" fill="var(--fg)">
                {l.length > (compact ? 15 : 17) ? l.slice(0, compact ? 14 : 16) + '…' : l}
              </text>
            </g>
          ))}
          {/* Arrows */}
          {packets.map((p, i) => (
            <Arrow
              key={p.no}
              p={p}
              label={arrowLabel(kb, p)}
              y={rowY(i)}
              x1={laneX(laneOf(laneKey(p, 'src')))}
              x2={laneX(laneOf(laneKey(p, 'dst')))}
              state={i < active ? 'done' : i === active ? 'active' : 'hidden'}
              progress={i === active ? frac : 1}
              hl={highlight.includes(p.no) || selected === p.no}
              compact={compact}
              showTime={!compact}
              reduced={reduced}
            />
          ))}
          {/* Handshake zipper */}
          {conns.map((c) => {
            const locked = head > c.ack + 0.99
            if (!locked) return null
            const xz = Math.max(laneX(c.a), laneX(c.b)) + 14
            const y1 = rowY(c.syn)
            const y2 = rowY(c.ack)
            const teeth = []
            for (let y = y1; y <= y2; y += 7) teeth.push(`M${xz} ${y} l6 3.5 l-6 3.5`)
            return (
              <g key={`zip-${c.id}`}>
                <motion.path
                  d={`M${xz} ${y1} V${y2} ${teeth.join(' ')}`}
                  stroke="var(--good)"
                  strokeWidth={1.6}
                  fill="none"
                  initial={{ pathLength: reduced ? 1 : 0, opacity: 0.4 }}
                  animate={{ pathLength: 1, opacity: 1 }}
                  transition={{ duration: 0.6 }}
                />
                <motion.g initial={{ scale: reduced ? 1 : 0, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ delay: reduced ? 0 : 0.45, type: 'spring', stiffness: 500, damping: 18 }} style={{ originX: `${xz + 14}px`, originY: `${(y1 + y2) / 2}px` }}>
                  <foreignObject x={xz + 6} y={(y1 + y2) / 2 - 9} width={130} height={18}>
                    <span className="flex items-center gap-1 font-mono text-[10px] font-semibold text-good">[locked] established</span>
                  </foreignObject>
                </motion.g>
              </g>
            )
          })}
        </svg>
      </div>
      <Controls
        head={head}
        n={n}
        playing={playing}
        speed={speed}
        compact={compact}
        onPlay={() => {
          if (head >= n) setHead(0)
          stopAt.current = null
          setPlaying((p) => !p)
        }}
        onSeek={(h) => {
          setPlaying(false)
          setHead(h)
        }}
        onStep={(d) => {
          setPlaying(false)
          setHead((h) => Math.max(0, Math.min(n, Math.round(h) + d)))
        }}
        onRestart={() => {
          setHead(0)
          stopAt.current = null
          setPlaying(true)
        }}
        onSpeed={setSpeed}
      />
    </div>
  )
}

interface ArrowProps {
  p: PacketSummary
  label: string
  y: number
  x1: number
  x2: number
  state: 'done' | 'active' | 'hidden'
  progress: number
  hl: boolean
  compact: boolean
  showTime: boolean
  reduced: boolean
}

const Arrow = memo(function Arrow({ p, label, y, x1, x2, state, progress, hl, compact, showTime, reduced }: ArrowProps) {
  if (state === 'hidden') return null
  const color = protoVar(p.protocol)
  const self = x1 === x2
  const dir = x2 >= x1 ? 1 : -1
  const len = Math.abs(x2 - x1)
  const shown = state === 'done' || reduced ? 1 : progress
  const tipX = x1 + dir * len * shown
  const rst = p.facts.tcp?.flags.rst
  return (
    <g
      className="cursor-pointer"
      onClick={() => useCapture.getState().select(p.no)}
      role="button"
      aria-label={`Packet ${p.no}: ${p.src} to ${p.dst}, ${label}`}
    >
      <rect x={Math.min(x1, x2) - 10} y={y - 14} width={Math.max(len, 20) + 20} height={24} fill="transparent" />
      {showTime && (
        <text x={6} y={y + 4} fontSize={10} fontFamily="var(--font-mono)" fill="var(--faint)">
          {p.relTime.toFixed(3)}
        </text>
      )}
      {self ? (
        <path d={`M${x1} ${y - 6} h26 v12 h-26`} stroke={color} strokeWidth={1.8} fill="none" markerEnd="" />
      ) : (
        <>
          {hl && <line x1={x1} y1={y} x2={tipX} y2={y} stroke={color} strokeWidth={9} opacity={0.22} />}
          <line
            x1={x1}
            y1={y}
            x2={tipX}
            y2={y}
            stroke={color}
            strokeWidth={hl ? 3 : 1.8}
            strokeDasharray={rst ? '5 3' : undefined}
            opacity={state === 'done' ? 0.9 : 1}
          />
          {shown >= 0.98 && <path d={`M${x2} ${y} l${-dir * 8} -4.5 v9 z`} fill={color} />}
        </>
      )}
      {state === 'active' && !reduced && !self && (
        <g transform={`translate(${tipX} ${y})`} filter="url(#glow)">
          <rect x={-13} y={-5} width={26} height={10} rx={0} fill={color} />
        </g>
      )}
      <text
        x={self ? x1 + 32 : (x1 + x2) / 2}
        y={y - 6}
        textAnchor={self ? 'start' : 'middle'}
        fontSize={compact ? 10 : 11}
        fontFamily="var(--font-mono)"
        fill={hl ? 'var(--fg)' : 'var(--muted)'}
        fontWeight={hl ? 700 : 400}
        opacity={shown > 0.3 ? 1 : 0}
      >
        {label.length > (compact ? 26 : 34) ? label.slice(0, compact ? 25 : 33) + '…' : label}
      </text>
      {hl && (
        <text x={Math.min(x1, x2) - 12} y={y + 4} textAnchor="end" fontSize={10} fill="var(--accent)" fontFamily="var(--font-mono)">
          #{p.no}
        </text>
      )}
    </g>
  )
})

function Controls(p: {
  head: number
  n: number
  playing: boolean
  speed: number
  compact: boolean
  onPlay: () => void
  onSeek: (h: number) => void
  onStep: (d: number) => void
  onRestart: () => void
  onSpeed: (s: number) => void
}) {
  const btn = 'h-6 min-w-7 border border-line-strong px-1.5 text-[11px] leading-none text-muted hover:border-accent hover:text-accent'
  return (
    <div className="flex shrink-0 items-center gap-1.5 border-t border-line bg-panel2 px-2 py-1 font-mono">
      <button className={btn} onClick={() => p.onSeek(0)} aria-label="Flow: jump to start">
        |&lt;
      </button>
      <button className={btn} onClick={() => p.onStep(-1)} aria-label="Flow: step back">
        &lt;
      </button>
      <button className={`${btn} ${p.playing ? '' : 'text-accent'}`} onClick={p.onPlay} aria-label={p.playing ? 'Pause' : 'Play'}>
        {p.playing ? '❚❚' : '▶'}
      </button>
      <button className={btn} onClick={() => p.onStep(1)} aria-label="Flow: step forward">
        &gt;
      </button>
      {!p.compact && (
        <button className={btn} onClick={p.onRestart} aria-label="Replay from start">
          ↺
        </button>
      )}
      <input
        type="range"
        min={0}
        max={p.n}
        step={0.01}
        value={p.head}
        onChange={(e) => p.onSeek(Number(e.target.value))}
        className="min-w-0 flex-1 accent-[var(--accent)]"
        aria-label="Timeline"
        aria-valuetext={`${Math.floor(p.head)} of ${p.n} packets`}
      />
      <span className="w-14 text-right font-mono text-[11px] tabular-nums text-muted">
        {Math.min(p.n, Math.ceil(p.head))}/{p.n}
      </span>
      <select
        value={p.speed}
        onChange={(e) => p.onSpeed(Number(e.target.value))}
        className="border border-line-strong bg-panel px-1 py-0.5 text-[11px] text-fg"
        aria-label="Playback speed"
      >
        {[0.5, 1, 2, 4].map((s) => (
          <option key={s} value={s}>
            {s}×
          </option>
        ))}
      </select>
    </div>
  )
}
