// One question in the console: case header, prompt, the mode-specific input, hint, then the graded log.

import { motion, Reorder } from 'framer-motion'
import { useEffect, useMemo, useRef, useState } from 'react'
import { compileFilter, FilterError } from '../../core/filter/filter'
import { seeded } from '../../game/engine'
import { maskInfo } from '../../game/knowledge'
import { shuffle } from '../../game/options'
import {
  CONCEPT_LABEL,
  MODE_INFO,
  type ChoiceQuestion,
  type FieldQuestion,
  type FilterQuestion,
  type OrderQuestion,
  type PickQuestion,
  type TextQuestion,
} from '../../game/types'
import { useCapture } from '../../store/capture'
import { BLITZ_SECONDS, useGame } from '../../store/game'
import { useProgress } from '../../store/progress'
import { useTicker } from '../hooks'
import { consoleHotkeyAllowed } from '../hotkeys'
import { Btn, Kbd, Meter } from '../term'
import { TIER_TONE } from '../tones'
import { ExplanationCard } from './ExplanationCard'
import { XpFloat } from './XpFloat'
import { SessionNav } from './SessionNav'

const pad = (n: number) => String(n).padStart(2, '0')
const clock = (s: number) => `${pad(Math.floor(s / 60))}:${pad(s % 60)}`

export function QuestionView() {
  const { deck, idx, phase, hintUsed, questionStart, blitzEndsAt, playMode, feedback } = useGame()
  const q = deck[idx]
  const showTimer = useProgress((s) => s.settings.showTimer)
  // Blitz keeps its clock running through feedback.
  const now = useTicker(phase === 'question' || (!!blitzEndsAt && phase === 'feedback'), 250)

  useEffect(() => {
    if (blitzEndsAt && now >= blitzEndsAt && (phase === 'question' || phase === 'feedback')) useGame.getState().finish()
  }, [now, blitzEndsAt, phase])

  // Keyboard: 1–4 answer choices, n = next, ? = hint. Text inputs keep their own keys.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!consoleHotkeyAllowed(e)) return
      const g = useGame.getState()
      const cur = g.deck[g.idx]
      if (g.phase === 'feedback' && (e.key === 'n' || e.key === 'N')) {
        e.preventDefault()
        g.next()
      } else if (g.phase === 'question' && e.key === '?') g.useHint()
      else if (g.phase === 'question' && cur?.kind === 'choice' && /^[1-4]$/.test(e.key)) g.submit({ kind: 'choice', index: Number(e.key) - 1 })
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  if (!q) return null
  // The ticker stops on answer, so the clock freezes there; a new question reads 0 until the first tick.
  const elapsed = Math.max(0, Math.floor((now - questionStart) / 1000))
  const blitzLeft = blitzEndsAt ? Math.max(0, (blitzEndsAt - now) / 1000) : null
  const info = MODE_INFO[q.mode]

  return (
    <div className="flex min-h-0 flex-1 flex-col text-[12.5px]">
      <SessionNav />
      <div className="shrink-0 border-b border-line px-3 py-1.5 text-[11px]">
        <div className="flex items-center gap-2 uppercase tracking-[0.1em]">
          <span className="text-fg">
            case {pad(idx + 1)}
            {playMode !== 'blitz' && <span className="text-faint">/{pad(deck.length)}</span>}
          </span>
          <span className="text-faint">·</span>
          <span className="text-accent">
            {info.letter} {info.name.toLowerCase()}
          </span>
          <span className="ml-auto flex items-center gap-2 normal-case tracking-normal tabular-nums">
            {blitzLeft !== null ? (
              <span className={blitzLeft < 10 ? 'text-bad' : 'text-warn'}>{blitzLeft.toFixed(0)}s left</span>
            ) : (
              showTimer && <span className="text-muted">{clock(elapsed)}</span>
            )}
            <button onClick={() => useGame.getState().finish()} className="text-faint underline-offset-2 hover:text-fg hover:underline" title="End the session and see the report">
              end
            </button>
          </span>
        </div>
        <div className="mt-0.5 flex items-center gap-2 text-faint">
          <span className={TIER_TONE[q.tier]}>{q.tier.toLowerCase()}</span>
          <span>·</span>
          <span>{CONCEPT_LABEL[q.concept].toLowerCase()}</span>
          <span className="ml-auto">
            {blitzLeft !== null ? (
              <Meter value={blitzLeft / BLITZ_SECONDS} width={14} label="Time left" />
            ) : (
              <Meter value={(idx + (phase === 'feedback' ? 1 : 0)) / deck.length} width={14} label="Session progress" />
            )}
          </span>
        </div>
      </div>

      <div className="scroll-thin relative min-h-0 flex-1 overflow-y-auto px-3 py-3">
        <motion.div key={q.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.12 }}>
          <h2 id="q-prompt" className="text-[13.5px] leading-snug text-fg">
            <span className="mr-1 text-accent">&gt;</span>
            {q.prompt}
          </h2>
          <div className="mt-3">
            {q.kind === 'pick' && <PickBody q={q} />}
            {q.kind === 'choice' && <ChoiceBody q={q} />}
            {q.kind === 'field' && <FieldBody q={q} />}
            {q.kind === 'order' && <OrderBody q={q} />}
            {q.kind === 'text' && <TextBody key={q.id} q={q} />}
            {q.kind === 'filter' && <FilterBody key={q.id} q={q} />}
          </div>
          {phase === 'question' && (
            <div className="mt-3 text-[12px]">
              {hintUsed ? (
                <p className="border-l-2 border-warn pl-2">
                  <span className="text-warn">hint</span> <span className="text-muted">{q.hint}</span>
                </p>
              ) : (
                <button onClick={() => useGame.getState().useHint()} className="text-faint hover:text-warn">
                  <Kbd>?</Kbd> hint <span className="text-faint">(−50% xp)</span>
                </button>
              )}
            </div>
          )}
          {phase === 'feedback' && feedback && <ExplanationCard q={q} feedback={feedback} />}
        </motion.div>
      </div>

      {phase === 'feedback' && (
        <div className="relative shrink-0 border-t border-line p-2">
          {/* Rises out of the empty right end of the button, clear of the prompt and explanation text. */}
          <XpFloat />
          <Btn tone="primary" block autoFocus hotkey="n" onClick={() => useGame.getState().next()}>
            {idx + 1 >= deck.length ? 'session report' : 'next case'}
          </Btn>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------- A · pick

function PickBody({ q }: { q: PickQuestion }) {
  const selected = useCapture((s) => s.selected)
  const multi = useCapture((s) => s.multi)
  const index = useCapture((s) => s.index)!
  const reveal = useCapture((s) => s.revealSecrets)
  const phase = useGame((s) => s.phase)
  const p = selected ? index.packets[selected - 1] : null
  if (phase !== 'question') return null
  return (
    <div className="border border-line p-2 text-[12px]">
      <p className="text-faint">
        {q.multi ? 'click every matching row in the packet list (click again to drop it), then submit' : 'click a row in the packet list, then submit — or double-click / ↵ in the list'}
      </p>
      <p className="mt-1.5 truncate">
        <span className="text-faint">sel </span>
        {q.multi ? (
          multi.length ? (
            [...multi]
              .sort((a, b) => a - b)
              .map((n) => (
                <button key={n} onClick={() => useCapture.getState().toggleMulti(n)} className="mr-2 text-accent hover:line-through" aria-label={`Remove packet ${n}`}>
                  #{n}
                </button>
              ))
          ) : (
            <span className="text-faint">none</span>
          )
        ) : p ? (
          <span>
            <span className="text-accent">#{p.no}</span> {p.protocol} {reveal ? p.info : maskInfo(p)}
          </span>
        ) : (
          <span className="text-faint">none</span>
        )}
      </p>
      <div className="mt-2">
        <Btn
          tone="primary"
          block
          hotkey="↵"
          disabled={q.multi ? multi.length === 0 : !selected}
          onClick={() => useGame.getState().submit({ kind: 'pick', packets: q.multi ? multi : [selected!] })}
        >
          {q.multi ? `submit ${multi.length} frame${multi.length === 1 ? '' : 's'}` : selected ? `submit #${selected}` : 'select a frame'}
        </Btn>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- B, C, F · choice

export function ChoiceBody({ q, chosen, onChoose, locked }: { q: ChoiceQuestion; chosen?: number | null; onChoose?: (i: number) => void; locked?: boolean }) {
  const phase = useGame((s) => s.phase)
  const feedback = useGame((s) => s.feedback)
  const answered = onChoose ? chosen !== null && chosen !== undefined : phase === 'feedback'
  const pick = onChoose ? chosen : feedback?.answer.kind === 'choice' ? feedback.answer.index : null
  return (
    <div role="radiogroup" aria-labelledby="q-prompt" className="border-t border-line">
      {q.options.map((o, i) => {
        const isCorrect = i === q.correct
        const isPicked = pick === i
        const state = !answered ? 'idle' : isCorrect ? 'correct' : isPicked ? 'wrong' : 'dim'
        return (
          <button
            key={i}
            role="radio"
            aria-checked={isPicked}
            disabled={answered || locked}
            onClick={() => (onChoose ? onChoose(i) : useGame.getState().submit({ kind: 'choice', index: i }))}
            className={`grid w-full grid-cols-[2rem_1fr_1rem] items-baseline gap-1 border-b border-line px-1 py-1.5 text-left ${
              state === 'correct'
                ? 'bg-good/15 text-fg'
                : state === 'wrong'
                  ? 'bg-bad/15 text-fg'
                  : state === 'dim'
                    ? 'text-faint'
                    : 'hover:bg-accent hover:text-accent-ink'
            } ${state === 'wrong' ? 'row-shake' : ''}`}
            style={state === 'wrong' ? ({ ['--pulse' as string]: 'var(--bad)' } as React.CSSProperties) : undefined}
          >
            <span className="tabular-nums opacity-70">[{i + 1}]</span>
            <span>{o}</span>
            <span aria-hidden className={state === 'correct' ? 'text-good' : state === 'wrong' ? 'text-bad' : ''}>
              {state === 'correct' ? '✓' : state === 'wrong' ? '✗' : ''}
            </span>
            {state === 'correct' && <span className="sr-only"> (correct answer)</span>}
            {state === 'wrong' && <span className="sr-only"> (your answer, incorrect)</span>}
          </button>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------- D · field hunt

function FieldBody({ q }: { q: FieldQuestion }) {
  const pick = useGame((s) => s.fieldPick)
  const phase = useGame((s) => s.phase)
  if (phase !== 'question') return null
  return (
    <div className="border border-line p-2 text-[12px]">
      <p className="text-faint">frame #{q.packet} is locked in the viewer. click the field in the details tree, or its bytes in the hex pane.</p>
      <p className="mt-1.5">
        <span className="text-faint">sel </span>
        {pick ? (
          <span>
            <span className="text-accent">{pick.key ?? pick.name}</span> <span className="text-faint">{pick.via === 'hex' ? `(byte ${pick.offset})` : '(tree)'}</span>
          </span>
        ) : (
          <span className="text-faint">none</span>
        )}
      </p>
      <div className="mt-2">
        <Btn tone="primary" block disabled={!pick} onClick={() => pick && useGame.getState().submit({ kind: 'field', key: pick.key, offset: pick.offset, via: pick.via })}>
          submit field
        </Btn>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- E · order

function OrderBody({ q }: { q: OrderQuestion }) {
  const phase = useGame((s) => s.phase)
  const feedback = useGame((s) => s.feedback)
  const initial = useMemo(() => {
    const rng = seeded(q.id.length * 7919 + q.cards.length)
    let s = shuffle(q.cards, rng)
    if (s.every((c, i) => c.id === q.cards[i].id)) s = [...s.slice(1), s[0]]
    return s
  }, [q])
  const [items, setItems] = useState(initial)
  const submitted = feedback?.answer.kind === 'order' ? feedback.answer.ids : null

  useEffect(() => {
    if (phase !== 'feedback') return
    const t = setTimeout(() => setItems(q.cards), 350)
    return () => clearTimeout(t)
  }, [phase, q.cards])

  const move = (i: number, d: number) => {
    const j = i + d
    if (j < 0 || j >= items.length) return
    const next = [...items]
    ;[next[i], next[j]] = [next[j], next[i]]
    setItems(next)
  }

  return (
    <div className="text-[12px]">
      <p className="mb-1.5 text-faint">{phase === 'question' ? 'drag rows (or use ↑ ↓) so the first frame on the wire is on top' : 'wire order:'}</p>
      <Reorder.Group axis="y" values={items} onReorder={setItems} className="border-t border-line" aria-label="Cards to order">
        {items.map((c, i) => {
          const wasAt = submitted ? submitted.indexOf(c.id) : -1
          const right = submitted ? wasAt === q.cards.findIndex((x) => x.id === c.id) : null
          return (
            <Reorder.Item
              key={c.id}
              value={c}
              dragListener={phase === 'question'}
              className={`grid select-none grid-cols-[1.6rem_1fr_auto] items-center gap-1 border-b border-line bg-panel px-1 py-1 ${
                right === null ? '' : right ? 'bg-good/10' : 'bg-bad/10'
              } ${phase === 'question' ? 'cursor-grab active:cursor-grabbing' : ''}`}
              whileDrag={{ boxShadow: 'var(--shadow)' }}
            >
              <span className="tabular-nums text-faint">{pad(i + 1)}</span>
              <span className="truncate">{c.label}</span>
              {right !== null ? (
                <span className={right ? 'text-good' : 'text-bad'} aria-label={right ? 'was in the right place' : 'was in the wrong place'}>
                  {right ? '✓' : `✗ was ${pad(wasAt + 1)}`}
                </span>
              ) : (
                <span className="flex gap-1 text-faint">
                  <button onClick={() => move(i, -1)} disabled={i === 0} className="px-1 hover:text-accent disabled:opacity-30" aria-label={`Move ${c.label} up`}>
                    ↑
                  </button>
                  <button onClick={() => move(i, 1)} disabled={i === items.length - 1} className="px-1 hover:text-accent disabled:opacity-30" aria-label={`Move ${c.label} down`}>
                    ↓
                  </button>
                </span>
              )}
            </Reorder.Item>
          )
        })}
      </Reorder.Group>
      {phase === 'question' && (
        <div className="mt-2">
          <Btn tone="primary" block onClick={() => useGame.getState().submit({ kind: 'order', ids: items.map((c) => c.id) })}>
            submit order
          </Btn>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------- H · type the answer

function PromptInput({
  label,
  value,
  onChange,
  onSubmit,
  placeholder,
  disabled,
  tone,
  describedBy,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  onSubmit: () => void
  placeholder: string
  disabled?: boolean
  tone?: 'good' | 'bad'
  describedBy?: string
}) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (!disabled) ref.current?.focus()
  }, [disabled])
  return (
    <label className={`flex items-center gap-2 border px-2 py-1.5 text-[13px] ${tone === 'good' ? 'border-good' : tone === 'bad' ? 'border-bad' : 'border-line-strong focus-within:border-accent'}`}>
      <span className="shrink-0 text-accent">{label}&gt;</span>
      <input
        ref={ref}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault()
            onSubmit()
          }
        }}
        placeholder={placeholder}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        autoCorrect="off"
        aria-labelledby="q-prompt"
        aria-describedby={describedBy}
        className="min-w-0 flex-1 bg-transparent caret-[var(--accent)] outline-none placeholder:text-faint disabled:text-muted"
      />
      {!disabled && <Kbd>↵</Kbd>}
    </label>
  )
}

function TextBody({ q }: { q: TextQuestion }) {
  const phase = useGame((s) => s.phase)
  const feedback = useGame((s) => s.feedback)
  const [v, setV] = useState('')
  const answered = phase === 'feedback'
  const typed = feedback?.answer.kind === 'text' ? feedback.answer.text : v
  const ok = (feedback?.grade.score ?? 0) >= 1
  return (
    <div className="text-[12px]">
      <PromptInput
        label="answer"
        value={answered ? typed : v}
        onChange={setV}
        onSubmit={() => v.trim() && useGame.getState().submit({ kind: 'text', text: v })}
        placeholder={q.placeholder}
        disabled={answered}
        tone={answered ? (ok ? 'good' : 'bad') : undefined}
      />
      {answered ? (
        <p className="mt-1.5">
          <span className="text-faint">expected </span>
          <span className="text-good">{q.accept[0]}</span>
          {q.accept.length > 1 && <span className="text-faint"> (also accepted: {q.accept.slice(1, 4).join(', ')})</span>}
        </p>
      ) : (
        <p className="mt-1.5 text-faint">
          {q.match === 'number' ? 'numbers only' : q.match === 'ip' ? 'dotted IPv4' : q.match === 'mac' ? 'any separator' : 'case-insensitive, small typos forgiven'}
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------- I · filter forge

function FilterBody({ q }: { q: FilterQuestion }) {
  const index = useCapture((s) => s.index)!
  const phase = useGame((s) => s.phase)
  const feedback = useGame((s) => s.feedback)
  const [v, setV] = useState('')
  const answered = phase === 'feedback'
  const text = answered && feedback?.answer.kind === 'filter' ? feedback.answer.text : v

  // Dry-run on every keystroke: compile errors and match counts appear as you type.
  const dry = useMemo(() => {
    if (!text.trim()) return null
    try {
      const pred = compileFilter(text)
      const matched = index.packets.filter(pred).map((p) => p.no)
      const want = new Set(q.target)
      const hit = matched.filter((n) => want.has(n)).length
      return { ok: true as const, matched, hit, extra: matched.length - hit, missing: q.target.length - hit }
    } catch (e) {
      return { ok: false as const, error: e instanceof FilterError ? e.message : 'invalid filter' }
    }
  }, [text, index, q.target])

  const submit = () => {
    if (!dry?.ok) return
    useGame.getState().submit({ kind: 'filter', text: v })
  }
  const preview = (f: string) => {
    const cap = useCapture.getState()
    cap.setFilter(f)
    cap.setTab('packets')
  }

  return (
    <div className="text-[12px]">
      <p className="mb-1.5 text-faint">
        target: <span className="text-fg tabular-nums">{q.target.length}</span> of {index.packets.length} frames · graded on exactly which frames match
      </p>
      <PromptInput
        label="filter"
        value={text}
        onChange={setV}
        onSubmit={submit}
        placeholder="e.g. tcp.port == 80"
        disabled={answered}
        tone={answered ? ((feedback?.grade.score ?? 0) >= 1 ? 'good' : 'bad') : dry && !dry.ok ? 'bad' : undefined}
        describedBy="forge-dry"
      />
      <p id="forge-dry" className="mt-1.5 min-h-[1.2em] tabular-nums" aria-live="polite">
        {!dry ? (
          <span className="text-faint">type a display filter; it runs against the capture as you type</span>
        ) : !dry.ok ? (
          <span className="text-bad">error: {dry.error}</span>
        ) : (
          <>
            <span className="text-faint">matches</span> {dry.matched.length} <span className="text-faint">·</span> <span className="text-good">{dry.hit} right</span>{' '}
            <span className="text-faint">·</span> <span className={dry.extra ? 'text-bad' : 'text-faint'}>{dry.extra} extra</span> <span className="text-faint">·</span>{' '}
            <span className={dry.missing ? 'text-warn' : 'text-faint'}>{dry.missing} missing</span>
          </>
        )}
      </p>
      {!answered ? (
        <div className="mt-2 flex gap-2">
          <Btn tone="primary" className="flex-1" disabled={!dry?.ok} onClick={submit}>
            submit filter
          </Btn>
          <Btn disabled={!dry?.ok} onClick={() => preview(v)} title="Apply to the packet list without submitting">
            preview
          </Btn>
        </div>
      ) : (
        <p className="mt-1.5">
          <span className="text-faint">reference </span>
          <button className="text-good underline-offset-2 hover:underline" onClick={() => preview(q.reference)} title="Apply the reference filter to the packet list">
            {q.reference}
          </button>
        </p>
      )}
      <details className="mt-3 text-[11.5px] text-faint">
        <summary className="cursor-pointer hover:text-fg">field reference</summary>
        <p className="mt-1 leading-relaxed">
          protocols: eth arp ip ipv6 icmp tcp udp dns http tls dhcp ftp telnet ssh ntp snmp · ip.addr ip.src ip.dst ip.ttl · tcp.port tcp.srcport tcp.dstport tcp.flags.syn/ack/fin/reset/push tcp.len ·
          udp.port · dns.qry.name dns.qry.type dns.flags.response dns.flags.rcode dns.a · http.request.method http.request.uri http.response.code http.host · tls.handshake.type
          tls.handshake.extensions_server_name · arp.opcode · icmp.type · dhcp.option.dhcp · ftp.request.command · frame.len frame.number · ops == != &gt; &lt; &gt;= &lt;= contains · && || ! ()
        </p>
      </details>
    </div>
  )
}
