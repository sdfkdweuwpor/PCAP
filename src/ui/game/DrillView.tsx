// Mode J: keystroke drill. A stream of terms, filter fields and values from this capture; the clock starts
// on the first keystroke. Space (or Enter) commits a word. Per-character feedback, live WPM and accuracy.

import { useEffect, useMemo, useRef, useState } from 'react'
import { buildDrillWords, drillStats, type DrillWord } from '../../game/drill'
import { seeded } from '../../game/engine'
import { useCapture } from '../../store/capture'
import { useGame } from '../../store/game'
import { useProgress } from '../../store/progress'
import { useTicker } from '../hooks'
import { Btn, Kbd, Meter } from '../term'

const SECONDS = 60
const WINDOW = 18

interface Done {
  word: DrillWord
  typed: string
}

export function DrillView() {
  const index = useCapture((s) => s.index)!
  const [seed, setSeed] = useState(() => Date.now() % 100000)
  const words = useMemo(() => buildDrillWords(index, seeded(seed), 200), [index, seed])
  const [done, setDone] = useState<Done[]>([])
  const [typed, setTyped] = useState('')
  const [startedAt, setStartedAt] = useState<number | null>(null)
  const [result, setResult] = useState<{ wpm: number; accuracy: number; xp: number; best: boolean } | null>(null)
  const input = useRef<HTMLInputElement>(null)
  const now = useTicker(startedAt !== null && !result, 200)
  const bestWpm = useProgress((s) => s.drill.bestWpm)

  // The ticker's last value can predate the first keystroke, so clamp at zero.
  const elapsed = startedAt ? Math.min(SECONDS, Math.max(0, (now - startedAt) / 1000)) : 0
  const left = SECONDS - elapsed
  const timeUp = startedAt !== null && left <= 0
  const current = words[done.length]

  // Count characters: committed words score position-by-position; the word in progress counts what's typed so far.
  const tally = (list: Done[], partial: string, cur?: DrillWord) => {
    let correct = 0
    let total = 0
    for (const d of list) {
      const n = Math.max(d.typed.length, d.word.text.length)
      total += n + 1
      for (let i = 0; i < n; i++) if (d.typed[i] === d.word.text[i]) correct++
      if (d.typed === d.word.text) correct++ // the separating space
    }
    if (cur)
      for (let i = 0; i < partial.length; i++) {
        total++
        if (partial[i] === cur.text[i]) correct++
      }
    return { correct, total }
  }
  const live = tally(done, typed, current)
  const stats = drillStats(live.correct, live.total, done.length, Math.max(elapsed, 1))

  useEffect(() => {
    if (timeUp && !result) {
      const final = tally(done, typed, current)
      const s = drillStats(final.correct, final.total, done.length, SECONDS)
      const xp = useGame.getState().finishDrill(s.wpm, s.accuracy)
      setResult({ wpm: s.wpm, accuracy: s.accuracy, xp, best: s.wpm > bestWpm })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once when the clock hits zero
  }, [timeUp, result])

  useEffect(() => {
    if (!result) input.current?.focus()
  }, [result])

  const restart = () => {
    setSeed((s) => s + 1)
    setDone([])
    setTyped('')
    setStartedAt(null)
    setResult(null)
  }

  const commit = () => {
    if (!current || !typed) return
    setDone((d) => [...d, { word: current, typed }])
    setTyped('')
  }

  const start = Math.max(0, done.length - 3)
  const view = words.slice(start, start + WINDOW)

  return (
    <div className="flex min-h-0 flex-1 flex-col text-[12.5px]">
      <div className="shrink-0 border-b border-line px-3 py-1.5 text-[11px]">
        <div className="flex items-center gap-2 uppercase tracking-[0.1em]">
          <span className="text-accent">j keystroke drill</span>
          <span className="ml-auto normal-case tracking-normal tabular-nums text-muted">best {bestWpm}wpm</span>
        </div>
        <div className="mt-0.5 flex items-center gap-3 tabular-nums">
          <Meter value={left / SECONDS} width={20} label="Time left" />
          <span className={left < 10 && startedAt ? 'text-bad' : 'text-fg'}>{Math.ceil(left)}s</span>
          <span>
            <span className="text-faint">wpm</span> <span className="text-fg">{startedAt ? stats.wpm : 0}</span>
          </span>
          <span>
            <span className="text-faint">acc</span> <span className="text-fg">{startedAt && live.total ? Math.round(stats.accuracy * 100) : 100}%</span>
          </span>
        </div>
      </div>

      {!result ? (
        <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-3 py-3" onClick={() => input.current?.focus()}>
          <p className="mb-2 text-faint">{startedAt ? 'type each token, space to commit' : 'start typing to begin the 60s clock · tokens come from this capture'}</p>
          <p className="flex flex-wrap gap-x-3 leading-[2] text-[14px]" aria-hidden>
            {view.map((w, k) => {
              const i = start + k
              const d = done[i]
              if (d) {
                const ok = d.typed === d.word.text
                return (
                  <span key={i} className={`break-all ${ok ? 'text-muted' : 'text-bad line-through decoration-1'}`}>
                    {w.text}
                  </span>
                )
              }
              if (i === done.length)
                return (
                  <span key={i} className="break-all border-b border-accent">
                    {w.text.split('').map((ch, j) => {
                      const t = typed[j]
                      const cls = t === undefined ? 'text-fg' : t === ch ? 'text-good' : 'bg-bad text-bg'
                      return (
                        <span key={j} className={`${cls} ${j === typed.length ? 'border-l border-accent' : ''}`}>
                          {ch}
                        </span>
                      )
                    })}
                    {typed.length > w.text.length && <span className="bg-bad text-bg">{typed.slice(w.text.length)}</span>}
                  </span>
                )
              return (
                <span key={i} className="break-all text-faint">
                  {w.text}
                </span>
              )
            })}
          </p>
          {current && (
            <p className="mt-2 text-[11px] text-faint">
              current: <span className="text-muted">{current.tag}</span>
            </p>
          )}
          <label className="mt-3 flex items-center gap-2 border border-line-strong px-2 py-1.5 focus-within:border-accent">
            <span className="text-accent">type&gt;</span>
            <input
              ref={input}
              value={typed}
              aria-label={current ? `Type: ${current.text}` : 'Drill finished'}
              spellCheck={false}
              autoCapitalize="off"
              autoComplete="off"
              autoCorrect="off"
              className="min-w-0 flex-1 bg-transparent caret-[var(--accent)] outline-none"
              onChange={(e) => {
                const v = e.target.value
                if (startedAt === null && v) setStartedAt(Date.now())
                if (v.endsWith(' ')) {
                  setTyped(v.trim())
                  if (v.trim()) {
                    setDone((d) => (current ? [...d, { word: current, typed: v.trim() }] : d))
                    setTyped('')
                  }
                  return
                }
                setTyped(v)
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  commit()
                } else if (e.key === 'Escape') restart()
              }}
            />
            <Kbd>esc</Kbd>
          </label>
          <p className="mt-1.5 text-[11px] text-faint">esc restarts · words: {done.length} · errors: {done.filter((d) => d.typed !== d.word.text).length}</p>
        </div>
      ) : (
        <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-3 py-3">
          <p className="type-in">
            <span className="font-semibold text-good">[ done ]</span> <span className="text-muted">60s drill complete</span>
            {result.best && <span className="text-warn"> · new best</span>}
          </p>
          <dl className="mt-3 grid grid-cols-[7rem_1fr] gap-y-1 tabular-nums">
            <dt className="text-faint">wpm</dt>
            <dd className="text-fg">{result.wpm}</dd>
            <dt className="text-faint">accuracy</dt>
            <dd>
              <Meter value={result.accuracy} width={16} label="Accuracy" /> {Math.round(result.accuracy * 100)}%
            </dd>
            <dt className="text-faint">tokens</dt>
            <dd>
              {done.length} typed · {done.filter((d) => d.typed !== d.word.text).length} wrong
            </dd>
            <dt className="text-faint">xp</dt>
            <dd className="text-accent">+{result.xp}</dd>
          </dl>
          {done.some((d) => d.typed !== d.word.text) && (
            <div className="mt-3">
              <p className="text-[11px] uppercase tracking-[0.12em] text-faint">misses</p>
              <ul className="mt-1 space-y-0.5 text-[12px]">
                {done
                  .filter((d) => d.typed !== d.word.text)
                  .slice(0, 8)
                  .map((d, i) => (
                    <li key={i}>
                      <span className="text-bad line-through">{d.typed}</span> <span className="text-faint">→</span> <span className="text-good">{d.word.text}</span>{' '}
                      <span className="text-faint">({d.word.tag})</span>
                    </li>
                  ))}
              </ul>
            </div>
          )}
          <div className="mt-4 flex gap-2">
            <Btn tone="primary" className="flex-1" onClick={restart}>
              again
            </Btn>
            <Btn onClick={() => useGame.getState().toMenu()}>menu</Btn>
          </div>
        </div>
      )}
    </div>
  )
}
