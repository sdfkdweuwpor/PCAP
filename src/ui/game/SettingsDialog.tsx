// Settings and progress as a config-file panel: `key  value` rows with bracket toggles, then stats.

import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { nextRank, rankFor } from '../../game/scoring'
import { CONCEPT_LABEL, type Concept } from '../../game/types'
import { useProgress, type Settings } from '../../store/progress'
import { useReduced } from '../motion'
import { Btn, Meter } from '../term'

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="file"]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function SettingsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const p = useProgress()
  const reduced = useReduced()
  const [msg, setMsg] = useState<string | null>(null)
  const [confirmReset, setConfirmReset] = useState(false)
  const [wasOpen, setWasOpen] = useState(open)
  const file = useRef<HTMLInputElement>(null)
  const panel = useRef<HTMLDivElement>(null)

  // Closing forgets the status line and any half-finished "erase all progress?" confirmation.
  if (open !== wasOpen) {
    setWasOpen(open)
    if (!open) {
      setMsg(null)
      setConfirmReset(false)
    }
  }

  // Focus moves into the dialog on open and back to whatever opened it on close.
  useEffect(() => {
    if (!open) return
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    panel.current?.focus()
    return () => {
      if (opener?.isConnected) opener.focus()
    }
  }, [open])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') return onClose()
      if (e.key !== 'Tab') return
      // Trap Tab inside the dialog: wrap at the ends and pull stray focus back in.
      const root = panel.current
      if (!root) return
      const nodes = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)]
      const first = nodes[0]
      const last = nodes[nodes.length - 1]
      const active = document.activeElement
      if (!first || !last) {
        e.preventDefault()
        root.focus()
      } else if (!root.contains(active) || active === root) {
        e.preventDefault()
        ;(e.shiftKey ? last : first).focus()
      } else if (e.shiftKey && active === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && active === last) {
        e.preventDefault()
        first.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  const set = (patch: Partial<Settings>) => p.setSettings(patch)
  const exportFile = () => {
    const json = p.exportJSON()
    const blob = new Blob([json], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `packetquest-progress-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    // Sandboxed embeds block downloads, so also put the JSON on the clipboard.
    if (!navigator.clipboard) {
      setMsg('error: clipboard unavailable; use a browser that allows downloads')
      return
    }
    navigator.clipboard.writeText(json).then(
      () => setMsg('[ ok ] exported; JSON also copied to clipboard'),
      () => setMsg('[ ok ] export started'),
    )
  }

  const concepts = (Object.entries(p.concepts) as [Concept, { seen: number; correct: number }][]).sort((a, b) => b[1].seen - a[1].seen)
  const rank = rankFor(p.xp)
  const next = nextRank(p.xp)
  const frac = next ? (p.xp - rank.minXp) / (next.minXp - rank.minXp) : 1
  const accuracy = p.answered ? Math.round((p.correct / p.answered) * 100) : 0
  const onOff: [string, string][] = [['on', 'on'], ['off', 'off']]
  const phosphor = p.settings.theme !== 'paper'

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-[90] flex justify-end bg-bg/70"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: reduced ? 0 : 0.1 }}
          onClick={onClose}
        >
          <motion.div
            ref={panel}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            aria-labelledby="settings-title"
            className="scroll-thin flex h-full w-full max-w-md flex-col overflow-y-auto border-l border-line-strong bg-panel text-[12px] outline-none"
            initial={{ x: reduced ? 0 : 24, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: reduced ? 0 : 24, opacity: 0 }}
            transition={{ duration: reduced ? 0 : 0.12, ease: 'linear' }}
            onClick={(e) => e.stopPropagation()}
          >
            <header className="flex h-6 shrink-0 items-center gap-2 border-b border-line bg-panel2 px-2 text-[11px] tracking-[0.06em]">
              <span className="text-faint" aria-hidden>
                ┌
              </span>
              <h2 id="settings-title" className="font-semibold text-fg">
                ~/.pktq/config
              </h2>
              <span className="rule" aria-hidden />
              <button onClick={onClose} aria-label="Close settings" className="text-muted hover:text-fg">
                [esc]
              </button>
            </header>

            <div className="space-y-6 p-4">
              <section aria-label="Settings">
                <Label>settings</Label>
                <dl className="space-y-1.5">
                  <Row k="theme">
                    <Choice
                      label="theme"
                      value={p.settings.theme}
                      options={[['dark', 'dark'], ['paper', 'paper']]}
                      onChange={(v) => set({ theme: v as Settings['theme'] })}
                    />
                  </Row>
                  <Row k="crt scanlines">
                    <Choice label="crt scanlines" value={p.settings.crt ? 'on' : 'off'} options={onOff} onChange={(v) => set({ crt: v === 'on' })} dim={!phosphor} />
                    {!phosphor && <span className="ml-2 text-faint">dark screen only</span>}
                  </Row>
                  <Row k="reduce motion">
                    <Choice
                      label="reduce motion"
                      value={p.settings.reduceMotion}
                      options={[['system', 'system'], ['on', 'on'], ['off', 'off']]}
                      onChange={(v) => set({ reduceMotion: v as Settings['reduceMotion'] })}
                    />
                  </Row>
                  <Row k="show timer">
                    <Choice label="show timer" value={p.settings.showTimer ? 'on' : 'off'} options={onOff} onChange={(v) => set({ showTimer: v === 'on' })} />
                  </Row>
                  <Row k="shortcuts">
                    <Choice label="single-key shortcuts" value={p.settings.hotkeys ? 'on' : 'off'} options={onOff} onChange={(v) => set({ hotkeys: v === 'on' })} />
                    <p className="mt-0.5 text-[11px] text-faint"># turn off if shortcuts clash with your screen reader or keyboard</p>
                  </Row>
                  <Row k="unlock all">
                    <Choice label="unlock all modes" value={p.settings.unlockAll ? 'on' : 'off'} options={onOff} onChange={(v) => set({ unlockAll: v === 'on' })} />
                    <span className="ml-2 text-faint"># instructor mode</span>
                  </Row>
                  <Row k="ai explain">
                    <Choice label="ai explain hook" value={p.settings.aiExplain ? 'on' : 'off'} options={onOff} onChange={(v) => set({ aiExplain: v === 'on' })} />
                    <span className="ml-2 text-faint"># experimental</span>
                  </Row>
                </dl>
                <p className="mt-1.5 border-l border-line pl-2 text-[11px] text-faint">
                  # ai explain is off by default. when on, an "ai explain" button appears; it only works if your build registers a provider, and it sends the masked text summary, never raw packets.
                </p>
              </section>

              <section aria-label="Progress">
                <Label>progress</Label>
                <dl className="space-y-1.5">
                  <Row k="rank">
                    <span className="text-accent">{rank.name.toLowerCase()}</span>
                  </Row>
                  <Row k="xp">
                    <Meter value={frac} width={14} label="Progress to next rank" /> <span className="tabular-nums">{p.xp}</span>
                    {next && <span className="text-faint tabular-nums"> / {next.minXp}</span>}
                  </Row>
                  <Row k="answered">
                    <span className="tabular-nums">{p.answered}</span>
                  </Row>
                  <Row k="accuracy">
                    <span className="tabular-nums">{accuracy}%</span>
                  </Row>
                  <Row k="best streak">
                    <span className="tabular-nums">{p.bestStreak}</span>
                  </Row>
                  <Row k="drill wpm">
                    <span className="tabular-nums">{p.drill.bestWpm}</span> <span className="text-faint">best</span>
                  </Row>
                  <Row k="drill acc">
                    <span className="tabular-nums">{Math.round(p.drill.bestAccuracy * 100)}%</span> <span className="text-faint">best</span>
                  </Row>
                  <Row k="drill runs">
                    <span className="tabular-nums">{p.drill.runs}</span>
                  </Row>
                </dl>
                {!p.storageOk && <p className="mt-2 text-warn">warn: browser storage unavailable, progress will not survive a reload. use export to keep it.</p>}
              </section>

              {concepts.length > 0 && (
                <section aria-label="Accuracy by concept">
                  <Label>concepts</Label>
                  <table className="w-full border-collapse tabular-nums">
                    <caption className="sr-only">Accuracy by concept</caption>
                    <tbody>
                      {concepts.map(([c, s]) => {
                        const v = s.correct / s.seen
                        return (
                          <tr key={c}>
                            <th scope="row" className="w-[9.5rem] truncate py-0.5 pr-2 text-left font-normal text-muted">
                              {CONCEPT_LABEL[c].toLowerCase()}
                            </th>
                            <td className="py-0.5 pr-2">
                              <Meter value={v} width={12} label={`${CONCEPT_LABEL[c]} accuracy`} />
                            </td>
                            <td className="py-0.5 pr-2 text-right">{Math.round(v * 100)}%</td>
                            <td className="py-0.5 text-right text-faint">n={s.seen}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </section>
              )}

              <section aria-label="Data">
                <Label>data</Label>
                <div className="flex flex-wrap items-center gap-2">
                  <Btn onClick={exportFile}>export</Btn>
                  <Btn onClick={() => file.current?.click()}>import</Btn>
                  <input
                    ref={file}
                    type="file"
                    accept="application/json,.json"
                    className="hidden"
                    onChange={async (e) => {
                      const f = e.target.files?.[0]
                      e.target.value = ''
                      if (!f) return
                      const err = p.importJSON(await f.text())
                      setMsg(err ? `error: ${err}` : '[ ok ] progress imported')
                    }}
                  />
                  {confirmReset ? (
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="text-bad">erase all progress?</span>
                      <Btn
                        tone="danger"
                        onClick={() => {
                          p.reset()
                          setConfirmReset(false)
                          setMsg('[ ok ] progress reset')
                        }}
                      >
                        yes, reset
                      </Btn>
                      <Btn onClick={() => setConfirmReset(false)}>cancel</Btn>
                    </span>
                  ) : (
                    <Btn tone="danger" onClick={() => setConfirmReset(true)}>
                      reset
                    </Btn>
                  )}
                </div>
                {msg && (
                  <p className={`mt-2 ${msg.startsWith('error') ? 'text-bad' : 'text-good'}`} role="status">
                    {msg}
                  </p>
                )}
              </section>

              <section aria-label="Privacy" className="border-t border-line pt-3 text-[11px] text-faint">
                <p>
                  # captures are parsed locally in a web worker and never leave this tab. progress lives in this browser's localStorage only.
                </p>
              </section>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

function Label({ children }: { children: ReactNode }) {
  return <h3 className="mb-2 border-b border-line pb-1 text-[11px] uppercase tracking-[0.12em] text-faint">[{children}]</h3>
}

/** `key  value` line: fixed-width key column, value flows after it. */
function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-2">
      <dt className="w-28 shrink-0 text-muted">{k}</dt>
      <dd className="m-0 min-w-0 flex-1">{children}</dd>
    </div>
  )
}

/** Bracket choice group: the active option reads `[on]`, the others are bare words. */
function Choice({ label, value, options, onChange, dim }: { label: string; value: string; options: [string, string][]; onChange: (v: string) => void; dim?: boolean }) {
  return (
    <span role="radiogroup" aria-label={label} className={`inline-flex gap-2 ${dim ? 'opacity-50' : ''}`}>
      {options.map(([v, l]) => {
        const on = value === v
        return (
          <button key={v} role="radio" aria-checked={on} onClick={() => onChange(v)} className={`whitespace-pre ${on ? 'text-accent' : 'text-muted hover:text-fg'}`}>
            {on ? `[${l}]` : ` ${l} `}
          </button>
        )
      })}
    </span>
  )
}
