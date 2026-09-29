import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useRef, useState } from 'react'
import { rankFor } from '../../game/scoring'
import { CONCEPT_LABEL, type Concept } from '../../game/types'
import { useProgress, type Settings } from '../../store/progress'
import { IconDownload, IconUpload, IconX } from '../icons'

export function SettingsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const p = useProgress()
  const [msg, setMsg] = useState<string | null>(null)
  const [confirmReset, setConfirmReset] = useState(false)
  const file = useRef<HTMLInputElement>(null)
  const panel = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    panel.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  const set = (patch: Partial<Settings>) => p.setSettings(patch)
  const exportFile = () => {
    const blob = new Blob([p.exportJSON()], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `packetquest-progress-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
  }

  const concepts = (Object.entries(p.concepts) as [Concept, { seen: number; correct: number }][]).sort((a, b) => b[1].seen - a[1].seen)

  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-[90] flex justify-end bg-bg/60 backdrop-blur-[2px]" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}>
          <motion.div
            ref={panel}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            aria-labelledby="settings-title"
            className="scroll-thin h-full w-full max-w-sm overflow-y-auto border-l border-line bg-panel p-5 outline-none"
            initial={{ x: 60, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 60, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 320, damping: 32 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h2 id="settings-title" className="text-lg font-bold">
                Settings & progress
              </h2>
              <button onClick={onClose} aria-label="Close settings" className="rounded p-1 text-muted hover:text-fg">
                <IconX />
              </button>
            </div>

            <section className="mt-4 space-y-3 text-sm">
              <Row label="Theme">
                <Seg value={p.settings.theme} options={[['dark', 'Dark'], ['light', 'Light']]} onChange={(v) => set({ theme: v as Settings['theme'] })} />
              </Row>
              <Row label="Reduce motion">
                <Seg
                  value={p.settings.reduceMotion}
                  options={[['system', 'System'], ['on', 'On'], ['off', 'Off']]}
                  onChange={(v) => set({ reduceMotion: v as Settings['reduceMotion'] })}
                />
              </Row>
              <Toggle label="Show question timer" checked={p.settings.showTimer} onChange={(v) => set({ showTimer: v })} />
              <Toggle label="Unlock all modes (instructor mode)" checked={p.settings.unlockAll} onChange={(v) => set({ unlockAll: v })} />
              <Toggle
                label="AI explain hook (experimental)"
                hint="Off by default. When on, an “AI explain” button appears; it only works if your build registers a provider, and it sends the masked text summary — never raw packets."
                checked={p.settings.aiExplain}
                onChange={(v) => set({ aiExplain: v })}
              />
            </section>

            <section className="mt-6">
              <h3 className="text-sm font-semibold">Your progress</h3>
              <p className="mt-1 text-sm text-muted">
                {rankFor(p.xp).name} · {p.xp} XP · {p.answered} answered · {p.answered ? Math.round((p.correct / p.answered) * 100) : 0}% correct · best streak {p.bestStreak}
              </p>
              {!p.storageOk && <p className="mt-1 text-xs text-warn">Browser storage is unavailable, so progress won't survive a reload. Use Export to keep it.</p>}
              {concepts.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {concepts.map(([c, s]) => (
                    <li key={c} className="flex items-center gap-2 text-xs">
                      <span className="w-28 truncate">{CONCEPT_LABEL[c]}</span>
                      <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel3">
                        <span className="block h-full origin-left rounded-full bg-accent" style={{ transform: `scaleX(${s.correct / s.seen})` }} />
                      </span>
                      <span className="w-16 text-right font-mono text-muted">
                        {Math.round((s.correct / s.seen) * 100)}% ({s.seen})
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-3 flex flex-wrap gap-2">
                <button onClick={exportFile} className="flex items-center gap-1 rounded-lg border border-line px-3 py-1.5 text-xs hover:border-accent">
                  <IconDownload size={13} /> Export progress
                </button>
                <button onClick={() => file.current?.click()} className="flex items-center gap-1 rounded-lg border border-line px-3 py-1.5 text-xs hover:border-accent">
                  <IconUpload size={13} /> Import progress
                </button>
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
                    setMsg(err ?? 'Progress imported.')
                  }}
                />
                {confirmReset ? (
                  <span className="flex items-center gap-1 text-xs">
                    Erase all progress?
                    <button
                      onClick={() => {
                        p.reset()
                        setConfirmReset(false)
                        setMsg('Progress reset.')
                      }}
                      className="rounded bg-bad px-2 py-1 font-semibold text-white"
                    >
                      Yes, reset
                    </button>
                    <button onClick={() => setConfirmReset(false)} className="rounded border border-line px-2 py-1">
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button onClick={() => setConfirmReset(true)} className="rounded-lg border border-bad/50 px-3 py-1.5 text-xs text-bad hover:bg-bad/10">
                    Reset
                  </button>
                )}
              </div>
              {msg && (
                <p className="mt-2 text-xs text-muted" role="status">
                  {msg}
                </p>
              )}
            </section>

            <section className="mt-6 rounded-lg border border-line bg-panel2 p-3 text-xs text-muted">
              <p className="font-semibold text-fg">Privacy</p>
              <p className="mt-1">Captures are parsed locally in a Web Worker and never leave this tab. Progress lives in this browser's localStorage only.</p>
            </section>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span>{label}</span>
      {children}
    </div>
  )
}

function Seg({ value, options, onChange }: { value: string; options: [string, string][]; onChange: (v: string) => void }) {
  return (
    <div role="radiogroup" className="flex rounded-lg border border-line p-0.5">
      {options.map(([v, l]) => (
        <button key={v} role="radio" aria-checked={value === v} onClick={() => onChange(v)} className={`rounded-md px-2.5 py-1 text-xs ${value === v ? 'bg-accent text-accent-ink' : 'text-muted'}`}>
          {l}
        </button>
      ))}
    </div>
  )
}

function Toggle({ label, hint, checked, onChange }: { label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-3">
      <span>
        {label}
        {hint && <span className="mt-0.5 block text-xs text-muted">{hint}</span>}
      </span>
      <button role="switch" aria-checked={checked} onClick={() => onChange(!checked)} className={`relative mt-0.5 h-5 w-9 shrink-0 rounded-full transition-colors ${checked ? 'bg-accent' : 'bg-panel3'}`}>
        <motion.span className="absolute top-0.5 h-4 w-4 rounded-full bg-white shadow" animate={{ x: checked ? 18 : 2 }} transition={{ type: 'spring', stiffness: 500, damping: 30 }} />
      </button>
    </label>
  )
}
