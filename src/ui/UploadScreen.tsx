// Landing screen: privacy note, drag-and-drop / file picker, built-in samples, parsing animation.

import { AnimatePresence, motion, useMotionValue, useTransform, animate } from 'framer-motion'
import { useEffect, useRef, useState } from 'react'
import { SAMPLES } from '../samples/samples'
import { ACCEPTED, useCapture } from '../store/capture'
import { useProgress } from '../store/progress'
import { IconAlert, IconLogo, IconMoon, IconShield, IconSun, IconUpload } from './icons'
import { useReduced } from './motion'
import { rankFor } from '../game/scoring'

const DIFF_COLOR = { Recruit: 'var(--good)', Analyst: 'var(--accent)', Hunter: 'var(--bad)' }

export function UploadScreen() {
  const { status, progress, error, loadFile, loadSample, fileName, sizeWarning } = useCapture()
  const [drag, setDrag] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const xp = useProgress((s) => s.xp)
  const theme = useProgress((s) => s.settings.theme)
  const setSettings = useProgress((s) => s.setSettings)
  const loading = status === 'loading'

  const onFiles = (files: FileList | null) => {
    const f = files?.[0]
    if (f) void loadFile(f)
  }

  return (
    <motion.main
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, y: -12 }}
      className="min-h-full overflow-y-auto scroll-thin"
    >
      <div className="mx-auto max-w-6xl px-4 py-6 sm:px-8 sm:py-10">
        <header className="mb-8 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <IconLogo size={36} />
            <div>
              <h1 className="text-xl font-bold tracking-tight">PacketQuest</h1>
              <p className="text-xs text-muted">Learn to read packet captures like an analyst</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {xp > 0 && (
              <span className="hidden rounded-full border border-line px-3 py-1 text-xs text-muted sm:inline">
                {rankFor(xp).name} · {xp} XP
              </span>
            )}
            <button
              className="rounded-lg border border-line p-2 text-muted hover:text-fg"
              onClick={() => setSettings({ theme: theme === 'dark' ? 'light' : 'dark' })}
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            >
              {theme === 'dark' ? <IconSun /> : <IconMoon />}
            </button>
          </div>
        </header>

        <section className="grid gap-6 lg:grid-cols-[1.1fr_1fr]">
          <div>
            <h2 className="text-3xl font-bold leading-tight tracking-tight sm:text-4xl">
              Turn any capture into a <span className="text-accent">packet-reading game</span>.
            </h2>
            <p className="mt-3 max-w-xl text-muted">
              Drop a Wireshark capture and PacketQuest builds quizzes from <em>your</em> traffic: find the handshake, decode
              the DNS answer, spot the port scan. Every answer explains the exact bytes involved.
            </p>
            <div className="mt-5 flex items-start gap-3 rounded-xl border border-line bg-panel p-4">
              <IconShield size={22} className="mt-0.5 shrink-0 text-good" />
              <div className="text-sm">
                <p className="font-semibold">Private by design</p>
                <p className="text-muted">
                  Your capture is parsed entirely in this browser tab (in a Web Worker). No packet data is ever uploaded or sent
                  anywhere. Progress is stored only in this browser.
                </p>
              </div>
            </div>
          </div>

          <div
            role="button"
            tabIndex={0}
            aria-label="Upload a capture file: drop it here or press Enter to browse"
            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
            onClick={() => !loading && input.current?.click()}
            onDragOver={(e) => {
              e.preventDefault()
              setDrag(true)
            }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDrag(false)
              onFiles(e.dataTransfer.files)
            }}
            className={`relative flex min-h-64 cursor-pointer flex-col items-center justify-center overflow-hidden rounded-2xl border-2 border-dashed p-6 text-center transition-colors ${
              drag ? 'border-accent bg-accent/10' : 'border-line bg-panel hover:border-accent/60'
            }`}
          >
            <input
              ref={input}
              type="file"
              accept={ACCEPTED.join(',')}
              className="hidden"
              onChange={(e) => {
                onFiles(e.target.files)
                e.target.value = ''
              }}
            />
            <AnimatePresence mode="wait">
              {loading ? (
                <ParsingAnimation key="parse" fileName={fileName} packets={progress?.packets ?? 0} fraction={progress?.fraction ?? 0} phase={progress?.phase ?? 'reading'} />
              ) : (
                <motion.div key="idle" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: 0.96 }}>
                  <motion.div
                    animate={drag ? { y: -6, scale: 1.1 } : { y: 0, scale: 1 }}
                    className="mx-auto mb-3 grid h-14 w-14 place-items-center rounded-2xl bg-accent/15 text-accent"
                  >
                    <IconUpload size={26} />
                  </motion.div>
                  <p className="font-semibold">Drop a .pcap / .pcapng / .cap here</p>
                  <p className="mt-1 text-sm text-muted">or click to browse · classic PCAP & PCAPNG · Ethernet, Linux SLL/SLL2, raw IP, loopback</p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </section>

        <AnimatePresence>
          {error && status === 'error' && (
            <motion.div
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              role="alert"
              className="mt-6 flex items-start gap-3 rounded-xl border border-bad/50 bg-bad/10 p-4 text-sm"
            >
              <IconAlert size={20} className="mt-0.5 shrink-0 text-bad" />
              <div>
                <p className="font-semibold">We couldn't open that capture</p>
                <p className="text-muted">{error.message}</p>
                <p className="mt-2">
                  <button className="font-semibold text-accent underline underline-offset-2" onClick={() => void loadSample('web-basic')}>
                    Load the "Basic web visit" sample instead
                  </button>
                </p>
              </div>
            </motion.div>
          )}
          {sizeWarning && loading && (
            <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-4 rounded-lg border border-warn/40 bg-warn/10 p-3 text-sm">
              {sizeWarning}
            </motion.p>
          )}
        </AnimatePresence>

        <section className="mt-10">
          <div className="mb-3 flex items-baseline justify-between">
            <h3 className="text-lg font-semibold">No capture handy? Try a sample</h3>
            <span className="text-xs text-muted">Synthetic, generated in your browser</span>
          </div>
          <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {SAMPLES.map((s, i) => (
              <motion.li key={s.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.03 * i }}>
                <button
                  disabled={loading}
                  onClick={() => void loadSample(s.id)}
                  className="group flex h-full w-full flex-col rounded-xl border border-line bg-panel p-4 text-left transition hover:-translate-y-0.5 hover:border-accent/60 disabled:opacity-50"
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="font-semibold">{s.title}</span>
                    <span
                      className="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide"
                      style={{ color: DIFF_COLOR[s.difficulty], background: `color-mix(in srgb, ${DIFF_COLOR[s.difficulty]} 15%, transparent)` }}
                    >
                      {s.difficulty}
                    </span>
                  </span>
                  <span className="mt-2 text-sm text-muted">{s.learn}</span>
                  <span className="mt-3 font-mono text-[11px] text-faint group-hover:text-accent">{s.fileName}</span>
                </button>
              </motion.li>
            ))}
          </ul>
        </section>

        <footer className="mt-10 text-center text-xs text-faint">
          Tip: in Wireshark, File → Export Specified Packets lets you save just the part of a capture you want to study.
        </footer>
      </div>
    </motion.main>
  )
}

function ParsingAnimation({ fileName, packets, fraction, phase }: { fileName: string; packets: number; fraction: number; phase: string }) {
  const reduced = useReduced()
  const count = useMotionValue(0)
  const rounded = useTransform(count, (v) => Math.round(v).toLocaleString())
  useEffect(() => {
    const c = animate(count, packets, { duration: reduced ? 0 : 0.4 })
    return () => c.stop()
  }, [packets, count, reduced])
  const label = phase === 'reading' ? 'Reading file' : phase === 'dissecting' ? 'Dissecting packets' : 'Building conversations & questions'
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="w-full max-w-sm" aria-live="polite">
      <div className="relative mb-4 h-20 overflow-hidden rounded-lg border border-line bg-bg" aria-hidden>
        {Array.from({ length: 7 }).map((_, i) => (
          <motion.div
            key={i}
            className="absolute left-2 right-2 h-2 rounded"
            style={{ top: 6 + i * 10, background: ['var(--p-dns)', 'var(--p-tcp)', 'var(--p-http)', 'var(--p-tls)', 'var(--p-arp)', 'var(--p-udp)', 'var(--p-syn)'][i], opacity: 0.55 }}
            initial={{ x: '-110%' }}
            animate={reduced ? { x: 0 } : { x: ['-110%', '0%', '0%', '110%'] }}
            transition={reduced ? {} : { duration: 1.6, delay: i * 0.12, repeat: Infinity, times: [0, 0.25, 0.75, 1] }}
          />
        ))}
      </div>
      <p className="truncate font-mono text-sm">{fileName}</p>
      <p className="mt-1 text-sm text-muted">
        {label}… <motion.span className="font-mono text-fg">{rounded}</motion.span> packets
      </p>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-panel3" role="progressbar" aria-valuenow={Math.round(fraction * 100)} aria-valuemin={0} aria-valuemax={100}>
        <motion.div className="h-full origin-left rounded-full bg-accent" animate={{ scaleX: Math.max(0.03, fraction) }} transition={{ type: 'tween', duration: 0.2 }} />
      </div>
    </motion.div>
  )
}
