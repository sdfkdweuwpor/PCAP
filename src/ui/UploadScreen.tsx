// Start screen: a load console. Drop/browse a capture, or load a sample from the listing (keys 1–8).

import { motion } from 'framer-motion'
import { useEffect, useMemo, useRef, useState } from 'react'
import { parseContainer } from '../core/pcap/container'
import { nextRank, rankFor } from '../game/scoring'
import { SAMPLES } from '../samples/samples'
import { ACCEPTED, useCapture } from '../store/capture'
import { useProgress } from '../store/progress'
import { ThemeSwitch } from './Header'
import { hotkeyAllowed } from './hotkeys'
import { Btn, Frame, Kbd, Meter } from './term'

const fmtSize = (n: number) => (n < 1024 ? `${n}B` : n < 1048576 ? `${(n / 1024).toFixed(1)}K` : `${(n / 1048576).toFixed(1)}M`)

export function UploadScreen() {
  const { status, progress, error, loadFile, loadSample, fileName, sizeWarning } = useCapture()
  const [drag, setDrag] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const xp = useProgress((s) => s.xp)
  const answered = useProgress((s) => s.answered)
  const correct = useProgress((s) => s.correct)
  const last = useProgress((s) => s.sessions[0])
  const loading = status === 'loading'

  // Sample metadata for the listing (they are tiny, so building them up front is cheap).
  const listing = useMemo(
    () =>
      SAMPLES.map((s) => {
        const bytes = s.build()
        return { ...s, size: bytes.length, packets: parseContainer(bytes).records.length }
      }),
    [],
  )

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (loading || !hotkeyAllowed(e)) return
      const n = Number(e.key)
      if (n >= 1 && n <= SAMPLES.length) void loadSample(SAMPLES[n - 1].id)
      if (e.key === 'o') input.current?.click()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [loading, loadSample])

  const rank = rankFor(xp)
  const next = nextRank(xp)

  return (
    <motion.main initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.12 }} className="scroll-thin min-h-full overflow-y-auto">
      <div className="mx-auto max-w-[1100px] px-4 py-6 sm:px-6">
        <header className="flex flex-wrap items-end justify-between gap-3 border-b border-line pb-3">
          <div>
            <h1 className="font-display text-[44px] leading-none text-accent glow">PACKETQUEST</h1>
            <p className="mt-1 text-[12px] text-muted">packet-capture reading drills · v1.1 · runs entirely in this tab</p>
          </div>
          <div className="flex items-center gap-4 text-[12px]">
            <span className="hidden text-muted sm:inline">
              {rank.name.toUpperCase()} · {xp} XP {next && <Meter value={(xp - rank.minXp) / (next.minXp - rank.minXp)} width={10} className="ml-1" label="Progress to next rank" />}
            </span>
            <ThemeSwitch />
          </div>
        </header>

        <div className="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <Frame title="Load capture" meta={ACCEPTED.join(' ')}>
            <div
              role="button"
              tabIndex={0}
              aria-label="Load a capture: drop a file here, or press Enter to browse"
              aria-disabled={loading || undefined}
              onKeyDown={(e) => {
                if (e.key !== 'Enter' && e.key !== ' ') return
                e.preventDefault() // Space would otherwise scroll the page
                if (!loading) input.current?.click()
              }}
              onClick={() => !loading && input.current?.click()}
              onDragOver={(e) => {
                e.preventDefault()
                if (!loading) setDrag(true)
              }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => {
                e.preventDefault() // always, so the browser doesn't navigate to the dropped file
                setDrag(false)
                if (loading) return
                const f = e.dataTransfer.files?.[0]
                if (f) void loadFile(f)
              }}
              className={`m-3 flex min-h-[210px] cursor-pointer flex-col justify-between border border-dashed p-4 text-[13px] ${drag ? 'border-accent bg-accent/10' : 'border-line-strong hover:border-accent'}`}
            >
              <input
                ref={input}
                type="file"
                accept={ACCEPTED.join(',')}
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  e.target.value = ''
                  if (f) void loadFile(f)
                }}
              />
              {loading ? (
                <LoadLog fileName={fileName} phase={progress?.phase ?? 'reading'} fraction={progress?.fraction ?? 0} packets={progress?.packets ?? 0} warning={sizeWarning} />
              ) : (
                <>
                  <div>
                    <p className="text-fg">
                      {drag ? '> release to load' : '> drop a capture here'}
                      <span className="cursor-block ml-1" aria-hidden />
                    </p>
                    <p className="mt-1 text-muted">
                      or press <Kbd>o</Kbd> / click to browse. In Wireshark: File → Save As → pcapng.
                    </p>
                  </div>
                  <dl className="mt-4 grid grid-cols-[6.5rem_1fr] gap-y-0.5 text-[12px]">
                    <dt className="text-faint">containers</dt>
                    <dd className="text-muted">pcap (LE/BE, µs/ns) · pcapng (SHB/IDB/EPB/SPB, multi-iface)</dd>
                    <dt className="text-faint">link types</dt>
                    <dd className="text-muted">ethernet+802.1Q · linux sll/sll2 · raw ip · bsd null</dd>
                    <dt className="text-faint">decodes</dt>
                    <dd className="text-muted">arp ip ipv6 icmp tcp udp dns http tls dhcp ftp telnet smtp pop3 imap ssh ntp snmp</dd>
                  </dl>
                </>
              )}
            </div>
            {error && status === 'error' && (
              <div role="alert" className="mx-3 mb-3 border-l-2 border-bad bg-bad/10 px-3 py-2 text-[12px]">
                <p>
                  <span className="font-semibold text-bad">ERR</span> {error.message}
                </p>
                <p className="mt-1 text-muted">
                  try a known-good file instead:{' '}
                  <button className="text-accent underline underline-offset-2" onClick={() => void loadSample('web-basic')}>
                    load 01-web-basic.pcap
                  </button>
                </p>
              </div>
            )}
          </Frame>

          <Frame title="About" meta="local only">
            <div className="space-y-3 p-3 text-[12.5px] leading-relaxed text-muted">
              <p>
                <span className="text-fg">PacketQuest</span> decodes a capture the way Wireshark does, then builds exercises from the packets it
                finds: pick the frame, read the field, write the filter, type the value, find the attack.
              </p>
              <ul className="space-y-1">
                <li>
                  <span className="text-good">✓</span> parsed in a Web Worker; nothing is uploaded
                </li>
                <li>
                  <span className="text-good">✓</span> no network requests after page load (fonts are bundled)
                </li>
                <li>
                  <span className="text-good">✓</span> progress stays in this browser (export/import in settings)
                </li>
                <li>
                  <span className="text-warn">!</span> cleartext passwords are masked until you reveal them
                </li>
              </ul>
              {answered > 0 && (
                <p className="border-t border-line pt-2 text-[12px]">
                  <span className="text-faint">record</span> {answered} answered · {Math.round((correct / answered) * 100)}% correct
                  {last && (
                    <>
                      {' '}
                      · <span className="text-faint">last</span> {last.file} ({last.correct}/{last.answered})
                    </>
                  )}
                </p>
              )}
            </div>
          </Frame>
        </div>

        <Frame title="Samples" meta="$ ls -l samples/" className="mt-4">
          <div className="scroll-thin overflow-x-auto">
            <table className="w-full min-w-[720px] text-[12.5px]">
              <thead className="text-left text-[11px] uppercase tracking-[0.12em] text-faint">
                <tr className="border-b border-line">
                  <th className="w-10 px-3 py-1.5 font-normal">key</th>
                  <th className="px-2 py-1.5 font-normal">file</th>
                  <th className="px-2 py-1.5 text-right font-normal">size</th>
                  <th className="px-2 py-1.5 text-right font-normal">pkts</th>
                  <th className="px-2 py-1.5 font-normal">level</th>
                  <th className="px-2 py-1.5 font-normal">covers</th>
                </tr>
              </thead>
              <tbody>
                {listing.map((s, i) => (
                  <tr
                    key={s.id}
                    role="button"
                    tabIndex={0}
                    onClick={() => !loading && void loadSample(s.id)}
                    onKeyDown={(e) => {
                      if (e.key !== 'Enter' && e.key !== ' ') return
                      e.preventDefault()
                      if (!loading) void loadSample(s.id)
                    }}
                    className="group cursor-pointer border-b border-line/60 last:border-0 hover:bg-accent hover:text-accent-ink focus:bg-accent focus:text-accent-ink focus:outline-none"
                  >
                    <td className="px-3 py-1.5">
                      <Kbd>{i + 1}</Kbd>
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-semibold">{s.fileName}</td>
                    <td className="px-2 py-1.5 text-right tabular-nums text-muted group-hover:text-inherit group-focus:text-inherit">{fmtSize(s.size)}</td>
                    <td className="px-2 py-1.5 text-right tabular-nums text-muted group-hover:text-inherit group-focus:text-inherit">{s.packets}</td>
                    <td className={`px-2 py-1.5 lowercase group-hover:text-inherit group-focus:text-inherit ${s.difficulty === 'Recruit' ? 'text-good' : s.difficulty === 'Analyst' ? 'text-accent' : 'text-bad'}`}>
                      {s.difficulty}
                    </td>
                    <td className="px-2 py-1.5 text-muted group-hover:text-inherit group-focus:text-inherit">{s.learn}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Frame>

        <footer className="mt-4 flex flex-wrap justify-between gap-2 text-[11px] text-faint">
          <span>tip: File → Export Specified Packets in Wireshark trims a capture to the part you want to study.</span>
          <span>
            <Btn className="py-0.5" onClick={() => input.current?.click()} disabled={loading}>
              browse
            </Btn>
          </span>
        </footer>
      </div>
    </motion.main>
  )
}

function LoadLog({ fileName, phase, fraction, packets, warning }: { fileName: string; phase: string; fraction: number; packets: number; warning: string | null }) {
  const steps = [
    { key: 'reading', label: 'read container headers' },
    { key: 'dissecting', label: 'dissect frames' },
    { key: 'analyzing', label: 'index conversations, run heuristics' },
  ]
  const at = steps.findIndex((s) => s.key === phase)
  return (
    <div className="text-[12.5px]" aria-live="polite">
      <p className="text-fg">
        <span className="text-faint">$</span> open {fileName}
      </p>
      {warning && <p className="text-warn">! {warning}</p>}
      {steps.map((s, i) =>
        i <= at ? (
          <p key={s.key} className="type-in text-muted">
            <span className={i < at ? 'text-good' : 'text-accent'}>{i < at ? '[ ok ]' : '[ .. ]'}</span> {s.label}
            {s.key === 'dissecting' && i <= at && <span className="text-fg"> · {packets.toLocaleString()} packets</span>}
          </p>
        ) : null,
      )}
      <p className="mt-3">
        <Meter value={fraction} width={32} label="Parse progress" /> <span className="tabular-nums text-muted">{Math.round(fraction * 100)}%</span>
      </p>
    </div>
  )
}
