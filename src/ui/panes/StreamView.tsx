// Follow TCP/UDP Stream: reassembled payload, client in one colour, server in another.

import { useMemo, useState } from 'react'
import { followStream } from '../../core/index/conversations'
import { getFrameBytes, useCapture } from '../../store/capture'

type View = 'ascii' | 'hex'

function toAscii(b: Uint8Array): string {
  let s = ''
  for (const c of b) s += c === 10 || c === 13 || c === 9 || (c >= 32 && c < 127) ? String.fromCharCode(c) : '.'
  return s
}
function toHex(b: Uint8Array): string {
  const lines: string[] = []
  for (let i = 0; i < b.length; i += 16) {
    const chunk = b.subarray(i, i + 16)
    lines.push(`${i.toString(16).padStart(8, '0')}  ${[...chunk].map((x) => x.toString(16).padStart(2, '0')).join(' ').padEnd(48)}  ${toAscii(chunk).replace(/[\r\n\t]/g, '.')}`)
  }
  return lines.join('\n')
}

export function StreamView() {
  const index = useCapture((s) => s.index)!
  const streamConv = useCapture((s) => s.streamConv)
  const selected = useCapture((s) => s.selected)
  const reveal = useCapture((s) => s.revealSecrets)
  const [view, setView] = useState<View>('ascii')
  const candidates = useMemo(() => index.conversations.filter((c) => (c.proto === 'TCP' || c.proto === 'UDP') && c.bytes > 0), [index])
  const fallback = selected ? index.packets[selected - 1].streamId : -1
  const convId = streamConv ?? (fallback >= 0 ? fallback : candidates.find((c) => c.proto === 'TCP')?.id ?? null)
  const conv = convId !== null ? index.conversations[convId] : null

  const segs = useMemo(() => {
    if (!conv || (conv.proto !== 'TCP' && conv.proto !== 'UDP')) return []
    return followStream(conv, (no) => index.packets[no - 1], (p) => getFrameBytes(p.no))
  }, [conv, index])

  const secrets = useMemo(() => {
    const s = new Set<string>()
    if (!conv || reveal) return s
    for (const no of conv.packets) {
      const sec = index.packets[no - 1].facts.creds?.secret
      if (sec) s.add(sec)
    }
    return s
  }, [conv, reveal, index])
  const maskedFrames = useMemo(() => {
    const s = new Set<number>()
    if (!conv || reveal) return s
    for (const no of conv.packets) if (index.packets[no - 1].facts.creds?.proto === 'Telnet' && index.packets[no - 1].facts.creds?.kind === 'pass') s.add(no)
    return s
  }, [conv, reveal, index])
  const mask = (t: string) => {
    let out = t
    for (const s of secrets) out = out.split(s).join('•'.repeat(s.length))
    return out
  }

  const aBytes = segs.filter((s) => s.fromA).reduce((n, s) => n + s.bytes.length, 0)
  const bBytes = segs.filter((s) => !s.fromA).reduce((n, s) => n + s.bytes.length, 0)

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-panel2 px-3 py-2 text-sm">
        <select
          value={convId ?? ''}
          onChange={(e) => useCapture.getState().setStreamConv(Number(e.target.value))}
          className="max-w-[24rem] rounded-md border border-line bg-panel px-2 py-1 font-mono text-xs"
          aria-label="Stream to follow"
        >
          {candidates.slice(0, 500).map((c) => (
            <option key={c.id} value={c.id}>
              {c.proto.toLowerCase()}.stream {c.id} · {c.app} · {c.a.addr}:{c.a.port} ⇄ {c.b.addr}:{c.b.port}
            </option>
          ))}
        </select>
        <div className="flex gap-1" role="radiogroup" aria-label="Show as">
          {(['ascii', 'hex'] as View[]).map((v) => (
            <button key={v} role="radio" aria-checked={view === v} onClick={() => setView(v)} className={`rounded px-2 py-0.5 text-xs ${view === v ? 'bg-accent text-accent-ink' : 'border border-line text-muted'}`}>
              {v.toUpperCase()}
            </button>
          ))}
        </div>
        {conv && (
          <span className="ml-auto flex gap-3 text-xs">
            <span className="text-[var(--p-http)]">■ {conv.a.addr} → {aBytes} B</span>
            <span className="text-[var(--p-tls)]">■ {conv.b.addr} → {bBytes} B</span>
          </span>
        )}
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-auto p-3 font-mono text-[12px] leading-relaxed">
        {!conv && <p className="font-sans text-sm text-muted">No TCP/UDP stream with payload in this capture.</p>}
        {conv && segs.length === 0 && <p className="font-sans text-sm text-muted">This stream carries no payload (only handshakes/ACKs).</p>}
        {segs.map((s, i) => (
          <pre
            key={i}
            onClick={() => useCapture.getState().select(s.frame)}
            title={`Frame ${s.frame} — click to select`}
            className={`mb-1 cursor-pointer whitespace-pre-wrap break-all rounded px-2 py-1 ${s.fromA ? 'bg-[var(--p-http)]/10 text-[var(--p-http)]' : 'bg-[var(--p-tls)]/10 text-[var(--p-tls)]'}`}
          >
            {maskedFrames.has(s.frame) ? '•'.repeat(Math.max(1, s.bytes.length - 2)) : view === 'ascii' ? mask(toAscii(s.bytes)) : mask(toHex(s.bytes))}
          </pre>
        ))}
      </div>
    </div>
  )
}
