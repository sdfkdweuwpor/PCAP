// Follow TCP/UDP Stream: reassembled payload, client in one colour, server in another.

import { useMemo, useState } from 'react'
import { followStream } from '../../core/index/conversations'
import { secretsOf } from '../../game/knowledge'
import { getFrameBytes, useCapture } from '../../store/capture'

type View = 'ascii' | 'hex'

/** The stream picker lists at most this many conversations (plus the one being shown). */
const MAX_OPTIONS = 500

function toAscii(b: Uint8Array): string {
  let s = ''
  for (const c of b) s += c === 10 || c === 13 || c === 9 || (c >= 32 && c < 127) ? String.fromCharCode(c) : '.'
  return s
}
/** Replace every secret in already-ASCII text with bullets of the same length. */
function maskText(t: string, secrets: Set<string>): string {
  let out = t
  for (const sec of secrets) if (sec) out = out.split(sec).join('•'.repeat(sec.length))
  return out
}
/** Per-byte flags for every occurrence of a secret (toAscii is one char per byte, so text offsets are byte offsets). */
function secretBytes(b: Uint8Array, secrets: Set<string>): boolean[] | null {
  let hidden: boolean[] | null = null
  if (!secrets.size) return hidden
  const text = toAscii(b)
  for (const sec of secrets) {
    if (!sec) continue
    for (let at = text.indexOf(sec); at >= 0; at = text.indexOf(sec, at + sec.length)) {
      hidden ??= new Array<boolean>(b.length).fill(false)
      hidden.fill(true, at, at + sec.length)
    }
  }
  return hidden
}
/** Hex dump; bytes flagged in `hidden` are replaced by bullets in both the hex and the ASCII column. */
function toHex(b: Uint8Array, hidden: boolean[] | null): string {
  const lines: string[] = []
  for (let i = 0; i < b.length; i += 16) {
    const chunk = b.subarray(i, i + 16)
    const hex = [...chunk].map((x, k) => (hidden?.[i + k] ? '••' : x.toString(16).padStart(2, '0'))).join(' ')
    const asc = [...toAscii(chunk).replace(/[\r\n\t]/g, '.')].map((c, k) => (hidden?.[i + k] ? '•' : c)).join('')
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hex.padEnd(48)}  ${asc}`)
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
  const isStream = !!conv && (conv.proto === 'TCP' || conv.proto === 'UDP')

  const segs = useMemo(() => {
    if (!conv || !isStream) return []
    return followStream(conv, (no) => index.packets[no - 1], (p) => getFrameBytes(p.no))
  }, [conv, isStream, index])

  // The picker is capped, but the stream on screen must always be selectable in it.
  const options = useMemo(() => {
    const list = candidates.slice(0, MAX_OPTIONS)
    if (conv && isStream && !list.some((c) => c.id === conv.id)) list.push(conv)
    return list.sort((a, b) => a.id - b.id)
  }, [candidates, conv, isStream])
  const inOptions = !!conv && options.some((c) => c.id === conv.id)

  const secrets = useMemo(() => {
    const s = new Set<string>()
    if (!conv || reveal) return s
    // Both the decoded secret and its on-the-wire (e.g. base64) form.
    for (const no of conv.packets) for (const sec of secretsOf(index.packets[no - 1])) s.add(sec)
    return s
  }, [conv, reveal, index])
  const maskedFrames = useMemo(() => {
    const s = new Set<number>()
    if (!conv || reveal) return s
    for (const no of conv.packets) if (index.packets[no - 1].facts.creds?.proto === 'Telnet' && index.packets[no - 1].facts.creds?.kind === 'pass') s.add(no)
    return s
  }, [conv, reveal, index])

  // Rendered text per segment: credential secrets and telnet password frames are masked in both views, hex digits included.
  const texts = useMemo(
    () =>
      segs.map((sg) => {
        if (maskedFrames.has(sg.frame)) return '•'.repeat(Math.max(1, sg.bytes.length - 2))
        return view === 'ascii' ? maskText(toAscii(sg.bytes), secrets) : toHex(sg.bytes, secretBytes(sg.bytes, secrets))
      }),
    [segs, view, secrets, maskedFrames],
  )

  const aBytes = segs.filter((s) => s.fromA).reduce((n, s) => n + s.bytes.length, 0)
  const bBytes = segs.filter((s) => !s.fromA).reduce((n, s) => n + s.bytes.length, 0)

  return (
    <div className="flex h-full min-h-0 flex-col text-[12px]">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-panel2 px-2 py-1 text-[11px]">
        <select
          value={inOptions ? conv.id : ''}
          onChange={(e) => useCapture.getState().setStreamConv(Number(e.target.value))}
          className="max-w-[24rem] border border-line-strong bg-panel px-1 py-0.5 text-[11px] text-fg"
          aria-label="Stream to follow"
        >
          {!inOptions && (
            <option value="" disabled>
              -- none --
            </option>
          )}
          {options.map((c) => (
            <option key={c.id} value={c.id}>
              {c.proto.toLowerCase()}.stream {c.protoIndex ?? c.id} · {c.app} · {c.a.addr}:{c.a.port} ⇄ {c.b.addr}:{c.b.port}
            </option>
          ))}
        </select>
        <div className="flex gap-x-1" role="radiogroup" aria-label="Show as">
          {(['ascii', 'hex'] as View[]).map((v) => (
            <button key={v} role="radio" aria-checked={view === v} onClick={() => setView(v)} className={`px-1 ${view === v ? 'bg-accent text-accent-ink' : 'text-muted hover:text-fg'}`}>
              [{v}]
            </button>
          ))}
        </div>
        {isStream && (
          <span className="ml-auto flex gap-3 tabular-nums">
            <span className="text-[var(--p-http)]" title={conv.a.addr}>
              <span aria-hidden>▌</span>client {aBytes}B
            </span>
            <span className="text-[var(--p-tls)]" title={conv.b.addr}>
              <span aria-hidden>▌</span>server {bBytes}B
            </span>
          </span>
        )}
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-auto p-2 leading-relaxed">
        {!conv && <p className="text-faint">-- no tcp/udp stream with payload in this capture --</p>}
        {conv && !isStream && <p className="text-faint">-- selected frame is not part of a TCP/UDP stream --</p>}
        {isStream && segs.length === 0 && <p className="text-faint">-- stream carries no payload (handshake/acks only) --</p>}
        {segs.map((s, i) => (
          <div
            key={i}
            role="button"
            tabIndex={0}
            onClick={() => useCapture.getState().select(s.frame)}
            onKeyDown={(e) => {
              if (e.key !== 'Enter' && e.key !== ' ') return
              e.preventDefault()
              e.stopPropagation()
              useCapture.getState().select(s.frame)
            }}
            title={`Frame ${s.frame} — click to select`}
            className={`mb-1 flex cursor-pointer gap-2 border-l-2 pl-2 hover:bg-panel3 ${s.fromA ? 'border-[var(--p-http)] text-[var(--p-http)]' : 'border-[var(--p-tls)] text-[var(--p-tls)]'}`}
          >
            <span aria-hidden className="w-9 shrink-0 select-none text-right text-[10px] tabular-nums text-faint">
              #{s.frame}
            </span>
            <pre className="m-0 min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-[12px]">
              <span className="sr-only select-none">
                frame {s.frame}, {s.fromA ? 'client' : 'server'}:{' '}
              </span>
              {texts[i]}
            </pre>
          </div>
        ))}
      </div>
    </div>
  )
}
