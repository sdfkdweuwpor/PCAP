// Statistics → Conversations: per-stream packets, bytes, duration; jump to flow / stream / filter.

import { useMemo, useState } from 'react'
import type { Conversation } from '../../core/types'
import { useCapture } from '../../store/capture'
import { protoVar } from '../colors'

type SortKey = 'id' | 'packets' | 'bytes' | 'duration' | 'start'

const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`)
const ep = (e: Conversation['a']) => (e.port !== undefined ? `${e.addr}:${e.port}` : e.addr)

export function ConversationsTable() {
  const index = useCapture((s) => s.index)!
  const [sort, setSort] = useState<SortKey>('id')
  const [proto, setProto] = useState<string>('all')
  const protos = useMemo(() => ['all', ...new Set(index.conversations.map((c) => c.proto))], [index])

  const rows = useMemo(() => {
    const list = index.conversations.filter((c) => proto === 'all' || c.proto === proto)
    const key = (c: Conversation) =>
      sort === 'packets' ? -c.packets.length : sort === 'bytes' ? -c.bytes : sort === 'duration' ? -(c.end - c.start) : sort === 'start' ? c.start : c.id
    return [...list].sort((a, b) => key(a) - key(b)).slice(0, 2000)
  }, [index, sort, proto])

  const thc = 'px-2 py-1 text-left text-[10.5px] font-normal uppercase tracking-[0.12em] text-faint'
  const th = (k: SortKey, label: string) => (
    <th className={thc}>
      <button className={`uppercase tracking-[0.12em] hover:text-fg ${sort === k ? 'text-accent' : ''}`} onClick={() => setSort(k)} aria-sort={sort === k ? 'descending' : 'none'}>
        {label}
        {sort === k && <span aria-hidden> ↓</span>}
      </button>
    </th>
  )

  const cap = useCapture.getState()
  const filterFor = (c: Conversation) =>
    c.proto === 'TCP' || c.proto === 'UDP'
      ? `ip.addr == ${c.a.addr} && ip.addr == ${c.b.addr} && ${c.proto.toLowerCase()}.port == ${c.a.port} && ${c.proto.toLowerCase()}.port == ${c.b.port}`
      : c.proto === 'ARP'
        ? `arp`
        : `ip.addr == ${c.a.addr} && ip.addr == ${c.b.addr}`

  const state = (c: Conversation): { text: string; tone: string } => {
    if (!c.handshake) return { text: '—', tone: 'text-faint' }
    if (c.handshake.ack) {
      if (c.closedBy === 'rst') return { text: 'reset', tone: 'text-bad' }
      if (c.closedBy === 'fin') return { text: 'closed', tone: 'text-muted' }
      return { text: 'open', tone: 'text-good' }
    }
    if (c.handshake.synAck) return { text: 'half-open', tone: 'text-warn' }
    if (c.closedBy === 'rst') return { text: 'refused', tone: 'text-bad' }
    return { text: 'SYN only', tone: 'text-warn' }
  }
  const link = 'hover:text-accent'
  const dot = (
    <span aria-hidden className="px-1 text-faint">
      ·
    </span>
  )

  return (
    <div className="flex h-full min-h-0 flex-col text-[12px]">
      <div className="flex items-center gap-2 border-b border-line bg-panel2 px-2 py-1 text-[11px]">
        <span className="text-[10.5px] uppercase tracking-[0.12em] text-faint">proto</span>
        <div className="flex flex-wrap gap-x-1">
          {protos.map((p) => (
            <button key={p} onClick={() => setProto(p)} aria-pressed={proto === p} className={`px-1 ${proto === p ? 'bg-accent text-accent-ink' : 'text-muted hover:text-fg'}`}>
              [{p}]
            </button>
          ))}
        </div>
        <span className="ml-auto tabular-nums text-faint">{rows.length} conversations</span>
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-auto">
        <table className="w-full min-w-[720px] tabular-nums">
          <thead className="sticky top-0 bg-panel2">
            <tr>
              {th('id', 'Stream')}
              <th className={thc}>App</th>
              <th className={thc}>Address A</th>
              <th className={thc}>Address B</th>
              {th('packets', 'Packets')}
              {th('bytes', 'Bytes')}
              <th className={thc}>A→B / B→A</th>
              {th('start', 'Rel start')}
              {th('duration', 'Duration')}
              <th className={thc}>State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => {
              const st = state(c)
              return (
                <tr key={c.id} className="h-[22px] border-b border-line/50 hover:bg-panel3">
                  <td className="px-2">{c.id}</td>
                  <td className="px-2 font-semibold" style={{ color: protoVar(c.app) }}>
                    {c.app}
                  </td>
                  <td className="px-2">{ep(c.a)}</td>
                  <td className="px-2">{ep(c.b)}</td>
                  <td className="px-2">{c.packets.length}</td>
                  <td className="px-2">{fmtBytes(c.bytes)}</td>
                  <td className="px-2 text-muted">
                    {fmtBytes(c.bytesAtoB)} / {fmtBytes(c.bytesBtoA)}
                  </td>
                  <td className="px-2">{c.start.toFixed(3)}</td>
                  <td className="px-2">{(c.end - c.start).toFixed(3)}</td>
                  <td className={`px-2 ${st.tone}`}>{st.text}</td>
                  <td className="whitespace-nowrap px-2 text-muted">
                    <button
                      className={link}
                      onClick={() => {
                        cap.setFlowConv(c.id)
                        cap.setTab('flow')
                      }}
                    >
                      flow
                    </button>
                    {(c.proto === 'TCP' || c.proto === 'UDP') && (
                      <>
                        {dot}
                        <button
                          className={link}
                          onClick={() => {
                            cap.setStreamConv(c.id)
                            cap.setTab('stream')
                          }}
                        >
                          stream
                        </button>
                      </>
                    )}
                    {dot}
                    <button
                      className={link}
                      onClick={() => {
                        cap.setFilter(filterFor(c))
                        cap.setTab('packets')
                      }}
                    >
                      filter
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
