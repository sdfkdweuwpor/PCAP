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

  const th = (k: SortKey, label: string) => (
    <th className="px-2 py-1.5 text-left">
      <button className={`uppercase tracking-wide ${sort === k ? 'text-accent' : ''}`} onClick={() => setSort(k)} aria-sort={sort === k ? 'descending' : 'none'}>
        {label}
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

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-2 border-b border-line bg-panel2 px-3 py-2 text-sm">
        <span className="text-muted">Protocol</span>
        <div className="flex gap-1">
          {protos.map((p) => (
            <button key={p} onClick={() => setProto(p)} className={`rounded px-2 py-0.5 text-xs ${proto === p ? 'bg-accent text-accent-ink' : 'border border-line text-muted'}`}>
              {p}
            </button>
          ))}
        </div>
        <span className="ml-auto text-xs text-muted">{rows.length} conversations</span>
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-auto">
        <table className="w-full min-w-[720px] font-mono text-xs">
          <thead className="sticky top-0 bg-panel2 font-sans text-[11px] font-semibold text-muted">
            <tr>
              {th('id', 'Stream')}
              <th className="px-2 py-1.5 text-left uppercase tracking-wide">App</th>
              <th className="px-2 py-1.5 text-left uppercase tracking-wide">Address A</th>
              <th className="px-2 py-1.5 text-left uppercase tracking-wide">Address B</th>
              {th('packets', 'Packets')}
              {th('bytes', 'Bytes')}
              <th className="px-2 py-1.5 text-left uppercase tracking-wide">A→B / B→A</th>
              {th('start', 'Rel start')}
              {th('duration', 'Duration')}
              <th className="px-2 py-1.5 text-left uppercase tracking-wide">State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id} className="border-b border-line/50 hover:bg-panel3">
                <td className="px-2 py-1">{c.id}</td>
                <td className="px-2 py-1 font-semibold" style={{ color: protoVar(c.app) }}>
                  {c.app}
                </td>
                <td className="px-2 py-1">{ep(c.a)}</td>
                <td className="px-2 py-1">{ep(c.b)}</td>
                <td className="px-2 py-1">{c.packets.length}</td>
                <td className="px-2 py-1">{fmtBytes(c.bytes)}</td>
                <td className="px-2 py-1 text-muted">
                  {fmtBytes(c.bytesAtoB)} / {fmtBytes(c.bytesBtoA)}
                </td>
                <td className="px-2 py-1">{c.start.toFixed(3)}</td>
                <td className="px-2 py-1">{(c.end - c.start).toFixed(3)}</td>
                <td className="px-2 py-1">
                  {c.handshake
                    ? c.handshake.ack
                      ? c.closedBy === 'rst'
                        ? 'reset'
                        : c.closedBy === 'fin'
                          ? 'closed'
                          : 'open'
                      : c.handshake.synAck
                        ? 'half-open'
                        : c.closedBy === 'rst'
                          ? 'refused'
                          : 'SYN only'
                    : '—'}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-sans">
                  <button
                    className="mr-1 rounded border border-line px-1.5 py-0.5 hover:border-accent hover:text-accent"
                    onClick={() => {
                      cap.setFlowConv(c.id)
                      cap.setTab('flow')
                    }}
                  >
                    Flow
                  </button>
                  {(c.proto === 'TCP' || c.proto === 'UDP') && (
                    <button
                      className="mr-1 rounded border border-line px-1.5 py-0.5 hover:border-accent hover:text-accent"
                      onClick={() => {
                        cap.setStreamConv(c.id)
                        cap.setTab('stream')
                      }}
                    >
                      Stream
                    </button>
                  )}
                  <button
                    className="rounded border border-line px-1.5 py-0.5 hover:border-accent hover:text-accent"
                    onClick={() => {
                      cap.setFilter(filterFor(c))
                      cap.setTab('packets')
                    }}
                  >
                    Filter
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
