import type { ColorRule, Field, PacketFacts } from '../types'

/** Mutable state threaded through the dissector chain for one packet. */
export interface DissectCtx {
  b: Uint8Array
  layers: Field[]
  facts: PacketFacts
  src: string
  dst: string
  protocol: string
  info: string
  color: ColorRule
  /** TCP initial sequence numbers keyed by flowKey(src,sport,dst,dport). Enables relative seq/ack. */
  tcpIsn?: Map<string, number>
  /** Bytes of the frame the capture did not keep (snaplen), so declared lengths beyond the data can be trusted. */
  missing?: number
}

export function field(
  name: string,
  key: string | undefined,
  value: string | number | undefined,
  offset: number,
  length: number,
  extra: Partial<Field> = {},
): Field {
  const f: Field = { name, offset, length, ...extra }
  if (key) f.key = key
  if (value !== undefined) f.value = String(value)
  return f
}

/** Appends a child to a node and returns the child for chaining. */
export function add(
  parent: Field,
  name: string,
  key: string | undefined,
  value: string | number | undefined,
  offset: number,
  length: number,
  extra: Partial<Field> = {},
): Field {
  const f = field(name, key, value, offset, length, extra)
  ;(parent.children ??= []).push(f)
  return f
}

export function layer(ctx: DissectCtx, name: string, key: string, offset: number, length: number): Field {
  const f: Field = { name, key, offset, length, children: [] }
  ctx.layers.push(f)
  if (!ctx.facts.protos.includes(key)) ctx.facts.protos.push(key)
  return f
}

/** Adds a "Data" layer for unrecognized payload bytes. */
export function dataLayer(ctx: DissectCtx, offset: number, length: number, label = 'Data'): void {
  if (length <= 0) return
  const l = layer(ctx, `${label} (${length} bytes)`, 'data', offset, length)
  let preview = ''
  for (let i = offset; i < Math.min(offset + 24, offset + length); i++) preview += ctx.b[i].toString(16).padStart(2, '0')
  add(l, 'Data', 'data.data', preview + (length > 24 ? '…' : ''), offset, length)
  add(l, '[Length]', 'data.len', length, offset, 0)
}

export function flowKey(src: string, sport: number, dst: string, dport: number): string {
  return `${src}:${sport}>${dst}:${dport}`
}

/** Standard bit-field rendering "..1. .... = Label: Set". */
export function bitLine(value: number, mask: number, bits: number, label: string, on = 'Set', off = 'Not set'): string {
  let s = ''
  for (let i = bits - 1; i >= 0; i--) {
    const bit = 1 << i
    s += mask & bit ? (value & bit ? '1' : '0') : '.'
    if (i % 4 === 0 && i !== 0) s += ' '
  }
  return `${s} = ${label}: ${value & mask ? on : off}`
}
