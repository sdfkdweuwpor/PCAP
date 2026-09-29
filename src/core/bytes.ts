// Small byte helpers used by the container parser and dissectors.

export class TruncatedError extends Error {
  constructor(what: string) {
    super(`Truncated ${what}`)
    this.name = 'TruncatedError'
  }
}

export function u8(b: Uint8Array, o: number): number {
  if (o >= b.length) throw new TruncatedError(`byte at ${o}`)
  return b[o]
}

export function u16(b: Uint8Array, o: number): number {
  if (o + 2 > b.length) throw new TruncatedError(`u16 at ${o}`)
  return (b[o] << 8) | b[o + 1]
}

export function u32(b: Uint8Array, o: number): number {
  if (o + 4 > b.length) throw new TruncatedError(`u32 at ${o}`)
  return ((b[o] << 24) >>> 0) + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3])
}

export function u16le(b: Uint8Array, o: number): number {
  if (o + 2 > b.length) throw new TruncatedError(`u16 at ${o}`)
  return b[o] | (b[o + 1] << 8)
}

export function u32le(b: Uint8Array, o: number): number {
  if (o + 4 > b.length) throw new TruncatedError(`u32 at ${o}`)
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)) + ((b[o + 3] << 24) >>> 0)
}

export function hex(n: number, width = 4): string {
  return '0x' + n.toString(16).padStart(width, '0')
}

export function mac(b: Uint8Array, o: number): string {
  if (o + 6 > b.length) throw new TruncatedError(`MAC at ${o}`)
  const parts: string[] = []
  for (let i = 0; i < 6; i++) parts.push(b[o + i].toString(16).padStart(2, '0'))
  return parts.join(':')
}

export function ipv4(b: Uint8Array, o: number): string {
  if (o + 4 > b.length) throw new TruncatedError(`IPv4 address at ${o}`)
  return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`
}

/** RFC 5952-ish compressed IPv6 text form. */
export function ipv6(b: Uint8Array, o: number): string {
  if (o + 16 > b.length) throw new TruncatedError(`IPv6 address at ${o}`)
  const groups: number[] = []
  for (let i = 0; i < 8; i++) groups.push((b[o + i * 2] << 8) | b[o + i * 2 + 1])
  // Find the longest run of zero groups (length >= 2) to compress.
  let bestStart = -1
  let bestLen = 0
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++
      continue
    }
    let j = i
    while (j < 8 && groups[j] === 0) j++
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i
      bestLen = j - i
    }
    i = j
  }
  const txt = groups.map((g) => g.toString(16))
  if (bestStart < 0) return txt.join(':')
  const head = txt.slice(0, bestStart).join(':')
  const tail = txt.slice(bestStart + bestLen).join(':')
  return `${head}::${tail}`
}

export function ascii(b: Uint8Array, o: number, len: number): string {
  let s = ''
  const end = Math.min(b.length, o + len)
  for (let i = o; i < end; i++) s += String.fromCharCode(b[i])
  return s
}

/** Printable-ASCII rendering used by the hex pane and for "Data" previews. */
export function printable(c: number): string {
  return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.'
}

/** Returns true if the bytes look like mostly-printable ASCII text. */
export function looksLikeText(b: Uint8Array, o: number, len: number): boolean {
  if (len <= 0) return false
  const end = Math.min(b.length, o + len)
  let ok = 0
  for (let i = o; i < end; i++) {
    const c = b[i]
    if ((c >= 0x20 && c < 0x7f) || c === 0x0d || c === 0x0a || c === 0x09) ok++
  }
  return ok / (end - o) > 0.9
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s.length) return 0
  const counts = new Map<string, number>()
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of counts.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}
