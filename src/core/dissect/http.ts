// HTTP/1.x request/response headers, including Basic auth detection.

import { ascii } from '../bytes'
import { add, layer, type DissectCtx } from './tree'

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE']

export function looksLikeHttp(b: Uint8Array, o: number, len: number): boolean {
  if (len < 4) return false
  const head = ascii(b, o, Math.min(len, 8))
  return head.startsWith('HTTP/') || METHODS.some((m) => head.startsWith(m + ' '))
}

export function decodeBase64(s: string): string | null {
  try {
    return atob(s.trim())
  } catch {
    return null
  }
}

export function dissectHttp(ctx: DissectCtx, o: number, len: number): void {
  const b = ctx.b
  const text = ascii(b, o, len)
  const l = layer(ctx, 'Hypertext Transfer Protocol', 'http', o, len)
  ctx.protocol = 'HTTP'
  ctx.color = 'http'
  if (!looksLikeHttp(b, o, len)) {
    add(l, 'Continuation or non-HTTP traffic', 'http.continuation', `${len} bytes`, o, len)
    ctx.info = 'Continuation'
    ctx.facts.http = { isRequest: false, version: '' }
    return
  }
  const headerEnd = text.indexOf('\r\n\r\n')
  const headBlock = headerEnd >= 0 ? text.slice(0, headerEnd) : text
  const lines = headBlock.split('\r\n')
  let p = o
  const first = lines[0]
  const isRequest = !first.startsWith('HTTP/')
  const facts: NonNullable<typeof ctx.facts.http> = { isRequest, version: '' }
  const firstNode = add(l, first + '\\r\\n', isRequest ? 'http.request.line' : 'http.response.line', undefined, p, first.length + 2)
  const [a, bpart, ...rest] = first.split(' ')
  if (isRequest) {
    facts.method = a
    facts.uri = bpart
    facts.version = rest.join(' ')
    add(firstNode, 'Request Method', 'http.request.method', a, p, a.length)
    add(firstNode, 'Request URI', 'http.request.uri', bpart, p + a.length + 1, bpart?.length ?? 0)
    add(firstNode, 'Request Version', 'http.request.version', facts.version, p + a.length + 2 + (bpart?.length ?? 0), facts.version.length)
  } else {
    facts.version = a
    facts.status = parseInt(bpart, 10)
    facts.reason = rest.join(' ')
    add(firstNode, 'Response Version', 'http.response.version', a, p, a.length)
    add(firstNode, 'Status Code', 'http.response.code', bpart, p + a.length + 1, bpart?.length ?? 0, facts.status >= 400 ? { warn: true } : {})
    add(firstNode, 'Response Phrase', 'http.response.phrase', facts.reason, p + a.length + 2 + (bpart?.length ?? 0), facts.reason.length)
  }
  p += first.length + 2
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':')
    const name = idx > 0 ? line.slice(0, idx) : line
    const value = idx > 0 ? line.slice(idx + 1).trim() : ''
    const lname = name.toLowerCase()
    const keyMap: Record<string, string> = {
      host: 'http.host',
      'user-agent': 'http.user_agent',
      'content-type': 'http.content_type',
      'content-length': 'http.content_length_header',
      authorization: 'http.authorization',
      cookie: 'http.cookie',
      'set-cookie': 'http.set_cookie',
      server: 'http.server',
      location: 'http.location',
      referer: 'http.referer',
      connection: 'http.connection',
      accept: 'http.accept',
    }
    const hdr = add(l, `${name}: ${value}\\r\\n`, keyMap[lname] ?? 'http.header', undefined, p, line.length + 2)
    if (lname === 'host') facts.host = value
    if (lname === 'user-agent') facts.userAgent = value
    if (lname === 'content-type') facts.contentType = value
    if (lname === 'authorization') {
      facts.authorization = value
      hdr.warn = true
      const m = /^Basic\s+(\S+)/i.exec(value)
      if (m) {
        hdr.secret = true
        const dec = decodeBase64(m[1])
        const valStart = p + line.indexOf(m[1])
        add(hdr, 'Credentials', 'http.authbasic', dec ?? '(invalid base64)', valStart, m[1].length, { secret: true, warn: true })
        if (dec) {
          const [user, ...pw] = dec.split(':')
          ctx.facts.creds = { proto: 'HTTP', kind: 'basic', user, secret: pw.join(':'), wire: m[1] }
          ctx.color = 'cleartext'
        }
      }
    }
    p += line.length + 2
  }
  if (headerEnd >= 0) {
    add(l, '\\r\\n', 'http.end_of_headers', undefined, p, 2)
    p += 2
    const bodyLen = o + len - p
    if (bodyLen > 0) {
      const ct = facts.contentType?.split(';')[0] ?? 'data'
      add(l, `File Data: ${bodyLen} bytes`, 'http.file_data', ct, p, bodyLen)
    }
  }
  ctx.facts.http = facts
  if (isRequest) ctx.info = `${facts.method} ${facts.uri} ${facts.version}`
  else {
    const ct = facts.contentType ? `  (${facts.contentType.split(';')[0]})` : ''
    ctx.info = `${facts.version} ${facts.status} ${facts.reason}${ct}`
    if ((facts.status ?? 0) >= 400) ctx.color = 'error'
  }
}
