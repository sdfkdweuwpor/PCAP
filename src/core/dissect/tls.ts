// TLS record layer + handshake parsing (ClientHello SNI / cipher suites, ServerHello chosen suite).

import { hex, TruncatedError, u16, u8 } from '../bytes'
import type { Field } from '../types'
import { add, layer, type DissectCtx } from './tree'

export const TLS_VERSIONS: Record<number, string> = {
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3',
}
const CONTENT_TYPES: Record<number, string> = {
  20: 'Change Cipher Spec',
  21: 'Alert',
  22: 'Handshake',
  23: 'Application Data',
  24: 'Heartbeat',
}
export const HANDSHAKE_TYPES: Record<number, string> = {
  0: 'Hello Request',
  1: 'Client Hello',
  2: 'Server Hello',
  4: 'New Session Ticket',
  8: 'Encrypted Extensions',
  11: 'Certificate',
  12: 'Server Key Exchange',
  13: 'Certificate Request',
  14: 'Server Hello Done',
  15: 'Certificate Verify',
  16: 'Client Key Exchange',
  20: 'Finished',
}
export const CIPHER_SUITES: Record<number, string> = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
  0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
}
const EXT_NAMES: Record<number, string> = {
  0: 'server_name',
  5: 'status_request',
  10: 'supported_groups',
  11: 'ec_point_formats',
  13: 'signature_algorithms',
  16: 'application_layer_protocol_negotiation',
  18: 'signed_certificate_timestamp',
  21: 'padding',
  23: 'extended_master_secret',
  35: 'session_ticket',
  43: 'supported_versions',
  45: 'psk_key_exchange_modes',
  51: 'key_share',
  65281: 'renegotiation_info',
}
const ALERT_DESC: Record<number, string> = {
  0: 'Close Notify',
  10: 'Unexpected Message',
  20: 'Bad Record MAC',
  40: 'Handshake Failure',
  42: 'Bad Certificate',
  45: 'Certificate Expired',
  48: 'Unknown CA',
  70: 'Protocol Version',
  80: 'Internal Error',
  112: 'Unrecognized Name',
}

export const tlsVersionName = (v: number) => TLS_VERSIONS[v] ?? hex(v)
export const cipherName = (c: number) => CIPHER_SUITES[c] ?? `Unknown (${hex(c)})`

export function looksLikeTls(b: Uint8Array, o: number, len: number): boolean {
  return len >= 5 && b[o] >= 20 && b[o] <= 24 && b[o + 1] === 3 && b[o + 2] <= 4
}

export function dissectTls(ctx: DissectCtx, o: number, len: number): void {
  const b = ctx.b
  const end = Math.min(b.length, o + len)
  const l = layer(ctx, 'Transport Layer Security', 'tls', o, end - o)
  ctx.protocol = 'TLS'
  ctx.color = 'tls'
  const facts: NonNullable<typeof ctx.facts.tls> = { contentTypes: [], handshakeTypes: [], recordVersion: '' }
  const infos: string[] = []
  let p = o
  if (!looksLikeTls(b, o, len)) {
    add(l, 'TLS segment data (continuation of an earlier record)', 'tls.segment.data', `${len} bytes`, o, len)
    ctx.info = 'Continuation Data'
    ctx.facts.tls = facts
    return
  }
  while (p + 5 <= end) {
    const ct = b[p]
    const ver = u16(b, p + 1)
    const rlen = u16(b, p + 3)
    if (!CONTENT_TYPES[ct] || b[p + 1] !== 3) break
    const recEnd = Math.min(end, p + 5 + rlen)
    const ctName = CONTENT_TYPES[ct]
    const rec = add(l, `${tlsVersionName(ver)} Record Layer: ${ctName}`, 'tls.record', undefined, p, recEnd - p)
    add(rec, 'Content Type', 'tls.record.content_type', `${ctName} (${ct})`, p, 1)
    add(rec, 'Version', 'tls.record.version', `${tlsVersionName(ver)} (${hex(ver)})`, p + 1, 2)
    add(rec, 'Length', 'tls.record.length', rlen, p + 3, 2)
    facts.contentTypes.push(ctName)
    if (!facts.recordVersion) facts.recordVersion = tlsVersionName(ver)
    const body = p + 5
    if (ct === 22) {
      dissectHandshakes(ctx, rec, body, recEnd, facts, infos)
    } else if (ct === 21) {
      if (recEnd - body === 2) {
        const level = b[body]
        const desc = b[body + 1]
        const msg = add(rec, 'Alert Message', 'tls.alert_message', undefined, body, 2)
        add(msg, 'Level', 'tls.alert_message.level', level === 2 ? 'Fatal (2)' : 'Warning (1)', body, 1)
        add(msg, 'Description', 'tls.alert_message.desc', `${ALERT_DESC[desc] ?? desc} (${desc})`, body + 1, 1)
        facts.alert = ALERT_DESC[desc] ?? `Alert ${desc}`
        infos.push(`Alert (Level: ${level === 2 ? 'Fatal' : 'Warning'}, Description: ${facts.alert})`)
      } else {
        add(rec, 'Alert Message', 'tls.alert_message', 'Encrypted Alert', body, recEnd - body)
        infos.push('Encrypted Alert')
      }
    } else if (ct === 20) {
      add(rec, 'Change Cipher Spec Message', 'tls.change_cipher_spec', undefined, body, recEnd - body)
      infos.push('Change Cipher Spec')
    } else if (ct === 23) {
      add(rec, 'Encrypted Application Data', 'tls.app_data', `${recEnd - body} bytes`, body, recEnd - body)
      infos.push('Application Data')
    } else {
      add(rec, 'Data', 'tls.data', undefined, body, recEnd - body)
      infos.push(ctName)
    }
    p = p + 5 + rlen
  }
  ctx.facts.tls = facts
  const v = facts.supportedVersions?.includes('TLS 1.3') && facts.handshakeTypes.includes('Server Hello')
    ? 'TLS 1.3'
    : facts.helloVersion && !facts.handshakeTypes.includes('Client Hello')
      ? facts.helloVersion
      : facts.recordVersion
  ctx.protocol = v === 'TLS 1.3' ? 'TLSv1.3' : v === 'TLS 1.2' ? 'TLSv1.2' : v === 'TLS 1.0' ? 'TLSv1' : v === 'TLS 1.1' ? 'TLSv1.1' : 'TLS'
  ctx.info = dedupeRuns(infos).join(', ')
  if (facts.alert && facts.alert !== 'Close Notify') ctx.color = 'error'
}

function dedupeRuns(xs: string[]): string[] {
  const out: string[] = []
  for (const x of xs) if (out[out.length - 1] !== x) out.push(x)
  return out
}

function dissectHandshakes(
  ctx: DissectCtx,
  rec: Field,
  body: number,
  recEnd: number,
  facts: NonNullable<DissectCtx['facts']['tls']>,
  infos: string[],
): void {
  const b = ctx.b
  let p = body
  while (p + 4 <= recEnd) {
    const ht = b[p]
    const hlen = (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]
    const name = HANDSHAKE_TYPES[ht]
    // A large Hello or Certificate often continues into the next TCP segment (or record). Those are parsed as far
    // as the bytes go; any other message that overruns its record is really encrypted data that happens to look
    // like a header.
    const overruns = p + 4 + hlen > recEnd
    const splittable = (ht === 1 || ht === 2) ? b[p + 4] === 3 && hlen < 0x10000 : ht === 11 && hlen < 0x100000
    // After ChangeCipherSpec handshake messages are encrypted and look like garbage.
    if (!name || (overruns && !splittable) || facts.contentTypes.includes('Change Cipher Spec')) {
      add(rec, 'Handshake Protocol: Encrypted Handshake Message', 'tls.handshake.encrypted', undefined, p, recEnd - p)
      infos.push('Encrypted Handshake Message')
      return
    }
    const hs = add(rec, `Handshake Protocol: ${name}${overruns ? ' [continues in next segment]' : ''}`, 'tls.handshake', undefined, p, Math.min(4 + hlen, recEnd - p))
    add(hs, 'Handshake Type', 'tls.handshake.type', `${name} (${ht})`, p, 1)
    add(hs, 'Length', 'tls.handshake.length', hlen, p + 1, 3)
    facts.handshakeTypes.push(name)
    const hb = p + 4
    const hEnd = Math.min(hb + hlen, recEnd)
    if (ht === 1 || ht === 2) {
      // Reads are bounded by the message end so a truncated Hello stops cleanly instead of reading the next record.
      const b = ctx.b.subarray(0, hEnd)
      try {
        const ver = u16(b, hb)
        add(hs, 'Version', 'tls.handshake.version', `${tlsVersionName(ver)} (${hex(ver)})`, hb, 2)
        add(hs, 'Random', 'tls.handshake.random', 'random bytes (32)', hb + 2, 32)
        let q = hb + 34
        const sidLen = u8(b, q)
        add(hs, 'Session ID Length', 'tls.handshake.session_id_length', sidLen, q, 1)
        if (sidLen) add(hs, 'Session ID', 'tls.handshake.session_id', `${sidLen} bytes`, q + 1, sidLen)
        q += 1 + sidLen
        facts.helloVersion = tlsVersionName(ver)
        if (ht === 1) {
          const csLen = u16(b, q)
          const suites: string[] = []
          const cs = add(hs, `Cipher Suites (${csLen / 2} suites)`, 'tls.handshake.ciphersuites', undefined, q, 2 + csLen)
          for (let i = 0; i + 2 <= csLen && q + 4 + i <= hEnd; i += 2) {
            const c = u16(b, q + 2 + i)
            if ((c & 0x0f0f) === 0x0a0a) continue // GREASE
            suites.push(cipherName(c))
            add(cs, 'Cipher Suite', 'tls.handshake.ciphersuite', `${cipherName(c)} (${hex(c)})`, q + 2 + i, 2)
          }
          facts.cipherSuites = suites
          q += 2 + csLen
          const cmLen = u8(b, q)
          add(hs, 'Compression Methods Length', 'tls.handshake.comp_methods_length', cmLen, q, 1)
          q += 1 + cmLen
        } else {
          const c = u16(b, q)
          facts.chosenCipher = cipherName(c)
          add(hs, 'Cipher Suite', 'tls.handshake.ciphersuite', `${cipherName(c)} (${hex(c)})`, q, 2)
          add(hs, 'Compression Method', 'tls.handshake.comp_method', b[q + 2], q + 2, 1)
          q += 3
        }
        if (q + 2 <= hEnd) {
          const extLen = u16(b, q)
          add(hs, 'Extensions Length', 'tls.handshake.extensions_length', extLen, q, 2)
          q += 2
          const extEnd = Math.min(hEnd, q + extLen)
          while (q + 4 <= extEnd) {
            const et = u16(b, q)
            const el = u16(b, q + 2)
            if ((et & 0x0f0f) === 0x0a0a) {
              q += 4 + el
              continue
            }
            const en = EXT_NAMES[et] ?? `Unknown type ${et}`
            const ext = add(hs, `Extension: ${en} (len=${el})`, 'tls.handshake.extension', undefined, q, 4 + el)
            add(ext, 'Type', 'tls.handshake.extension.type', `${en} (${et})`, q, 2)
            add(ext, 'Length', 'tls.handshake.extension.len', el, q + 2, 2)
            const d = q + 4
            if (et === 0 && el >= 5) {
              const nameLen = u16(b, d + 3)
              let sni = ''
              for (let i = 0; i < nameLen && d + 5 + i < hEnd; i++) sni += String.fromCharCode(b[d + 5 + i])
              add(ext, 'Server Name Indication extension', 'tls.handshake.extensions_server_name_list', undefined, d, el)
              if (d + 5 + nameLen <= hEnd) {
                add(ext, 'Server Name', 'tls.handshake.extensions_server_name', sni, d + 5, nameLen)
                facts.sni = sni
                ext.name = `Extension: server_name (len=${el}) name=${sni}`
              } else {
                // Never report half a hostname: the rest is in the next segment.
                add(ext, 'Server Name [truncated]', 'tls.handshake.extensions_server_name.truncated', `${sni}…`, d + 5, hEnd - d - 5)
              }
            } else if (et === 43) {
              const vers: string[] = []
              if (ht === 1) {
                const n = b[d]
                for (let i = 0; i < n; i += 2) {
                  const v = u16(b, d + 1 + i)
                  if ((v & 0x0f0f) !== 0x0a0a) vers.push(tlsVersionName(v))
                }
              } else vers.push(tlsVersionName(u16(b, d)))
              add(ext, ht === 1 ? 'Supported Versions' : 'Supported Version', 'tls.handshake.extensions.supported_version', vers.join(', '), d, el)
              facts.supportedVersions = vers
            } else if (et === 16 && el > 2) {
              const protos: string[] = []
              let r = d + 2
              while (r < d + el && r < hEnd) {
                const pl = b[r]
                let s = ''
                for (let i = 0; i < pl; i++) s += String.fromCharCode(b[r + 1 + i])
                protos.push(s)
                r += 1 + pl
              }
              add(ext, 'ALPN Protocols', 'tls.handshake.extensions_alpn_str', protos.join(', '), d, el)
            }
            q += 4 + el
          }
        }
      } catch (e) {
        if (!(e instanceof TruncatedError)) throw e
        add(hs, '[message continues in the next segment]', 'tls.handshake.truncated', undefined, hEnd, 0)
      }
      infos.push(ht === 1 && facts.sni ? `Client Hello (SNI=${facts.sni})` : name)
    } else {
      if (hlen) add(hs, name === 'Certificate' ? 'Certificates' : 'Body', 'tls.handshake.body', `${hlen} bytes${overruns ? ` (${hEnd - hb} in this segment)` : ''}`, hb, hEnd - hb)
      infos.push(name)
    }
    if (overruns) return
    p = hb + hlen
  }
}
