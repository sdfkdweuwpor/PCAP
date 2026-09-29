// Application protocols: DHCP, FTP/Telnet/SMTP/POP3/IMAP command lines, SSH banner, NTP, SNMP.

import { ascii, hex, ipv4, mac, u16, u32, u8 } from '../bytes'
import type { PacketFacts } from '../types'
import { decodeBase64 } from './http'
import { add, layer, type DissectCtx } from './tree'

// ---------------------------------------------------------------- DHCP

export const DHCP_TYPES: Record<number, string> = {
  1: 'Discover',
  2: 'Offer',
  3: 'Request',
  4: 'Decline',
  5: 'ACK',
  6: 'NAK',
  7: 'Release',
  8: 'Inform',
}
const DHCP_OPTS: Record<number, string> = {
  1: 'Subnet Mask',
  3: 'Router',
  6: 'Domain Name Server',
  12: 'Host Name',
  15: 'Domain Name',
  50: 'Requested IP Address',
  51: 'IP Address Lease Time',
  53: 'DHCP Message Type',
  54: 'DHCP Server Identifier',
  55: 'Parameter Request List',
  57: 'Maximum DHCP Message Size',
  58: 'Renewal Time Value',
  59: 'Rebinding Time Value',
  61: 'Client identifier',
  255: 'End',
}

export function dissectDhcp(ctx: DissectCtx, o: number, len: number): void {
  const b = ctx.b
  const op = u8(b, o)
  const xid = u32(b, o + 4)
  const secs = u16(b, o + 8)
  const flags = u16(b, o + 10)
  const ciaddr = ipv4(b, o + 12)
  const yiaddr = ipv4(b, o + 16)
  const siaddr = ipv4(b, o + 20)
  const giaddr = ipv4(b, o + 24)
  const chaddr = mac(b, o + 28)
  const l = layer(ctx, 'Dynamic Host Configuration Protocol', 'dhcp', o, len)
  add(l, 'Message type', 'dhcp.type', op === 1 ? 'Boot Request (1)' : 'Boot Reply (2)', o, 1)
  add(l, 'Hardware type', 'dhcp.hw.type', 'Ethernet (0x01)', o + 1, 1)
  add(l, 'Hardware address length', 'dhcp.hw.len', u8(b, o + 2), o + 2, 1)
  add(l, 'Hops', 'dhcp.hops', u8(b, o + 3), o + 3, 1)
  add(l, 'Transaction ID', 'dhcp.id', hex(xid, 8), o + 4, 4)
  add(l, 'Seconds elapsed', 'dhcp.secs', secs, o + 8, 2)
  add(l, 'Bootp flags', 'dhcp.flags', `${hex(flags)} (${flags & 0x8000 ? 'Broadcast' : 'Unicast'})`, o + 10, 2)
  add(l, 'Client IP address', 'dhcp.ip.client', ciaddr, o + 12, 4)
  add(l, 'Your (client) IP address', 'dhcp.ip.your', yiaddr, o + 16, 4)
  add(l, 'Next server IP address', 'dhcp.ip.server', siaddr, o + 20, 4)
  add(l, 'Relay agent IP address', 'dhcp.ip.relay', giaddr, o + 24, 4)
  add(l, 'Client MAC address', 'dhcp.hw.mac_addr', chaddr, o + 28, 6)
  add(l, 'Server host name', 'dhcp.server', 'not given', o + 44, 64)
  add(l, 'Boot file name', 'dhcp.file', 'not given', o + 108, 128)
  const facts: NonNullable<PacketFacts['dhcp']> = { msgType: op === 1 ? 'Request' : 'Reply', xid, clientMac: chaddr, yiaddr, ciaddr }
  let p = o + 236
  if (p + 4 <= o + len && u32(b, p) === 0x63825363) {
    add(l, 'Magic cookie', 'dhcp.cookie', 'DHCP', p, 4)
    p += 4
    const end = o + len
    while (p < end) {
      const code = b[p]
      if (code === 0) {
        p++
        continue
      }
      if (code === 255) {
        add(l, 'Option: (255) End', 'dhcp.option.end', 255, p, 1)
        break
      }
      if (p + 1 >= end) break
      const olen = b[p + 1]
      const d = p + 2
      if (d + olen > end) break
      const name = DHCP_OPTS[code] ?? 'Unknown'
      let value = `${olen} bytes`
      let key = `dhcp.option.${code}`
      if (code === 53 && olen >= 1) {
        facts.msgType = DHCP_TYPES[b[d]] ?? `Type ${b[d]}`
        value = `${facts.msgType} (${b[d]})`
        key = 'dhcp.option.dhcp'
      } else if ((code === 50 || code === 54 || code === 1 || code === 3) && olen >= 4) {
        value = ipv4(b, d)
        if (code === 50) {
          facts.requestedIp = value
          key = 'dhcp.option.requested_ip_address'
        } else if (code === 54) {
          facts.serverId = value
          key = 'dhcp.option.dhcp_server_id'
        } else if (code === 3) {
          facts.router = value
          key = 'dhcp.option.router'
        } else key = 'dhcp.option.subnet_mask'
      } else if (code === 6) {
        const list: string[] = []
        for (let i = 0; i + 4 <= olen; i += 4) list.push(ipv4(b, d + i))
        facts.dnsServers = list
        value = list.join(', ')
        key = 'dhcp.option.domain_name_server'
      } else if (code === 12 || code === 15) {
        value = ascii(b, d, olen)
        if (code === 12) {
          facts.hostname = value
          key = 'dhcp.option.hostname'
        }
      } else if ((code === 51 || code === 58 || code === 59) && olen === 4) {
        const secs2 = u32(b, d)
        value = `${secs2} s`
        if (code === 51) {
          facts.leaseTime = secs2
          key = 'dhcp.option.ip_address_lease_time'
        }
      }
      const opt = add(l, `Option: (${code}) ${name}`, key, value, p, 2 + olen)
      add(opt, 'Length', 'dhcp.option.length', olen, p + 1, 1)
      p = d + olen
    }
  }
  ctx.facts.dhcp = facts
  ctx.protocol = 'DHCP'
  ctx.color = 'dhcp'
  ctx.info = `DHCP ${facts.msgType}${' '.repeat(Math.max(1, 9 - facts.msgType.length))}- Transaction ID ${hex(xid, 8)}`
}

// ---------------------------------------------------------------- Line-based text protocols

type TextProto = 'FTP' | 'SMTP' | 'POP' | 'IMAP' | 'Telnet'
const KEYS: Record<TextProto, string> = { FTP: 'ftp', SMTP: 'smtp', POP: 'pop', IMAP: 'imap', Telnet: 'telnet' }
const NAMES: Record<TextProto, string> = {
  FTP: 'File Transfer Protocol (FTP)',
  SMTP: 'Simple Mail Transfer Protocol',
  POP: 'Post Office Protocol',
  IMAP: 'Internet Message Access Protocol',
  Telnet: 'Telnet',
}

export function dissectTextProto(ctx: DissectCtx, proto: TextProto, o: number, len: number, isRequest: boolean): void {
  const b = ctx.b
  const key = KEYS[proto]
  const l = layer(ctx, NAMES[proto], key, o, len)
  ctx.protocol = proto === 'POP' ? 'POP' : proto
  ctx.color = 'tcp'
  if (proto === 'Telnet') {
    // Strip IAC negotiation sequences (0xFF cmd opt) for display.
    let text = ''
    let p = o
    const end = o + len
    const negs: string[] = []
    while (p < end) {
      if (b[p] === 0xff && p + 2 < end) {
        const cmd = b[p + 1]
        const cmdName = cmd === 251 ? 'Will' : cmd === 252 ? "Won't" : cmd === 253 ? 'Do' : cmd === 254 ? "Don't" : `Cmd ${cmd}`
        negs.push(`${cmdName} ${b[p + 2]}`)
        add(l, `${cmdName} option ${b[p + 2]}`, 'telnet.cmd', undefined, p, 3)
        p += 3
        continue
      }
      text += String.fromCharCode(b[p])
      p++
    }
    if (text) add(l, 'Data', 'telnet.data', JSON.stringify(text).slice(1, -1), o + (len - text.length), text.length)
    ctx.facts.app = { proto: 'Telnet', line: text, isRequest }
    ctx.info = text ? `Telnet Data …` : `Telnet ${negs.join(', ')}`
    return
  }
  const text = ascii(b, o, len)
  const lines = text.split('\r\n').filter((x, i, arr) => x.length || i < arr.length - 1)
  let p = o
  let firstFacts: NonNullable<PacketFacts['app']> | undefined
  for (const line of lines) {
    if (!line.length) {
      p += 2
      continue
    }
    const node = add(l, `${line}\\r\\n`, `${key}.${isRequest ? 'request' : 'response'}`, undefined, p, Math.min(line.length + 2, o + len - p))
    const f: NonNullable<PacketFacts['app']> = { proto, line, isRequest }
    if (isRequest) {
      let cmdLine = line
      let tagLen = 0
      const tagEnd = proto === 'IMAP' ? line.indexOf(' ') : -1
      if (tagEnd > 0) {
        tagLen = tagEnd + 1
        add(node, 'Request Tag', 'imap.request_tag', line.slice(0, tagEnd), p, tagEnd)
        cmdLine = line.slice(tagEnd + 1)
      }
      const sp = cmdLine.indexOf(' ')
      const cmd = (sp < 0 ? cmdLine : cmdLine.slice(0, sp)).toUpperCase()
      const arg = sp < 0 ? '' : cmdLine.slice(sp + 1)
      f.command = cmd
      f.arg = arg
      add(node, 'Request command', `${key}.request.command`, cmd, p + tagLen, cmd.length)
      if (arg) {
        const isPass = cmd === 'PASS' || (proto === 'IMAP' && cmd === 'LOGIN') || (proto === 'SMTP' && cmd === 'AUTH' && /^PLAIN\s/i.test(arg))
        add(node, 'Request arg', `${key}.request.arg`, arg, p + tagLen + cmd.length + 1, arg.length, isPass ? { secret: true, warn: true } : {})
      }
      detectCreds(ctx, proto, cmd, arg)
    } else {
      const m = /^(\d{3})([ -])(.*)$/.exec(line)
      if (m && (proto === 'FTP' || proto === 'SMTP')) {
        f.code = parseInt(m[1], 10)
        add(node, 'Response code', `${key}.response.code`, m[1], p, 3, f.code >= 400 ? { warn: true } : {})
        add(node, 'Response arg', `${key}.response.arg`, m[3], p + 4, m[3].length)
      } else if (proto === 'POP') {
        const ok = line.startsWith('+OK')
        f.command = ok ? '+OK' : line.startsWith('-ERR') ? '-ERR' : ''
        if (f.command) add(node, 'Response indicator', 'pop.response.indicator', f.command, p, f.command.length, ok ? {} : { warn: true })
      } else if (proto === 'IMAP') {
        const mm = /^(\S+) (OK|NO|BAD|PREAUTH|BYE)\b/.exec(line)
        if (mm) {
          f.command = mm[2]
          add(node, 'Response status', 'imap.response.status', mm[2], p + mm[1].length + 1, mm[2].length, mm[2] === 'OK' ? {} : { warn: true })
        }
      }
    }
    firstFacts ??= f
    p += line.length + 2
  }
  if (firstFacts) {
    ctx.facts.app = firstFacts
    const { command, code } = firstFacts
    if (isRequest && (command === 'PASS' || (proto === 'IMAP' && command === 'LOGIN') || ctx.facts.creds?.secret)) ctx.color = 'cleartext'
    if (!isRequest && ((code ?? 0) >= 500 || command === '-ERR' || command === 'NO')) ctx.color = 'error'
    ctx.info = `${isRequest ? 'Request' : 'Response'}: ${firstFacts.line}`
  } else ctx.info = `${NAMES[proto]}`
}

function detectCreds(ctx: DissectCtx, proto: TextProto, cmd: string, arg: string): void {
  if (!arg) return
  if ((proto === 'FTP' || proto === 'POP') && cmd === 'USER') {
    ctx.facts.creds = { proto, kind: 'user', user: arg }
    ctx.color = 'cleartext'
  } else if ((proto === 'FTP' || proto === 'POP') && cmd === 'PASS') {
    ctx.facts.creds = { proto, kind: 'pass', secret: arg }
    ctx.color = 'cleartext'
  } else if (proto === 'IMAP' && cmd === 'LOGIN') {
    const [user, ...rest] = arg.split(' ')
    ctx.facts.creds = { proto: 'IMAP', kind: 'login', user: user.replace(/"/g, ''), secret: rest.join(' ').replace(/"/g, '') }
    ctx.color = 'cleartext'
  } else if (proto === 'SMTP' && cmd === 'AUTH') {
    const m = /^PLAIN\s+(\S+)/i.exec(arg)
    const dec = m ? decodeBase64(m[1]) : null
    if (dec) {
      const parts = dec.split('\u0000')
      ctx.facts.creds = { proto: 'SMTP', kind: 'login', user: parts[1], secret: parts[2], wire: m![1] }
      ctx.color = 'cleartext'
    }
  }
}

// ---------------------------------------------------------------- SSH

export function dissectSsh(ctx: DissectCtx, o: number, len: number): void {
  const b = ctx.b
  const l = layer(ctx, 'SSH Protocol', 'ssh', o, len)
  ctx.protocol = 'SSH'
  ctx.color = 'tcp'
  const head = ascii(b, o, Math.min(len, 255))
  if (head.startsWith('SSH-')) {
    const banner = head.split('\r\n')[0].split('\n')[0]
    add(l, 'Protocol', 'ssh.protocol', banner, o, banner.length)
    ctx.facts.ssh = { banner }
    ctx.info = `Protocol (${banner})`
    return
  }
  const plen = len >= 5 ? u32(b, o) : 0
  if (plen > 0 && plen + 4 <= len && b[o + 5] === 20) {
    add(l, 'Packet Length', 'ssh.packet_length', plen, o, 4)
    add(l, 'Message Code', 'ssh.message_code', 'Key Exchange Init (20)', o + 5, 1)
    ctx.info = 'Key Exchange Init'
    return
  }
  add(l, 'Encrypted Packet', 'ssh.encrypted_packet', `${len} bytes`, o, len)
  ctx.info = `Encrypted packet (len=${len})`
}

// ---------------------------------------------------------------- NTP

const NTP_MODES: Record<number, string> = {
  1: 'symmetric active',
  2: 'symmetric passive',
  3: 'client',
  4: 'server',
  5: 'broadcast',
  6: 'control',
}

export function dissectNtp(ctx: DissectCtx, o: number, len: number): void {
  const b = ctx.b
  const f0 = u8(b, o)
  const li = f0 >> 6
  const vn = (f0 >> 3) & 7
  const mode = f0 & 7
  const stratum = u8(b, o + 1)
  const l = layer(ctx, 'Network Time Protocol', 'ntp', o, len)
  const flags = add(l, 'Flags', 'ntp.flags', hex(f0, 2), o, 1)
  add(flags, 'Leap Indicator', 'ntp.flags.li', li, o, 1)
  add(flags, 'Version number', 'ntp.flags.vn', `NTP Version ${vn}`, o, 1)
  add(flags, 'Mode', 'ntp.flags.mode', `${NTP_MODES[mode] ?? mode} (${mode})`, o, 1)
  add(l, 'Peer Clock Stratum', 'ntp.stratum', stratum, o + 1, 1)
  if (len >= 48) {
    add(l, 'Peer Polling Interval', 'ntp.ppoll', u8(b, o + 2), o + 2, 1)
    add(l, 'Root Delay', 'ntp.rootdelay', u32(b, o + 4) / 65536, o + 4, 4)
    add(l, 'Root Dispersion', 'ntp.rootdispersion', u32(b, o + 8) / 65536, o + 8, 4)
    add(l, 'Reference ID', 'ntp.refid', stratum === 1 ? ascii(b, o + 12, 4).replace(/\0/g, '') : ipv4(b, o + 12), o + 12, 4)
    add(l, 'Reference Timestamp', 'ntp.reftime', ntpTime(b, o + 16), o + 16, 8)
    add(l, 'Origin Timestamp', 'ntp.org', ntpTime(b, o + 24), o + 24, 8)
    add(l, 'Receive Timestamp', 'ntp.rec', ntpTime(b, o + 32), o + 32, 8)
    add(l, 'Transmit Timestamp', 'ntp.xmt', ntpTime(b, o + 40), o + 40, 8)
  }
  const modeName = NTP_MODES[mode] ?? `mode ${mode}`
  ctx.facts.ntp = { version: vn, mode, modeName, stratum }
  ctx.protocol = 'NTP'
  ctx.color = 'udp'
  ctx.info = `NTP Version ${vn}, ${modeName}`
}

function ntpTime(b: Uint8Array, o: number): string {
  const sec = u32(b, o)
  if (!sec) return '(0) NULL'
  const unix = sec - 2208988800
  return new Date(unix * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC')
}

// ---------------------------------------------------------------- SNMP (BER basics)

const SNMP_PDUS: Record<number, string> = {
  0xa0: 'get-request',
  0xa1: 'get-next-request',
  0xa2: 'get-response',
  0xa3: 'set-request',
  0xa4: 'trap',
  0xa5: 'getBulkRequest',
  0xa6: 'informRequest',
  0xa7: 'snmpV2-trap',
  0xa8: 'report',
}

function berLen(b: Uint8Array, o: number): { len: number; hdr: number } {
  const first = u8(b, o)
  if (first < 0x80) return { len: first, hdr: 1 }
  const n = first & 0x7f
  let len = 0
  for (let i = 0; i < n; i++) len = (len << 8) | u8(b, o + 1 + i)
  return { len, hdr: 1 + n }
}

export function dissectSnmp(ctx: DissectCtx, o: number, len: number): boolean {
  const b = ctx.b
  if (b[o] !== 0x30) return false
  const seq = berLen(b, o + 1)
  let p = o + 1 + seq.hdr
  if (b[p] !== 0x02) return false
  const vl = berLen(b, p + 1)
  const ver = u8(b, p + 1 + vl.hdr)
  const verStart = p
  p += 1 + vl.hdr + vl.len
  if (b[p] !== 0x04) return false
  const cl = berLen(b, p + 1)
  const commStart = p + 1 + cl.hdr
  const community = ascii(b, commStart, cl.len)
  p = commStart + cl.len
  const pduTag = b[p]
  const pdu = SNMP_PDUS[pduTag] ?? `PDU ${hex(pduTag, 2)}`
  const version = ver === 0 ? 'v1' : ver === 1 ? 'v2c' : ver === 3 ? 'v3' : `v?${ver}`
  const l = layer(ctx, 'Simple Network Management Protocol', 'snmp', o, len)
  add(l, 'version', 'snmp.version', `${version} (${ver})`, verStart, 2 + vl.len)
  add(l, 'community', 'snmp.community', community, commStart, cl.len, { warn: true })
  add(l, 'data', 'snmp.data', pdu, p, o + len - p)
  ctx.facts.snmp = { version, community, pdu }
  ctx.protocol = 'SNMP'
  ctx.color = 'udp'
  ctx.info = `${pdu}`
  return true
}
