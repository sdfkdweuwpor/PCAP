// Mode B — "What Is This Line Saying?": highlight one packet, choose its literal meaning.

import { KB, type Kind } from '../knowledge'
import type { ChoiceQuestion } from '../types'
import { choice, confusableStatements, GenCtx, notNull, tierFor, type Generator } from './context'

const TEACHABLE: Kind[] = [
  'tcp-syn',
  'tcp-synack',
  'tcp-hs-ack',
  'tcp-fin',
  'tcp-rst-closed',
  'tcp-rst',
  'dns-query',
  'dns-answer',
  'dns-nxdomain',
  'http-request',
  'http-ok',
  'http-notfound',
  'http-unauth',
  'tls-ch',
  'tls-sh',
  'tls-appdata',
  'dhcp-discover',
  'dhcp-offer',
  'dhcp-request',
  'dhcp-ack',
  'arp-request',
  'arp-reply',
  'arp-gratuitous',
  'icmp-echo-req',
  'icmp-echo-reply',
  'icmp-unreach',
  'ftp-banner',
  'ftp-user',
  'ftp-pass',
  'ftp-331',
  'ftp-230',
  'ftp-530',
  'ssh-banner',
  'ntp-client',
]

export function saysQuestion(ctx: GenCtx, no: number, idPrefix = 'says'): ChoiceQuestion | null {
  const kind = ctx.kindOf(no)
  const info = KB[kind]
  if (!info.confusables.length) return null
  return choice(
    ctx,
    {
      id: `${idPrefix}.${kind}:${no}`,
      mode: 'says',
      tier: tierFor(kind),
      concept: info.concept,
      prompt: `Packet #${no} is highlighted. What is this line saying?`,
      hint: hintFor(kind),
      explanation: ctx.explain(no),
      highlight: [{ packet: no }],
      focusPacket: no,
    },
    info.statement,
    confusableStatements(kind),
  )
}

function hintFor(kind: Kind): string {
  if (kind.startsWith('tcp')) return 'Look at the TCP flags in the Info column and the details tree.'
  if (kind.startsWith('dns')) return 'Is it a query or a response? Check the flags and the reply code.'
  if (kind.startsWith('http')) return 'Requests start with a method; responses start with HTTP/1.x and a status code.'
  if (kind.startsWith('tls')) return 'Expand the TLS layer and read the handshake or record type.'
  if (kind.startsWith('dhcp')) return 'Option 53 (DHCP Message Type) names the step.'
  if (kind.startsWith('arp')) return 'Check the ARP opcode and compare the sender and target IPs.'
  if (kind.startsWith('icmp')) return 'The ICMP type number tells you what kind of message it is.'
  if (kind.startsWith('ftp')) return 'Read the command or the 3-digit reply code at the start of the line.'
  return 'Expand the top protocol in the details pane.'
}

export const saysGenerators: Generator[] = [
  {
    id: 'says.kinds',
    mode: 'says',
    needs: 'any recognisable packet type',
    generate(ctx) {
      const out: (ChoiceQuestion | null)[] = []
      for (const k of TEACHABLE) {
        const ps = ctx.of(k)
        if (!ps.length) continue
        // One question per kind; prefer an early example (usually the clearest).
        out.push(saysQuestion(ctx, ps[0].no))
      }
      return out.filter(notNull).slice(0, 10)
    },
  },
]
