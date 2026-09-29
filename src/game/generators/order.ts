// Mode E — "Put It In Order": drag shuffled cards into wire order.

import type { Conversation } from '../../core/types'
import type { Concept, OrderCard, OrderQuestion, Tier } from '../types'
import { GenCtx, notNull, type Generator } from './context'

function order(
  ctx: GenCtx,
  id: string,
  tier: Tier,
  concept: Concept,
  prompt: string,
  hint: string,
  frames: number[],
  roles: (no: number) => string,
  means: string,
  matters: string,
): OrderQuestion | null {
  const uniq = [...new Set(frames)].sort((a, b) => a - b)
  if (uniq.length < 3) return null
  const cards: OrderCard[] = uniq.map((no) => ({ id: `c${no}`, label: `${roles(no)}: ${ctx.label(no)}`, packet: no }))
  // Labels must be distinguishable, otherwise the order is ambiguous.
  if (new Set(cards.map((c) => c.label)).size !== cards.length) return null
  return {
    id,
    mode: 'order',
    kind: 'order',
    tier,
    concept,
    prompt,
    hint,
    cards,
    explanation: {
      says: cards.map((c) => c.label).join(' → '),
      means,
      matters,
      deeper: ctx.explain(uniq[0]).deeper,
    },
    highlight: uniq.map((packet) => ({ packet })),
  }
}

function tcpRoles(ctx: GenCtx, c: Conversation) {
  return (no: number) => {
    const p = ctx.pkt(no)
    if (p.facts.dns) return p.facts.dns.isResponse ? 'DNS server' : 'Client'
    return p.facts.ip?.src === c.a.addr ? 'Client' : 'Server'
  }
}

export const orderGenerators: Generator[] = [
  {
    id: 'order.connection',
    mode: 'order',
    needs: 'a TCP connection with a handshake and an application exchange',
    generate(ctx) {
      const out: (OrderQuestion | null)[] = []
      const convs = ctx.index.conversations.filter((c) => c.handshake?.syn && c.handshake.synAck && c.handshake.ack)
      for (const c of convs.slice(0, 2)) {
        const hs = c.handshake!
        const frames: number[] = []
        // DNS lookup for the server, if present.
        const dnsAns = ctx.of('dns-answer').find((p) => p.no < hs.syn! && p.facts.dns!.answers.some((a) => a.data === c.b.addr))
        if (dnsAns) {
          const q = ctx.of('dns-query').filter((p) => p.no < dnsAns.no && p.facts.dns!.id === dnsAns.facts.dns!.id).pop()
          if (q) frames.push(q.no)
          frames.push(dnsAns.no)
        }
        frames.push(hs.syn!, hs.synAck!, hs.ack!)
        const app = c.packets.filter((n) => {
          const k = ctx.kindOf(n)
          return n > hs.ack! && !k.startsWith('tcp-')
        })
        frames.push(...app.slice(0, 2))
        const fin = c.packets.find((n) => ctx.pkt(n).facts.tcp?.flags.fin)
        if (fin) frames.push(fin)
        const tier: Tier = frames.length > 6 ? 'Analyst' : 'Recruit'
        out.push(
          order(
            ctx,
            `order.connection:${c.id}`,
            tier,
            'tcp-handshake',
            `Put this ${c.app} session between ${c.a.addr} and ${c.b.addr} in the order it happened.`,
            'Name resolution comes before connecting; connecting comes before talking; talking before closing.',
            frames,
            tcpRoles(ctx, c),
            'A client resolves the name, opens TCP with the three-way handshake, exchanges application data, and closes with FIN.',
            'Knowing the normal order lets you spot what is missing — e.g. data without a handshake (spoofing) or SYNs with no ACK (floods/scans).',
          ),
        )
      }
      return out.filter(notNull)
    },
  },
  {
    id: 'order.dhcp',
    mode: 'order',
    needs: 'a full DHCP DORA exchange',
    generate(ctx) {
      const d = ctx.of('dhcp-discover')[0]
      const o = ctx.of('dhcp-offer')[0]
      const r = ctx.of('dhcp-request')[0]
      const a = ctx.of('dhcp-ack')[0]
      if (!d || !o || !r || !a) return []
      const role = (no: number) => (ctx.pkt(no).facts.dhcp!.msgType === 'Discover' || ctx.pkt(no).facts.dhcp!.msgType === 'Request' ? 'Client' : 'Server')
      return [
        order(
          ctx,
          `order.dhcp:${d.no}`,
          'Recruit',
          'dhcp',
          'Order the DHCP exchange that gives the new laptop its address.',
          'Remember “DORA”.',
          [d.no, o.no, r.no, a.no],
          role,
          'Discover (who can give me an address?) → Offer (take this one) → Request (I’ll take it) → ACK (it’s yours).',
          'Every step is broadcast on the LAN, which is why a rogue DHCP server can race the real one.',
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'order.arp-ping',
    mode: 'order',
    needs: 'ARP resolution followed by a ping',
    generate(ctx) {
      for (const req of ctx.of('arp-request')) {
        const rep = ctx.of('arp-reply').find((r) => r.no > req.no && r.facts.arp!.senderIp === req.facts.arp!.targetIp)
        if (!rep) continue
        const ping = ctx.of('icmp-echo-req').find((p) => p.no > rep.no && p.facts.ip!.dst === rep.facts.arp!.senderIp)
        const pong = ping && ctx.of('icmp-echo-reply').find((p) => p.no > ping.no && p.facts.ip!.src === ping.facts.ip!.dst)
        if (!ping || !pong) continue
        const role = (no: number) => (no === req.no || no === ping.no ? 'Client' : 'Gateway')
        return [
          order(
            ctx,
            `order.arp-ping:${req.no}`,
            'Recruit',
            'arp',
            `Order the packets as ${req.facts.arp!.senderIp} pings ${rep.facts.arp!.senderIp} for the first time.`,
            'You need a MAC address before you can send an Ethernet frame.',
            [req.no, rep.no, ping.no, pong.no],
            role,
            'Before the first ping the host must learn the gateway’s MAC with ARP; only then can it wrap the ICMP packet in an Ethernet frame.',
            'ARP happens silently before most first contacts — which is exactly what ARP spoofing abuses.',
          ),
        ].filter(notNull)
      }
      return []
    },
  },
  {
    id: 'order.ftp',
    mode: 'order',
    needs: 'an FTP login',
    generate(ctx) {
      const banner = ctx.of('ftp-banner')[0]
      const ok = ctx.of('ftp-230')[0]
      if (!banner || !ok) return []
      // The successful USER/331/PASS/230 sequence.
      const pass = ctx.of('ftp-pass').filter((p) => p.no < ok.no).pop()
      const user = pass && ctx.of('ftp-user').filter((p) => p.no < pass.no).pop()
      const need = user && ctx.of('ftp-331').filter((p) => p.no > user.no && p.no < pass!.no).pop()
      if (!pass || !user || !need) return []
      const role = (no: number) => (ctx.pkt(no).facts.app?.isRequest ? 'Client' : 'Server')
      return [
        order(
          ctx,
          `order.ftp:${ok.no}`,
          'Analyst',
          'cleartext',
          'Order the successful FTP login, from greeting to confirmation.',
          'The server speaks first on FTP.',
          [banner.no, user.no, need.no, pass.no, ok.no],
          role,
          'Server greets (220) → client names the user → server asks for a password (331) → client sends PASS → server confirms (230).',
          'Every one of these lines, including the password, is readable by anyone who captures the traffic.',
        ),
      ].filter(notNull)
    },
  },
  {
    id: 'order.tls',
    mode: 'order',
    needs: 'a TLS handshake',
    generate(ctx) {
      const ch = ctx.of('tls-ch')[0]
      const sh = ctx.of('tls-sh')[0]
      if (!ch || !sh) return []
      const c = ctx.kb.conv(ch)
      if (!c?.handshake?.syn || !c.handshake.synAck) return []
      const data = c.packets.find((n) => n > sh.no && ctx.kindOf(n) === 'tls-appdata' && ctx.pkt(n).facts.ip?.src === c.a.addr)
      const frames = [c.handshake.syn, c.handshake.synAck, ch.no, sh.no, ...(data ? [data] : [])]
      return [
        order(
          ctx,
          `order.tls:${ch.no}`,
          'Analyst',
          'tls',
          'Order the steps of this HTTPS connection, from TCP to encrypted data.',
          'TLS runs on top of an already-open TCP connection.',
          frames,
          tcpRoles(ctx, c),
          'TCP connects first; then ClientHello → ServerHello negotiate keys; after that everything is encrypted application data.',
          'Anything before the ServerHello (like the SNI) is visible to observers; everything after is not.',
        ),
      ].filter(notNull)
    },
  },
]
