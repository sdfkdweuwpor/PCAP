// Mode F — "Spot the Anomaly": only asked when a heuristic actually detected the anomaly.

import type { Anomaly, AnomalyKind } from '../../core/types'
import type { Concept, Question } from '../types'
import { choice, GenCtx, notNull, type Generator } from './context'

const SUMMARY: Record<AnomalyKind, string> = {
  'port-scan': 'A host is probing many ports on another host.',
  'syn-flood': 'A server is flooded with half-open connections.',
  'arp-spoof': 'A host is poisoning ARP caches to intercept traffic.',
  'cleartext-creds': 'A user logged in with credentials in cleartext.',
  'dns-tunnel': 'A host is smuggling data out inside DNS queries.',
  'failed-logins': 'Someone keeps failing to log in to a service.',
  'rst-storm': 'Connections are reset in unusually large numbers.',
  'unusual-port': 'A host is talking to a service on a suspicious port.',
}

const NEXT_STEP: Record<AnomalyKind, { correct: string; wrong: string[] }> = {
  'port-scan': {
    correct: 'Check whether the scanner later connected to the open ports.',
    wrong: [
      'Reboot the target so that the scan results become invalid.',
      'Block all ICMP traffic on the network to stop the scanning.',
      'Ignore it, since a scan can never be part of a real attack.',
    ],
  },
  'syn-flood': {
    correct: 'Enable SYN cookies and rate-limit or filter the flood upstream.',
    wrong: [
      'Block the one source address that is sending all of the SYNs.',
      'Raise the TCP window size so the server accepts more data.',
      'Switch the web server to UDP so that handshakes are avoided.',
    ],
  },
  'arp-spoof': {
    correct: 'Locate the switch port of the rogue MAC and isolate that host.',
    wrong: [
      'Renew the DHCP lease on the gateway to get a fresh address.',
      'Flush the DNS cache on the victim to remove the bad entries.',
      'Change the password for the user of the victim workstation.',
    ],
  },
  'cleartext-creds': {
    correct: 'Reset the exposed password and move the service to SFTP/FTPS.',
    wrong: [
      'Increase the password length policy for all the other users.',
      'Block the client IP address from ever using the file server.',
      'Enable the verbose server logging to record future logins.',
    ],
  },
  'dns-tunnel': {
    correct: 'Block the tunnel domain and investigate the host sending queries.',
    wrong: [
      'Switch the client to another public DNS resolver immediately.',
      'Increase the DNS cache TTL so that fewer queries are needed.',
      'Block every TXT query on the network, including legitimate ones.',
    ],
  },
  'failed-logins': {
    correct: 'Check the source of the attempts and lock or rate-limit logins.',
    wrong: [
      'Disable the failing account and every other account too.',
      'Increase the session timeout so that users stay logged in.',
      'Ignore it, because failed logins can never lead to access.',
    ],
  },
  'rst-storm': {
    correct: 'Find which host sends the resets and why connections are refused.',
    wrong: [
      'Increase the MTU so that fewer packets need to be resent.',
      'Restart every client machine to clear its TCP connections.',
      'Disable TCP resets on all hosts across the entire network.',
    ],
  },
  'unusual-port': {
    correct: 'Identify the process behind the connection and check it for malware.',
    wrong: [
      'Open the same port on the firewall for every other host too.',
      'Change the port of the service to 80 so that it looks normal.',
      'Ignore it, because only the well-known ports carry any risk.',
    ],
  },
}

const CONCEPT: Record<AnomalyKind, Concept> = {
  'port-scan': 'recon',
  'syn-flood': 'dos',
  'arp-spoof': 'mitm',
  'cleartext-creds': 'cleartext',
  'dns-tunnel': 'exfil',
  'failed-logins': 'cleartext',
  'rst-storm': 'tcp-flags',
  'unusual-port': 'recon',
}

const MATTERS: Record<AnomalyKind, string> = {
  'port-scan': 'Reconnaissance usually precedes exploitation; the open ports found are the attacker’s next targets.',
  'syn-flood': 'Availability is part of security: a SYN flood can take a service offline without any exploit.',
  'arp-spoof': 'A man-in-the-middle can read, modify or downgrade everything the victim sends.',
  'cleartext-creds': 'Captured credentials give an attacker legitimate access that is hard to distinguish from the real user.',
  'dns-tunnel': 'DNS tunnels bypass most firewalls and proxies to exfiltrate data or run command-and-control.',
  'failed-logins': 'Brute force and password spraying are among the most common initial-access techniques.',
  'rst-storm': 'Reset storms signal scanning, misconfigured firewalls, or services failing under load.',
  'unusual-port': 'Malware and backdoors often listen on unusual ports to avoid casual detection.',
}

function describe(a: Anomaly) {
  return {
    says: a.detail,
    means: SUMMARY[a.kind],
    matters: MATTERS[a.kind],
    deeper: `Evidence: ${Object.entries(a.evidence)
      .map(([k, v]) => `${k}=${v}`)
      .join(', ')}.`,
  }
}

export const anomalyGenerators: Generator[] = [
  {
    id: 'anomaly.identify',
    mode: 'anomaly',
    needs: 'a detected anomaly',
    generate(ctx) {
      const detected = new Set(ctx.index.anomalies.map((a) => a.kind))
      const out: (Question | null)[] = []
      for (const a of ctx.index.anomalies) {
        if (a.kind === 'rst-storm' && detected.has('port-scan')) continue // a symptom of the scan, not a separate story
        const others = (Object.keys(SUMMARY) as AnomalyKind[]).filter((k) => !detected.has(k) && !partlyTrue(ctx, k))
        const distractors = others.sort(() => ctx.rng() - 0.5).map((k) => SUMMARY[k])
        const base = {
          mode: 'anomaly' as const,
          tier: 'Hunter' as const,
          concept: CONCEPT[a.kind],
          explanation: describe(a),
          highlight: a.packets.slice(0, 8).map((packet) => ({ packet })),
        }
        out.push(
          choice(
            ctx,
            {
              ...base,
              id: `anomaly.identify.${a.kind}`,
              prompt: 'Scan the whole capture (try the Conversations tab and filters). Which best describes what is going on?',
              hint: hintFor(a.kind),
            },
            SUMMARY[a.kind],
            distractors,
          ),
        )
        out.push({
          ...base,
          id: `anomaly.evidence.${a.kind}`,
          kind: 'pick',
          multi: false,
          prompt: `Evidence hunt — ${SUMMARY[a.kind]} Click a packet that directly shows it.`,
          hint: hintFor(a.kind),
          answer: a.packets,
        })
        const ns = NEXT_STEP[a.kind]
        out.push(
          choice(
            ctx,
            {
              ...base,
              id: `anomaly.next.${a.kind}`,
              prompt: `You have confirmed this: ${a.title}. As the analyst on shift, what would you do next?`,
              hint: 'Contain the actual cause and verify impact; avoid actions that break things or miss the point.',
            },
            ns.correct,
            ns.wrong,
          ),
        )
      }
      return out.filter(notNull)
    },
  },
]

/**
 * True when the capture shows enough of an anomaly's raw signs (below the detector's threshold) that its summary
 * would be a defensible answer too — such kinds can't serve as wrong options.
 */
function partlyTrue(ctx: GenCtx, k: AnomalyKind): boolean {
  const ps = ctx.packets
  switch (k) {
    case 'cleartext-creds':
      return ps.some((p) => p.facts.creds)
    case 'failed-logins':
      return ps.some((p) => {
        const a = p.facts.app
        return a?.code === 530 || a?.code === 535 || a?.command === '-ERR' || a?.command === 'NO' || p.facts.http?.status === 401
      })
    case 'port-scan':
      return ctx.of('tcp-rst-closed').length >= 3
    case 'rst-storm':
      return ps.filter((p) => p.facts.tcp?.flags.rst).length >= 5
    case 'dns-tunnel':
      return ps.some((p) => p.facts.dns?.qname.split('.').some((l) => l.length > 30))
    default:
      return false
  }
}

function hintFor(k: AnomalyKind): string {
  switch (k) {
    case 'port-scan':
      return 'Try the filter tcp.flags.syn == 1 && tcp.flags.ack == 0 and look at the destination ports.'
    case 'syn-flood':
      return 'Count the SYNs and their source addresses. Do any connections complete?'
    case 'arp-spoof':
      return 'Filter with "arp" and compare the MAC address given for each IP.'
    case 'cleartext-creds':
      return 'Look for USER/PASS, LOGIN or Authorization in unencrypted protocols.'
    case 'dns-tunnel':
      return 'Filter with "dns" and look at the length and randomness of the names.'
    case 'failed-logins':
      return 'Look for 530, -ERR, NO or 401 replies.'
    case 'rst-storm':
      return 'Filter with tcp.flags.reset == 1.'
    case 'unusual-port':
      return 'Check the Conversations tab for unexpected server ports.'
  }
}
