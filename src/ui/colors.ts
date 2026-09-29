import type { ColorRule } from '../core/types'

/** CSS variable for a protocol name (packet list Protocol column, flow view, chips). */
export function protoVar(protocol: string): string {
  const p = protocol.toUpperCase()
  if (p.startsWith('TLS') || p === 'SSH') return 'var(--p-tls)'
  if (p === 'HTTP') return 'var(--p-http)'
  if (p === 'DNS') return 'var(--p-dns)'
  if (p === 'ARP') return 'var(--p-arp)'
  if (p.startsWith('ICMP')) return 'var(--p-icmp)'
  if (p === 'DHCP') return 'var(--p-dhcp)'
  if (p === 'UDP' || p === 'NTP' || p === 'SNMP') return 'var(--p-udp)'
  if (['FTP', 'TELNET', 'POP', 'IMAP', 'SMTP', 'FTP-DATA'].includes(p)) return 'var(--p-clear)'
  if (p === 'TCP') return 'var(--p-tcp)'
  return 'var(--p-other)'
}

export function ruleVar(rule: ColorRule): string {
  switch (rule) {
    case 'tcp-rst':
    case 'error':
    case 'icmp-error':
      return 'var(--p-err)'
    case 'tcp-syn':
    case 'tcp-fin':
      return 'var(--p-syn)'
    case 'cleartext':
      return 'var(--p-clear)'
    default:
      return `var(--p-${rule === 'tcp' ? 'tcp' : rule})`
  }
}

export const RULE_LEGEND: { rule: ColorRule; label: string }[] = [
  { rule: 'tcp-syn', label: 'TCP SYN/FIN' },
  { rule: 'tcp', label: 'TCP' },
  { rule: 'tcp-rst', label: 'RST / errors' },
  { rule: 'udp', label: 'UDP' },
  { rule: 'dns', label: 'DNS' },
  { rule: 'http', label: 'HTTP' },
  { rule: 'tls', label: 'TLS' },
  { rule: 'arp', label: 'ARP' },
  { rule: 'icmp', label: 'ICMP' },
  { rule: 'dhcp', label: 'DHCP' },
  { rule: 'cleartext', label: 'Cleartext creds' },
]
