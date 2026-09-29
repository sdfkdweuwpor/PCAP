// Core data model shared by the parser worker, the UI and the game engine.

/** A node in the packet-details tree. Offsets are relative to the start of the packet bytes. */
export interface Field {
  /** Human label, e.g. "Time to Live". */
  name: string
  /** Wireshark-ish field key, e.g. "ip.ttl". Used for Field Hunt and highlighting. */
  key?: string
  /** Display value, e.g. "64". */
  value?: string
  offset: number
  length: number
  children?: Field[]
  /** Holds a credential; masked in the UI unless revealed. */
  secret?: boolean
  /** Visual emphasis for teaching moments (cleartext creds, errors). */
  warn?: boolean
}

export type LinkType = 0 | 1 | 101 | 113 | 228 | 229 | 276 | number

/** One captured frame as read from the container, before dissection. */
export interface RawRecord {
  /** Seconds since epoch (float). */
  ts: number
  linkType: LinkType
  /** Offset of the frame bytes inside the source file buffer. */
  dataOffset: number
  capLen: number
  origLen: number
  interfaceId: number
}

export interface TcpFlags {
  fin: boolean
  syn: boolean
  rst: boolean
  psh: boolean
  ack: boolean
  urg: boolean
  ece: boolean
  cwr: boolean
}

export interface DnsRecordFact {
  name: string
  type: string
  data: string
  ttl: number
}

export interface CredentialFact {
  proto: 'FTP' | 'HTTP' | 'Telnet' | 'POP' | 'IMAP' | 'SMTP'
  kind: 'user' | 'pass' | 'basic' | 'login'
  user?: string
  secret?: string
}

/** Compact protocol facts extracted during dissection. Drives filters, analysis and question generation. */
export interface PacketFacts {
  eth?: { src: string; dst: string; type: number }
  vlan?: { id: number; priority: number }
  arp?: { op: number; senderMac: string; senderIp: string; targetMac: string; targetIp: string }
  ip?: {
    version: 4 | 6
    src: string
    dst: string
    ttl: number
    proto: number
    len: number
    id?: number
    df?: boolean
    mf?: boolean
    fragOffset?: number
  }
  icmp?: { v6: boolean; type: number; code: number; typeName: string }
  tcp?: {
    srcPort: number
    dstPort: number
    seq: number
    ack: number
    relSeq?: number
    relAck?: number
    flags: TcpFlags
    flagStr: string
    window: number
    payloadLen: number
    payloadOffset: number
    options: string[]
    mss?: number
    wscale?: number
    sackPerm?: boolean
  }
  udp?: { srcPort: number; dstPort: number; len: number; payloadOffset: number; payloadLen: number }
  dns?: {
    id: number
    isResponse: boolean
    opcode: number
    rcode: number
    rcodeName: string
    qname: string
    qtype: string
    answers: DnsRecordFact[]
  }
  http?: {
    isRequest: boolean
    method?: string
    uri?: string
    version: string
    status?: number
    reason?: string
    host?: string
    userAgent?: string
    contentType?: string
    authorization?: string
  }
  tls?: {
    contentTypes: string[]
    handshakeTypes: string[]
    recordVersion: string
    sni?: string
    cipherSuites?: string[]
    chosenCipher?: string
    helloVersion?: string
    supportedVersions?: string[]
    alert?: string
  }
  dhcp?: {
    msgType: string
    xid: number
    clientMac: string
    yiaddr: string
    ciaddr: string
    requestedIp?: string
    serverId?: string
    hostname?: string
    router?: string
    dnsServers?: string[]
    leaseTime?: number
  }
  app?: {
    proto: 'FTP' | 'SMTP' | 'POP' | 'IMAP' | 'Telnet' | 'FTP-DATA'
    line: string
    isRequest: boolean
    command?: string
    arg?: string
    code?: number
  }
  ssh?: { banner: string }
  ntp?: { version: number; mode: number; modeName: string; stratum: number }
  snmp?: { version: string; community: string; pdu: string }
  creds?: CredentialFact
  /** Lowercase protocol names present in the packet, e.g. ["eth","ip","tcp","http"]. */
  protos: string[]
  malformed?: string
}

/** Wireshark-style coloring rule id. */
export type ColorRule =
  | 'tcp-syn'
  | 'tcp-fin'
  | 'tcp-rst'
  | 'tcp'
  | 'udp'
  | 'dns'
  | 'http'
  | 'tls'
  | 'arp'
  | 'icmp'
  | 'icmp-error'
  | 'dhcp'
  | 'cleartext'
  | 'error'
  | 'other'

export interface Dissection {
  layers: Field[]
  facts: PacketFacts
  src: string
  dst: string
  protocol: string
  info: string
  color: ColorRule
}

/** Lightweight per-packet row produced by the indexer (no field tree). */
export interface PacketSummary {
  /** 1-based frame number. */
  no: number
  ts: number
  relTime: number
  capLen: number
  origLen: number
  linkType: LinkType
  dataOffset: number
  src: string
  dst: string
  protocol: string
  info: string
  color: ColorRule
  facts: PacketFacts
  streamId: number
}

export interface Endpoint {
  addr: string
  port?: number
}

export interface Conversation {
  id: number
  proto: 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'Other'
  /** Application label, e.g. "HTTP", "DNS", "TLS". */
  app: string
  a: Endpoint
  b: Endpoint
  /** Frame numbers (1-based) in capture order. */
  packets: number[]
  bytes: number
  bytesAtoB: number
  bytesBtoA: number
  start: number
  end: number
  /** TCP only: handshake/teardown state. */
  handshake?: { syn?: number; synAck?: number; ack?: number }
  closedBy?: 'fin' | 'rst'
}

export type AnomalyKind =
  | 'port-scan'
  | 'syn-flood'
  | 'arp-spoof'
  | 'cleartext-creds'
  | 'dns-tunnel'
  | 'failed-logins'
  | 'rst-storm'
  | 'unusual-port'

export interface Anomaly {
  kind: AnomalyKind
  title: string
  detail: string
  /** Representative frame numbers. */
  packets: number[]
  severity: 'low' | 'medium' | 'high'
  evidence: Record<string, string | number>
}

export interface CaptureIndex {
  fileName: string
  format: 'pcap' | 'pcapng'
  linkTypes: LinkType[]
  packets: PacketSummary[]
  conversations: Conversation[]
  anomalies: Anomaly[]
  warnings: string[]
  totalBytes: number
  duration: number
}
