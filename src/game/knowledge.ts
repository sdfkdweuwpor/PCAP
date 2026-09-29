// The protocol "knowledge base": classifies packets into teaching kinds and provides literal
// statements, plain-English meaning, analyst relevance and RFC-level detail for each.
// Statements are written role-generic and of similar length so they work as balanced
// multiple-choice options.

import type { CaptureIndex, Conversation, PacketSummary } from '../core/types'
import type { Concept, Explanation } from './types'

export type Kind =
  | 'tcp-syn'
  | 'tcp-synack'
  | 'tcp-hs-ack'
  | 'tcp-fin'
  | 'tcp-rst'
  | 'tcp-rst-closed'
  | 'tcp-ack'
  | 'tcp-data'
  | 'dns-query'
  | 'dns-answer'
  | 'dns-nxdomain'
  | 'http-request'
  | 'http-ok'
  | 'http-notfound'
  | 'http-redirect'
  | 'http-unauth'
  | 'tls-ch'
  | 'tls-sh'
  | 'tls-appdata'
  | 'tls-alert'
  | 'dhcp-discover'
  | 'dhcp-offer'
  | 'dhcp-request'
  | 'dhcp-ack'
  | 'arp-request'
  | 'arp-reply'
  | 'arp-gratuitous'
  | 'icmp-echo-req'
  | 'icmp-echo-reply'
  | 'icmp-unreach'
  | 'ftp-banner'
  | 'ftp-user'
  | 'ftp-pass'
  | 'ftp-331'
  | 'ftp-230'
  | 'ftp-530'
  | 'ftp-cmd'
  | 'ssh-banner'
  | 'ntp-client'
  | 'ntp-server'
  | 'other'

export const SERVICES: Record<number, string> = {
  20: 'FTP data',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP server',
  68: 'DHCP client',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  143: 'IMAP',
  161: 'SNMP',
  443: 'HTTPS',
  445: 'SMB',
  3306: 'MySQL',
  3389: 'RDP',
  8080: 'HTTP-alt',
}
export const serviceName = (port?: number) => (port !== undefined ? (SERVICES[port] ?? `port ${port}`) : '')

/** Values available to templates. */
export interface Vars {
  src: string
  dst: string
  client: string
  server: string
  sport: number
  dport: number
  service: string
  qname: string
  qtype: string
  answer: string
  method: string
  uri: string
  host: string
  status: string
  sni: string
  cipher: string
  mac: string
  ip: string
  target: string
  user: string
}

interface KindInfo {
  concept: Concept
  /** Short label for order cards and flow arrows. */
  label: (v: Vars) => string
  /** Literal multiple-choice statement (role-generic, ~55–80 chars). */
  statement: string
  means: (v: Vars) => string
  matters: string
  deeper: string
  confusables: Kind[]
}

const RFC_TCP =
  'RFC 9293 §3.5: a connection opens with SYN (client ISN), SYN-ACK (server ISN, acking client ISN+1) and ACK. SYN and FIN each consume one sequence number; relative sequence numbers in Wireshark subtract the ISN.'
const RFC_DNS =
  'RFC 1035 §4.1: a DNS message has a 12-byte header (ID, flags incl. QR/opcode/RCODE, four counts) followed by question, answer, authority and additional sections. Names use length-prefixed labels with 0xC0 compression pointers.'
const RFC_HTTP =
  'RFC 9110/9112: an HTTP/1.1 message is a start line (request-line or status-line), CRLF-separated header fields, an empty line, then an optional body sized by Content-Length or chunked encoding.'
const RFC_TLS =
  'RFC 8446 §4: the ClientHello carries versions, random, cipher_suites and extensions (SNI, supported_versions, key_share). The ServerHello picks one suite; in TLS 1.3 everything after it is encrypted, disguised as application_data records.'
const RFC_DHCP =
  'RFC 2131 §3.1: DHCP uses UDP 67/68. The client broadcasts DISCOVER, servers answer OFFER (yiaddr), the client broadcasts REQUEST naming the server (option 54), and the server confirms with ACK. Option 53 carries the message type.'
const RFC_ARP =
  'RFC 826: ARP maps protocol (IPv4) addresses to hardware (MAC) addresses. Opcode 1 = request (usually broadcast), 2 = reply. There is no authentication, and hosts typically cache any reply they receive.'
const RFC_ICMP =
  'RFC 792: ICMP type 8 is Echo Request and type 0 Echo Reply, matched by identifier and sequence number. Type 3 (Destination Unreachable) carries the original IP header plus 8 bytes so the sender can match it.'
const RFC_FTP =
  'RFC 959: FTP uses a TCP control connection on port 21 with text commands (USER, PASS, PWD, QUIT…) and 3-digit replies: 2xx success, 3xx need more info, 4xx/5xx failure. Nothing is encrypted.'

export const KB: Record<Kind, KindInfo> = {
  'tcp-syn': {
    concept: 'tcp-handshake',
    label: () => 'SYN',
    statement: 'The client asks the server to open a brand-new TCP connection.',
    means: (v) => `${v.client} wants to open a connection to ${v.service} (port ${v.dport}) on ${v.server}.`,
    matters: 'Every TCP session starts with a SYN, so counting SYNs per host is how IDSs spot scans and floods.',
    deeper: RFC_TCP,
    confusables: ['tcp-synack', 'tcp-hs-ack', 'tcp-fin', 'tcp-rst'],
  },
  'tcp-synack': {
    concept: 'tcp-handshake',
    label: () => 'SYN, ACK',
    statement: 'The server agrees to connect and sends its own starting sequence number.',
    means: (v) => `${v.server} is listening on port ${v.sport} and accepts the connection from ${v.client}.`,
    matters: 'A SYN-ACK proves a service is listening on that port — exactly what port scanners look for.',
    deeper: RFC_TCP,
    confusables: ['tcp-syn', 'tcp-hs-ack', 'tcp-rst-closed'],
  },
  'tcp-hs-ack': {
    concept: 'tcp-handshake',
    label: () => 'ACK',
    statement: "The client confirms the server's reply and completes the handshake.",
    means: (v) => `The connection between ${v.client} and ${v.server} is now established and data can flow.`,
    matters: 'Half-open connections never get this ACK; lots of missing final ACKs point to a SYN flood.',
    deeper: RFC_TCP,
    confusables: ['tcp-syn', 'tcp-synack', 'tcp-fin', 'tcp-data'],
  },
  'tcp-fin': {
    concept: 'tcp-teardown',
    label: () => 'FIN, ACK',
    statement: 'This side has finished sending data and asks to close the connection.',
    means: (v) => `${v.src} is done sending and starts a polite, graceful close of the connection.`,
    matters: 'Graceful FINs are normal; compare them with RSTs when judging whether a session ended badly.',
    deeper: RFC_TCP + ' A FIN closes one direction; the other side sends its own FIN when done (four-way close).',
    confusables: ['tcp-rst', 'tcp-syn', 'tcp-ack'],
  },
  'tcp-rst': {
    concept: 'tcp-flags',
    label: () => 'RST',
    statement: 'This side abruptly aborts the connection instead of closing it politely.',
    means: (v) => `${v.src} tears the connection down immediately; no more data will be accepted.`,
    matters: 'Unexpected resets can mean a crashed service, a firewall, or a scanner tearing down its probes.',
    deeper: RFC_TCP + ' A RST is not acknowledged; the receiver discards the connection state at once.',
    confusables: ['tcp-fin', 'tcp-synack', 'tcp-ack'],
  },
  'tcp-rst-closed': {
    concept: 'tcp-flags',
    label: () => 'RST, ACK',
    statement: 'The host refuses the connection because nothing is listening on that port.',
    means: (v) => `Port ${v.sport} on ${v.src} is closed, so it rejects the attempt from ${v.dst}.`,
    matters: 'Many RST/ACKs back to one source is the classic fingerprint of a port scan hitting closed ports.',
    deeper: RFC_TCP + ' A SYN to a closed port elicits RST with ACK = the SYN’s sequence number + 1.',
    confusables: ['tcp-synack', 'tcp-fin', 'tcp-ack'],
  },
  'tcp-ack': {
    concept: 'tcp-flags',
    label: () => 'ACK',
    statement: 'This side acknowledges data it received without sending any data itself.',
    means: (v) => `${v.src} tells ${v.dst} which bytes arrived safely so nothing needs resending.`,
    matters: 'ACK timing reveals round-trip time and retransmissions — key for diagnosing slow connections.',
    deeper: RFC_TCP + ' The Acknowledgment Number is the next byte the sender expects to receive.',
    confusables: ['tcp-data', 'tcp-fin', 'tcp-syn'],
  },
  'tcp-data': {
    concept: 'tcp-flags',
    label: () => 'data',
    statement: 'This side sends application data inside an already-established connection.',
    means: (v) => `${v.src} sends ${v.service} payload bytes to ${v.dst} over the open connection.`,
    matters: 'Payload is where the application lives; if it is not encrypted, anyone on the path can read it.',
    deeper: RFC_TCP + ' PSH asks the receiver to hand buffered data to the application promptly.',
    confusables: ['tcp-ack', 'tcp-syn', 'tcp-fin'],
  },
  'dns-query': {
    concept: 'dns',
    label: (v) => `DNS query ${v.qtype} ${short(v.qname)}`,
    statement: 'The client asks the DNS server to translate a hostname into an address.',
    means: (v) => `${v.client} wants the ${v.qtype} record (address) for ${short(v.qname)} before it can connect.`,
    matters: 'DNS queries reveal every site a host visits and are abused for tunneling and malware C2 lookups.',
    deeper: RFC_DNS,
    confusables: ['dns-answer', 'dns-nxdomain', 'arp-request', 'http-request'],
  },
  'dns-answer': {
    concept: 'dns',
    label: (v) => `DNS answer ${short(v.qname)}`,
    statement: 'The DNS server replies with the address records for the name requested.',
    means: (v) => `The resolver says ${short(v.qname)} is at ${v.answer || 'the returned address'}.`,
    matters: 'Analysts pivot on resolved IPs; a spoofed DNS answer could silently send the client to an attacker.',
    deeper: RFC_DNS,
    confusables: ['dns-query', 'dns-nxdomain', 'dhcp-offer'],
  },
  'dns-nxdomain': {
    concept: 'dns',
    label: (v) => `NXDOMAIN ${short(v.qname)}`,
    statement: 'The DNS server replies that the requested name does not exist at all.',
    means: (v) => `${short(v.qname)} is not a registered name, so the client cannot reach it by name.`,
    matters: 'Bursts of NXDOMAINs can indicate malware trying algorithmically generated domains (DGA).',
    deeper: RFC_DNS + ' RCODE 3 (NXDOMAIN, “No such name”) is authoritative proof that the name does not exist.',
    confusables: ['dns-answer', 'dns-query', 'icmp-unreach'],
  },
  'http-request': {
    concept: 'http',
    label: (v) => `${v.method} ${short(v.uri, 18)}`,
    statement: 'The browser asks the web server to send back one specific resource.',
    means: (v) => `${v.client} requests ${v.uri} from ${v.host || v.server} using ${v.method}.`,
    matters: 'Cleartext HTTP exposes URLs, cookies and credentials to anyone who can see the traffic.',
    deeper: RFC_HTTP,
    confusables: ['http-ok', 'dns-query', 'http-notfound'],
  },
  'http-ok': {
    concept: 'http',
    label: () => '200 OK',
    statement: 'The web server says the request worked and sends back the content.',
    means: (v) => `${v.server} found the resource and returns it to ${v.client} (status ${v.status}).`,
    matters: 'The body travels unencrypted, so the content could be read or modified in transit.',
    deeper: RFC_HTTP + ' 2xx status codes mean success; 200 OK carries the representation in the body.',
    confusables: ['http-request', 'http-notfound', 'http-redirect'],
  },
  'http-notfound': {
    concept: 'http',
    label: () => '404 Not Found',
    statement: 'The web server says the requested resource could not be found there.',
    means: (v) => `The client asked for something ${v.server} does not have (status ${v.status}).`,
    matters: 'Many 404s from one client can indicate directory brute-forcing or vulnerability scanning.',
    deeper: RFC_HTTP + ' 4xx status codes mean a client error; 404 says no current representation exists.',
    confusables: ['http-ok', 'http-unauth', 'http-redirect'],
  },
  'http-redirect': {
    concept: 'http',
    label: (v) => `${v.status} Redirect`,
    statement: 'The web server tells the client to fetch the resource from elsewhere.',
    means: (v) => `${v.server} points the client to a different URL via the Location header.`,
    matters: 'Open redirects and HTTP→HTTPS upgrades both show up here; attackers abuse the former for phishing.',
    deeper: RFC_HTTP + ' 3xx status codes redirect; the Location header carries the new target.',
    confusables: ['http-ok', 'http-notfound', 'http-request'],
  },
  'http-unauth': {
    concept: 'http',
    label: () => '401 Unauthorized',
    statement: 'The web server says the client must authenticate before continuing.',
    means: (v) => `${v.server} demands credentials before it will serve the resource.`,
    matters: 'Repeated 401s from one source suggest password guessing against the web login.',
    deeper: RFC_HTTP + ' 401 includes WWW-Authenticate naming the scheme (e.g. Basic, which is just base64).',
    confusables: ['http-ok', 'http-notfound', 'http-redirect'],
  },
  'tls-ch': {
    concept: 'tls',
    label: () => 'Client Hello',
    statement: 'The client proposes TLS versions and ciphers and names the site it wants.',
    means: (v) => `${v.client} starts a TLS session and reveals it wants ${v.sni || 'the server'} via SNI.`,
    matters: 'Even with encryption, the SNI in the ClientHello tells observers which site is being visited.',
    deeper: RFC_TLS,
    confusables: ['tls-sh', 'tls-appdata', 'http-request'],
  },
  'tls-sh': {
    concept: 'tls',
    label: () => 'Server Hello',
    statement: 'The server picks the TLS version and the cipher suite for this session.',
    means: (v) => `${v.server} chose ${v.cipher || 'a cipher suite'} from the client's list.`,
    matters: 'Weak or outdated negotiated ciphers and versions are findings in any security assessment.',
    deeper: RFC_TLS,
    confusables: ['tls-ch', 'tls-appdata', 'tcp-synack'],
  },
  'tls-appdata': {
    concept: 'tls',
    label: () => 'App Data',
    statement: 'Encrypted application data is exchanged and its contents are unreadable.',
    means: (v) => `${v.src} sends encrypted bytes; only the endpoints holding the session keys can read them.`,
    matters: 'Encrypted payloads cannot be inspected without keys — analysts rely on metadata like size and timing.',
    deeper: RFC_TLS,
    confusables: ['tls-ch', 'tls-sh', 'http-ok'],
  },
  'tls-alert': {
    concept: 'tls',
    label: () => 'Alert',
    statement: 'One side sends a TLS alert to warn about or to end the secure session.',
    means: (v) => `${v.src} signals an error or closes the TLS session with an alert record.`,
    matters: 'Alerts can reveal certificate problems, protocol mismatches or interception attempts.',
    deeper: RFC_TLS + ' close_notify (0) is a normal shutdown; fatal alerts abort the handshake.',
    confusables: ['tls-appdata', 'tls-sh', 'tcp-rst'],
  },
  'dhcp-discover': {
    concept: 'dhcp',
    label: () => 'DHCP Discover',
    statement: 'A client with no address broadcasts to find any available DHCP server.',
    means: (v) => `A device (${v.mac}) just joined the network and is looking for an IP address.`,
    matters: 'Rogue DHCP servers can answer Discovers and hand out a malicious gateway or DNS server.',
    deeper: RFC_DHCP,
    confusables: ['dhcp-offer', 'dhcp-request', 'dhcp-ack'],
  },
  'dhcp-offer': {
    concept: 'dhcp',
    label: () => 'DHCP Offer',
    statement: 'The DHCP server offers an IP address and settings to the new client.',
    means: (v) => `The server proposes ${v.ip} for the client, along with gateway and DNS settings.`,
    matters: 'Only authorized servers should send Offers; an unexpected one may be a rogue DHCP server.',
    deeper: RFC_DHCP,
    confusables: ['dhcp-discover', 'dhcp-request', 'dhcp-ack'],
  },
  'dhcp-request': {
    concept: 'dhcp',
    label: () => 'DHCP Request',
    statement: 'The client formally asks to take the address that the server offered.',
    means: (v) => `The client accepts the offer and requests ${v.ip || 'the offered address'} from that server.`,
    matters: 'The Request names the chosen server, which helps confirm which DHCP server is authoritative.',
    deeper: RFC_DHCP,
    confusables: ['dhcp-discover', 'dhcp-offer', 'dhcp-ack'],
  },
  'dhcp-ack': {
    concept: 'dhcp',
    label: () => 'DHCP ACK',
    statement: 'The DHCP server confirms the lease so the client may now use the address.',
    means: (v) => `${v.ip} now belongs to the client for the lease time; configuration is complete.`,
    matters: 'DHCP logs map IPs to MACs and hostnames — vital for attributing activity in an investigation.',
    deeper: RFC_DHCP,
    confusables: ['dhcp-discover', 'dhcp-offer', 'dhcp-request'],
  },
  'arp-request': {
    concept: 'arp',
    label: (v) => `Who has ${v.target}?`,
    statement: 'A host broadcasts asking which MAC address owns a particular IP address.',
    means: (v) => `${v.src} needs the hardware address for ${v.target} before it can send it frames.`,
    matters: 'ARP has no authentication, so any host can answer — the root of ARP spoofing attacks.',
    deeper: RFC_ARP,
    confusables: ['arp-reply', 'dns-query', 'dhcp-discover'],
  },
  'arp-reply': {
    concept: 'arp',
    label: (v) => `${v.ip} is at …${v.mac.slice(-5)}`,
    statement: 'A host answers that a particular IP address belongs to its MAC address.',
    means: (v) => `${v.mac} claims to own ${v.ip}; the receiver will cache that mapping.`,
    matters: 'If a different MAC suddenly answers for the same IP, suspect ARP spoofing (man-in-the-middle).',
    deeper: RFC_ARP,
    confusables: ['arp-request', 'dhcp-offer', 'dns-answer'],
  },
  'arp-gratuitous': {
    concept: 'arp',
    label: () => 'Gratuitous ARP',
    statement: 'A host announces its own IP-to-MAC mapping without anyone asking for it.',
    means: (v) => `${v.mac} tells the LAN it now uses ${v.ip} and checks nobody else does.`,
    matters: 'Gratuitous ARPs are normal at boot, but attackers use unsolicited ARPs to poison caches.',
    deeper: RFC_ARP + ' A gratuitous ARP has sender IP = target IP (RFC 5227 address conflict detection).',
    confusables: ['arp-reply', 'dhcp-discover', 'icmp-echo-req'],
  },
  'icmp-echo-req': {
    concept: 'icmp',
    label: () => 'Echo request',
    statement: 'A host sends a ping to test whether the other host is reachable.',
    means: (v) => `${v.src} checks whether ${v.dst} is up and measures the round-trip time.`,
    matters: 'Ping sweeps map live hosts, and ICMP payloads can even be abused to tunnel data.',
    deeper: RFC_ICMP,
    confusables: ['icmp-echo-reply', 'icmp-unreach', 'arp-request'],
  },
  'icmp-echo-reply': {
    concept: 'icmp',
    label: () => 'Echo reply',
    statement: 'A host answers a ping, proving that it is reachable and responding.',
    means: (v) => `${v.src} is alive and answers the ping from ${v.dst}.`,
    matters: 'A reply confirms a live host; the TTL in replies hints at the remote OS and hop count.',
    deeper: RFC_ICMP,
    confusables: ['icmp-echo-req', 'icmp-unreach', 'tcp-synack'],
  },
  'icmp-unreach': {
    concept: 'icmp',
    label: () => 'Unreachable',
    statement: 'A router or host reports that a packet could not be delivered.',
    means: (v) => `${v.src} tells ${v.dst} its earlier packet could not reach its destination.`,
    matters: 'Unreachable messages reveal filtering and closed ports; UDP scans rely on them.',
    deeper: RFC_ICMP,
    confusables: ['icmp-echo-reply', 'tcp-rst-closed', 'dns-nxdomain'],
  },
  'ftp-banner': {
    concept: 'cleartext',
    label: () => '220 Welcome',
    statement: 'The FTP server greets the client and says it is ready for commands.',
    means: (v) => `${v.server} announces its FTP service (and often its software version) to ${v.client}.`,
    matters: 'Banners leak software versions that attackers match against known vulnerabilities.',
    deeper: RFC_FTP,
    confusables: ['ftp-230', 'ftp-331', 'ftp-user'],
  },
  'ftp-user': {
    concept: 'cleartext',
    label: () => 'USER',
    statement: 'The client tells the FTP server which account it wants to log in as.',
    means: (v) => `${v.client} identifies itself as user "${v.user}" — visible to anyone on the path.`,
    matters: 'FTP sends usernames in cleartext, handing attackers half of a valid login for free.',
    deeper: RFC_FTP,
    confusables: ['ftp-pass', 'ftp-331', 'ftp-banner'],
  },
  'ftp-pass': {
    concept: 'cleartext',
    label: () => 'PASS',
    statement: 'The client sends the account password to the FTP server as plain text.',
    means: (v) => `${v.client} transmits the password for "${v.user || 'the account'}" completely unencrypted.`,
    matters: 'Anyone who can sniff this traffic now has a working password — use SFTP or FTPS instead.',
    deeper: RFC_FTP,
    confusables: ['ftp-user', 'ftp-230', 'ftp-331'],
  },
  'ftp-331': {
    concept: 'cleartext',
    label: () => '331 Need password',
    statement: 'The FTP server accepts the username and asks for the matching password.',
    means: (v) => `${v.server} is waiting for the password that goes with that username.`,
    matters: 'A 331 for any username can let attackers confirm which accounts exist (user enumeration).',
    deeper: RFC_FTP,
    confusables: ['ftp-230', 'ftp-530', 'ftp-banner'],
  },
  'ftp-230': {
    concept: 'cleartext',
    label: () => '230 Logged in',
    statement: 'The FTP server confirms the login succeeded and the session is open.',
    means: (v) => `The credentials worked: ${v.client} is now logged in to ${v.server}.`,
    matters: 'A 230 right after cleartext PASS confirms the sniffed password is valid.',
    deeper: RFC_FTP,
    confusables: ['ftp-530', 'ftp-331', 'ftp-banner'],
  },
  'ftp-530': {
    concept: 'cleartext',
    label: () => '530 Login failed',
    statement: 'The FTP server rejects the login because the credentials were wrong.',
    means: (v) => `The password sent to ${v.server} was incorrect, so access is denied.`,
    matters: 'Several 530s in a row from one source suggest someone is guessing passwords.',
    deeper: RFC_FTP,
    confusables: ['ftp-230', 'ftp-331', 'ftp-banner'],
  },
  'ftp-cmd': {
    concept: 'cleartext',
    label: (v) => v.method || 'FTP command',
    statement: 'The client sends an FTP command asking the server to perform an action.',
    means: (v) => `${v.client} issues the ${v.method} command over the cleartext control channel.`,
    matters: 'Every FTP command is readable on the wire, revealing what files a user browses.',
    deeper: RFC_FTP,
    confusables: ['ftp-230', 'ftp-banner', 'ftp-331'],
  },
  'ssh-banner': {
    concept: 'protocols',
    label: () => 'SSH banner',
    statement: 'The host announces which SSH protocol version and software it runs.',
    means: (v) => `${v.src} identifies its SSH implementation before encryption begins.`,
    matters: 'Banners leak software versions that attackers match against known vulnerabilities.',
    deeper: 'RFC 4253 §4.2: both sides send an identification string "SSH-protoversion-softwareversion".',
    confusables: ['tls-ch', 'ftp-banner', 'tcp-data'],
  },
  'ntp-client': {
    concept: 'udp',
    label: () => 'NTP request',
    statement: 'The client asks a time server for the current time to sync its clock.',
    means: (v) => `${v.src} asks ${v.dst} for the time so its logs and certificates stay accurate.`,
    matters: 'Accurate time keeps logs correlatable; NTP can also be abused for amplification DDoS.',
    deeper: 'RFC 5905: NTP mode 3 = client, 4 = server; four 64-bit timestamps let the client compute offset and delay.',
    confusables: ['ntp-server', 'dns-query', 'dhcp-request'],
  },
  'ntp-server': {
    concept: 'udp',
    label: () => 'NTP reply',
    statement: 'The time server replies with timestamps the client uses to set its clock.',
    means: (v) => `${v.src} provides the current time to ${v.dst}.`,
    matters: 'Accurate time keeps logs correlatable; NTP can also be abused for amplification DDoS.',
    deeper: 'RFC 5905: NTP mode 3 = client, 4 = server; four 64-bit timestamps let the client compute offset and delay.',
    confusables: ['ntp-client', 'dns-answer', 'dhcp-ack'],
  },
  other: {
    concept: 'protocols',
    label: (v) => v.method || 'packet',
    statement: 'This packet carries protocol data between the two hosts.',
    means: (v) => `${v.src} sends a packet to ${v.dst}.`,
    matters: 'Knowing what normal traffic looks like is the baseline for spotting anything abnormal.',
    deeper: 'See the packet details pane for each layer’s fields.',
    confusables: [],
  },
}

export function short(s: string, n = 28): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

/** Helper that knows about conversations for role-aware classification. */
export class Kb {
  index: CaptureIndex
  constructor(index: CaptureIndex) {
    this.index = index
  }
  pkt(no: number): PacketSummary {
    return this.index.packets[no - 1]
  }
  conv(p: PacketSummary): Conversation | undefined {
    return p.streamId >= 0 ? this.index.conversations[p.streamId] : undefined
  }

  classify(p: PacketSummary): Kind {
    const f = p.facts
    if (f.arp) {
      if (f.arp.senderIp === f.arp.targetIp) return 'arp-gratuitous'
      return f.arp.op === 1 ? 'arp-request' : 'arp-reply'
    }
    if (f.dhcp) {
      const m = f.dhcp.msgType
      if (m === 'Discover') return 'dhcp-discover'
      if (m === 'Offer') return 'dhcp-offer'
      if (m === 'Request') return 'dhcp-request'
      if (m === 'ACK') return 'dhcp-ack'
      return 'other'
    }
    if (f.dns) {
      if (!f.dns.isResponse) return 'dns-query'
      return f.dns.rcode === 3 ? 'dns-nxdomain' : 'dns-answer'
    }
    if (f.icmp) {
      const { type, v6 } = f.icmp
      if ((!v6 && type === 8) || (v6 && type === 128)) return 'icmp-echo-req'
      if ((!v6 && type === 0) || (v6 && type === 129)) return 'icmp-echo-reply'
      if ((!v6 && type === 3) || (v6 && type === 1)) return 'icmp-unreach'
      return 'other'
    }
    if (f.ntp) return f.ntp.mode === 3 ? 'ntp-client' : 'ntp-server'
    if (f.http && f.http.version) {
      if (f.http.isRequest) return 'http-request'
      const s = f.http.status ?? 0
      if (s >= 200 && s < 300) return 'http-ok'
      if (s >= 300 && s < 400) return 'http-redirect'
      if (s === 401) return 'http-unauth'
      if (s === 404) return 'http-notfound'
    }
    if (f.tls) {
      if (f.tls.handshakeTypes.includes('Client Hello')) return 'tls-ch'
      if (f.tls.handshakeTypes.includes('Server Hello')) return 'tls-sh'
      if (f.tls.alert || f.tls.contentTypes.includes('Alert')) return 'tls-alert'
      if (f.tls.contentTypes.includes('Application Data')) return 'tls-appdata'
    }
    if (f.app?.proto === 'FTP') {
      const a = f.app
      if (a.isRequest) {
        if (a.command === 'USER') return 'ftp-user'
        if (a.command === 'PASS') return 'ftp-pass'
        return 'ftp-cmd'
      }
      if (a.code === 220) return 'ftp-banner'
      if (a.code === 331) return 'ftp-331'
      if (a.code === 230) return 'ftp-230'
      if (a.code === 530) return 'ftp-530'
    }
    if (f.ssh) return 'ssh-banner'
    const t = f.tcp
    if (t) {
      const c = this.conv(p)
      if (t.flags.syn && !t.flags.ack) return 'tcp-syn'
      if (t.flags.syn && t.flags.ack) return 'tcp-synack'
      if (t.flags.rst) {
        const refused = c && c.handshake?.synAck === undefined && c.handshake?.syn !== undefined && t.flags.ack
        return refused ? 'tcp-rst-closed' : 'tcp-rst'
      }
      if (t.flags.fin) return 'tcp-fin'
      if (c?.handshake?.ack === p.no) return 'tcp-hs-ack'
      if (t.payloadLen > 0) return 'tcp-data'
      return 'tcp-ack'
    }
    return 'other'
  }

  vars(p: PacketSummary): Vars {
    const f = p.facts
    const c = this.conv(p)
    const src = f.ip?.src ?? p.src
    const dst = f.ip?.dst ?? p.dst
    const sport = f.tcp?.srcPort ?? f.udp?.srcPort ?? 0
    const dport = f.tcp?.dstPort ?? f.udp?.dstPort ?? 0
    let client = c?.a.addr ?? src
    let server = c?.b.addr ?? dst
    if (f.dns) [client, server] = f.dns.isResponse ? [dst, src] : [src, dst]
    const serverPort = c?.b.port ?? dport
    const ans = f.dns?.answers.find((a) => a.type === 'A' || a.type === 'AAAA') ?? f.dns?.answers[0]
    return {
      src,
      dst,
      client,
      server,
      sport,
      dport,
      service: serviceName(serverPort),
      qname: f.dns?.qname ?? '',
      qtype: f.dns?.qtype ?? '',
      answer: ans ? ans.data : '',
      method: f.http?.method ?? f.app?.command ?? '',
      uri: f.http?.uri ?? '',
      host: f.http?.host ?? '',
      status: f.http?.status !== undefined ? `${f.http.status} ${f.http.reason ?? ''}`.trim() : '',
      sni: f.tls?.sni ?? '',
      cipher: f.tls?.chosenCipher ?? '',
      mac: f.arp?.senderMac ?? f.dhcp?.clientMac ?? f.eth?.src ?? '',
      ip: f.arp?.senderIp ?? f.dhcp?.yiaddr ?? f.dhcp?.requestedIp ?? '',
      target: f.arp?.targetIp ?? '',
      user: this.userFor(p),
    }
  }

  private userFor(p: PacketSummary): string {
    if (p.facts.creds?.user) return p.facts.creds.user
    const c = this.conv(p)
    if (!c) return ''
    for (const n of c.packets) {
      if (n > p.no) break
      const u = this.pkt(n).facts.creds?.user
      if (u) return u
    }
    return ''
  }

  /** Literal, field-level description of a packet ("What it says"). Secrets are masked. */
  says(p: PacketSummary): string {
    const f = p.facts
    const t = f.tcp
    if (t && f.ip) {
      const kind = this.classify(p)
      const base = `${f.ip.src}:${t.srcPort} → ${f.ip.dst}:${t.dstPort}, TCP flags [${t.flagStr}], seq=${t.relSeq ?? t.seq}${t.flags.ack ? `, ack=${t.relAck ?? t.ack}` : ''}, len=${t.payloadLen}`
      if (kind.startsWith('tcp-')) return base
      return `${base}; ${p.protocol}: ${maskInfo(p)}`
    }
    const who = f.ip ? `${f.ip.src} → ${f.ip.dst}` : `${p.src} → ${p.dst}`
    return `${who}, ${p.protocol}: ${maskInfo(p)}`
  }

  explain(p: PacketSummary, kind = this.classify(p)): Explanation {
    const k = KB[kind]
    const v = this.vars(p)
    return { says: this.says(p), means: k.means(v), matters: k.matters, deeper: k.deeper }
  }

  label(p: PacketSummary, kind = this.classify(p)): string {
    return KB[kind].label(this.vars(p))
  }

  /** One-line plain-English description used for wrong-pick feedback and story narration. */
  describe(p: PacketSummary): string {
    const kind = this.classify(p)
    return `#${p.no} (${this.label(p, kind)}): ${KB[kind].means(this.vars(p))}`
  }
}

/** Info column with credential secrets masked. */
export function maskInfo(p: PacketSummary): string {
  const s = p.facts.creds?.secret
  if (!s) return p.info
  return p.info.split(s).join('•'.repeat(Math.min(8, s.length)))
}

/** Field keys that best illustrate a packet kind — used by "Show me" when a question names none. */
export function keyFieldsFor(kind: Kind): string[] {
  if (kind.startsWith('tcp')) return ['tcp.flags']
  if (kind === 'dns-query') return ['dns.qry.name', 'dns.flags.response']
  if (kind.startsWith('dns')) return ['dns.flags.rcode', 'dns.a', 'dns.aaaa']
  if (kind === 'http-request') return ['http.request.method', 'http.request.uri']
  if (kind.startsWith('http')) return ['http.response.code']
  if (kind === 'tls-ch') return ['tls.handshake.extensions_server_name', 'tls.handshake.type']
  if (kind === 'tls-sh') return ['tls.handshake.ciphersuite', 'tls.handshake.type']
  if (kind.startsWith('tls')) return ['tls.record.content_type']
  if (kind.startsWith('dhcp')) return ['dhcp.option.dhcp', 'dhcp.ip.your']
  if (kind.startsWith('arp')) return ['arp.opcode', 'arp.src.hw_mac', 'arp.src.proto_ipv4']
  if (kind.startsWith('icmp')) return ['icmp.type', 'icmp.code']
  if (kind === 'ftp-user' || kind === 'ftp-pass' || kind === 'ftp-cmd') return ['ftp.request.command', 'ftp.request.arg']
  if (kind.startsWith('ftp')) return ['ftp.response.code']
  if (kind === 'ssh-banner') return ['ssh.protocol']
  if (kind.startsWith('ntp')) return ['ntp.flags.mode']
  return []
}
