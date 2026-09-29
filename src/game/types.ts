// Question model shared by generators, the engine and the game UI.

export type Mode = 'pick' | 'says' | 'means' | 'field' | 'order' | 'anomaly' | 'story'
export type Tier = 'Recruit' | 'Analyst' | 'Hunter'
export type Concept =
  | 'protocols'
  | 'addressing'
  | 'tcp-handshake'
  | 'tcp-teardown'
  | 'tcp-flags'
  | 'udp'
  | 'dns'
  | 'http'
  | 'tls'
  | 'dhcp'
  | 'arp'
  | 'icmp'
  | 'cleartext'
  | 'recon'
  | 'dos'
  | 'exfil'
  | 'mitm'

export const MODE_INFO: Record<Mode, { letter: string; name: string; blurb: string }> = {
  pick: { letter: 'A', name: 'Which Line Is It?', blurb: 'Find the packet that matches a plain-English description.' },
  says: { letter: 'B', name: 'What Is This Line Saying?', blurb: 'Read one packet and choose what it literally says.' },
  means: { letter: 'C', name: 'What Does It Mean?', blurb: 'Interpret packets like an analyst: why does it matter?' },
  field: { letter: 'D', name: 'Field Hunt', blurb: 'Click the exact field or bytes in the details tree or hex pane.' },
  order: { letter: 'E', name: 'Put It In Order', blurb: 'Drag the exchange into the order it happened on the wire.' },
  anomaly: { letter: 'F', name: 'Spot the Anomaly', blurb: 'Hunt for attacks and misbehaviour across the whole capture.' },
  story: { letter: 'G', name: 'Story Mode', blurb: 'A narrated, packet-by-packet walkthrough with quick checks.' },
}

export const CONCEPT_LABEL: Record<Concept, string> = {
  protocols: 'Protocols',
  addressing: 'Addressing',
  'tcp-handshake': 'TCP handshake',
  'tcp-teardown': 'TCP teardown',
  'tcp-flags': 'TCP flags',
  udp: 'UDP',
  dns: 'DNS',
  http: 'HTTP',
  tls: 'TLS',
  dhcp: 'DHCP',
  arp: 'ARP',
  icmp: 'ICMP',
  cleartext: 'Cleartext creds',
  recon: 'Recon / scanning',
  dos: 'Denial of service',
  exfil: 'Exfiltration',
  mitm: 'Man-in-the-middle',
}

export interface Explanation {
  /** Literal meaning of the bytes. */
  says: string
  /** Plain-English interpretation. */
  means: string
  /** One-sentence security / analyst relevance. */
  matters: string
  /** RFC-level detail. */
  deeper?: string
}

export interface Highlight {
  packet: number
  fieldKeys?: string[]
}

interface QuestionBase {
  id: string
  mode: Mode
  tier: Tier
  concept: Concept
  prompt: string
  hint: string
  explanation: Explanation
  /** What "Show me" lights up and replays. */
  highlight: Highlight[]
  /** Packet shown as context while answering (modes B, C, D). */
  focusPacket?: number
}

export interface PickQuestion extends QuestionBase {
  kind: 'pick'
  answer: number[]
  multi: boolean
}

export interface ChoiceQuestion extends QuestionBase {
  kind: 'choice'
  options: string[]
  correct: number
}

export interface FieldQuestion extends QuestionBase {
  kind: 'field'
  packet: number
  /** Field keys that count as fully correct. */
  targetKeys: string[]
  /** Field keys that earn partial credit (right data, wrong representation / container). */
  partialKeys: string[]
  targetLabel: string
}

export interface OrderCard {
  id: string
  label: string
  packet: number
}

export interface OrderQuestion extends QuestionBase {
  kind: 'order'
  /** Cards in the correct order. The UI shuffles them. */
  cards: OrderCard[]
}

export type Question = PickQuestion | ChoiceQuestion | FieldQuestion | OrderQuestion

export interface StoryStep {
  packet: number
  title: string
  narration: string
  check?: ChoiceQuestion
}

export interface Story {
  id: string
  title: string
  steps: StoryStep[]
}

/** The learner's submission for a question. */
export type Answer =
  | { kind: 'pick'; packets: number[] }
  | { kind: 'choice'; index: number }
  | { kind: 'field'; key?: string; offset?: number; via: 'tree' | 'hex' }
  | { kind: 'order'; ids: string[] }

export interface Grade {
  /** 0 = wrong, 0.5 = partial, 1 = correct. */
  score: number
  feedback: string
}
