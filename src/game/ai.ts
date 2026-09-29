// Optional "AI explain" hook. OFF by default and not wired to any provider: PacketQuest never sends
// packet data anywhere unless a developer registers a provider AND the learner enables the setting.

export interface AiExplainRequest {
  question: string
  /** A short, already-masked textual summary of the packet(s) — never raw bytes. */
  context: string
}

export type AiProvider = (req: AiExplainRequest) => Promise<string>

let provider: AiProvider | null = null

/** Call from your own build to plug in a provider (e.g. a local model or your organisation's API). */
export function registerAiProvider(p: AiProvider | null): void {
  provider = p
}

export function aiAvailable(): boolean {
  return provider !== null
}

export async function aiExplain(req: AiExplainRequest): Promise<string> {
  if (!provider) throw new Error('No AI provider is registered in this build. See README → "Optional AI explain hook".')
  return provider(req)
}
