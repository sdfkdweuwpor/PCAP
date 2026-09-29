// Mode G — "Story Mode": narrated packet-by-packet walkthrough with quick checks.

import { KB, type Kind } from '../knowledge'
import type { Story, StoryStep } from '../types'
import type { GenCtx } from './context'
import { saysQuestion } from './says'

const SKIP: Kind[] = ['tcp-ack', 'other']

export function buildStory(ctx: GenCtx, maxSteps = 14): Story {
  const perKind = new Map<Kind, number>()
  const steps: StoryStep[] = []
  let sinceCheck = 0
  for (const p of ctx.packets) {
    if (steps.length >= maxSteps) break
    const kind = ctx.kindOf(p.no)
    if (SKIP.includes(kind)) continue
    // Repetitive traffic (scans, floods, tunnels): show each kind at most twice.
    const seen = perKind.get(kind) ?? 0
    if (seen >= 2) continue
    perKind.set(kind, seen + 1)
    const ex = ctx.explain(p.no)
    const info = KB[kind]
    const step: StoryStep = {
      packet: p.no,
      title: `#${p.no} · ${ctx.label(p.no)}`,
      narration: `${ex.means} ${seen === 0 && isSecurityRelevant(kind) ? info.matters : ''}`.trim(),
    }
    sinceCheck++
    if (sinceCheck >= 2 && seen === 0) {
      const q = saysQuestion(ctx, p.no, 'story')
      if (q) {
        step.check = { ...q, mode: 'story', prompt: 'Quick check: what is this packet saying?' }
        sinceCheck = 0
      }
    }
    steps.push(step)
  }
  const anomalies = ctx.index.anomalies
  if (anomalies.length && steps.length) {
    const a = anomalies[0]
    steps.push({
      packet: a.packets[0],
      title: `Analyst's view · ${a.title}`,
      narration: `${a.detail} This is why this capture is worth a closer look.`,
    })
  }
  return { id: `story:${ctx.index.fileName}`, title: `Walkthrough of ${ctx.index.fileName}`, steps }
}

function isSecurityRelevant(k: Kind): boolean {
  return ['ftp-pass', 'ftp-user', 'tls-ch', 'arp-reply', 'dns-query', 'tcp-rst-closed', 'http-request', 'dhcp-offer'].includes(k)
}
