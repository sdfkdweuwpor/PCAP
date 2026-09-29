// Terminal UI primitives. Deliberately plain: 1px rules, no radii, no gradients, text-first.

import type { ButtonHTMLAttributes, ReactNode } from 'react'

/** A bordered pane with a title rule: ┌─ TITLE ───────── meta ─┐ */
export function Frame({
  title,
  meta,
  actions,
  children,
  className = '',
  bodyClass = '',
  id,
}: {
  title: ReactNode
  meta?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClass?: string
  id?: string
}) {
  return (
    <section id={id} aria-label={typeof title === 'string' ? title : undefined} className={`flex min-h-0 flex-col border border-line bg-panel ${className}`}>
      <header className="flex h-6 shrink-0 items-center gap-2 border-b border-line bg-panel2 px-2 text-[11px] uppercase tracking-[0.12em] text-muted">
        <span className="text-faint" aria-hidden>
          ┌
        </span>
        <span className="font-semibold text-fg">{title}</span>
        <span className="rule" aria-hidden />
        {meta && <span className="normal-case tracking-normal text-faint">{meta}</span>}
        {actions}
        <span className="text-faint" aria-hidden>
          ┐
        </span>
      </header>
      <div className={`min-h-0 flex-1 ${bodyClass}`}>{children}</div>
    </section>
  )
}

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { tone?: 'primary' | 'plain' | 'danger'; hotkey?: string; block?: boolean }

/** [ LABEL ] button. Primary is a solid block; plain inverts on hover like a selected terminal cell. */
export function Btn({ tone = 'plain', hotkey, block, className = '', children, ...rest }: BtnProps) {
  const base = 'inline-flex items-center justify-center gap-2 border px-3 py-1.5 text-[12px] font-semibold uppercase tracking-[0.1em] transition-colors disabled:cursor-not-allowed disabled:opacity-40'
  const tones = {
    primary: 'border-accent bg-accent text-accent-ink hover:brightness-110',
    plain: 'border-line-strong text-fg hover:border-accent hover:bg-accent hover:text-accent-ink',
    danger: 'border-bad text-bad hover:bg-bad hover:text-bg',
  }
  return (
    <button className={`${base} ${tones[tone]} ${block ? 'w-full' : ''} ${className}`} {...rest}>
      <span aria-hidden className="opacity-60">
        [
      </span>
      {children}
      {hotkey && <Kbd>{hotkey}</Kbd>}
      <span aria-hidden className="opacity-60">
        ]
      </span>
    </button>
  )
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="border border-current/40 px-1 text-[10px] font-normal normal-case tracking-normal opacity-75">{children}</kbd>
}

/** ASCII meter: ███████░░░░ */
export function Meter({ value, width = 16, className = '', label }: { value: number; width?: number; className?: string; label?: string }) {
  const v = Math.max(0, Math.min(1, value))
  const full = Math.round(v * width)
  return (
    <span className={`whitespace-pre font-mono ${className}`} role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v * 100)} aria-label={label}>
      <span className="text-accent">{'█'.repeat(full)}</span>
      <span className="text-faint">{'░'.repeat(width - full)}</span>
    </span>
  )
}

/** Small uppercase label/value pair used in status lines. */
export function Stat({ k, v, tone }: { k: string; v: ReactNode; tone?: 'good' | 'bad' | 'warn' | 'accent' }) {
  const color = tone ? { good: 'text-good', bad: 'text-bad', warn: 'text-warn', accent: 'text-accent' }[tone] : 'text-fg'
  return (
    <span className="whitespace-nowrap">
      <span className="text-faint">{k}</span> <span className={color}>{v}</span>
    </span>
  )
}
