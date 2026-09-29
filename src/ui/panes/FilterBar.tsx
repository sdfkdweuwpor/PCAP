import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useRef, useState } from 'react'
import { FILTER_EXAMPLES } from '../../core/filter/filter'
import { useCapture } from '../../store/capture'
import { IconFilter, IconX } from '../icons'

export function FilterBar() {
  const filterText = useCapture((s) => s.filterText)
  const filterError = useCapture((s) => s.filterError)
  const visible = useCapture((s) => s.visible)
  const total = useCapture((s) => s.index?.packets.length ?? 0)
  const [draft, setDraft] = useState(filterText)
  const [showEx, setShowEx] = useState(false)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => setDraft(filterText), [filterText])

  // "/" focuses the filter like many analyst tools.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault()
        input.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const apply = (t: string) => useCapture.getState().setFilter(t)
  const bad = !!filterError && draft === filterText
  const good = !filterError && !!filterText && draft === filterText

  return (
    <div className="relative">
      <form
        className="flex items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          apply(draft)
        }}
      >
        <div
          className={`flex min-w-0 flex-1 items-center gap-2 rounded-lg border px-2 py-1.5 font-mono text-sm transition-colors ${
            bad ? 'border-bad bg-bad/10' : good ? 'border-good/70 bg-good/10' : 'border-line bg-panel2'
          }`}
        >
          <IconFilter size={14} className="shrink-0 text-muted" />
          <input
            ref={input}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onFocus={() => setShowEx(true)}
            onBlur={() => setTimeout(() => setShowEx(false), 150)}
            placeholder='Apply a display filter … e.g. dns || tcp.flags.syn == 1   (press "/")'
            aria-label="Display filter"
            aria-invalid={bad}
            aria-describedby="filter-msg"
            spellCheck={false}
            className="min-w-0 flex-1 bg-transparent outline-none placeholder:text-faint"
          />
          {draft && (
            <button
              type="button"
              aria-label="Clear filter"
              onClick={() => {
                setDraft('')
                apply('')
              }}
              className="text-muted hover:text-fg"
            >
              <IconX size={14} />
            </button>
          )}
        </div>
        <button type="submit" className="rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-accent-ink">
          Apply
        </button>
        <span className="hidden shrink-0 text-xs text-muted sm:inline" aria-live="polite">
          {visible ? `${visible.length} / ${total}` : `${total}`} shown
        </span>
      </form>
      <p id="filter-msg" className="sr-only" aria-live="polite">
        {bad ? filterError : ''}
      </p>
      <AnimatePresence>
        {bad && (
          <motion.p initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="mt-1 text-xs text-bad">
            {filterError}
          </motion.p>
        )}
        {showEx && !bad && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="absolute left-0 right-0 top-full z-30 mt-1 flex flex-wrap gap-1 rounded-lg border border-line bg-panel p-2 shadow-xl"
          >
            <span className="w-full text-[11px] text-muted">Supported: ip.addr, ip.src/dst, tcp.port, udp.port, tcp.flags.*, dns, http, tls, arp, dhcp, icmp, frame.len, dns.qry.name, http.response.code … with == != &gt; &lt; contains && || ! ( )</span>
            {FILTER_EXAMPLES.map((ex) => (
              <button
                key={ex}
                type="button"
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => {
                  setDraft(ex)
                  apply(ex)
                }}
                className="rounded border border-line px-2 py-0.5 font-mono text-[11px] hover:border-accent hover:text-accent"
              >
                {ex}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
