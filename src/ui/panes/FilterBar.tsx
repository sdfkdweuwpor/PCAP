import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useMemo, useRef, useState } from 'react'
import { compileFilter, FILTER_EXAMPLES, FilterError } from '../../core/filter/filter'
import { useCapture } from '../../store/capture'
import { hotkeyAllowed } from '../hotkeys'

/** The live match count re-runs the filter over every packet, so wait for a typing pause and skip huge captures. */
const PREVIEW_DELAY_MS = 150
const PREVIEW_MAX_PACKETS = 200_000

export function FilterBar() {
  const filterText = useCapture((s) => s.filterText)
  const filterError = useCapture((s) => s.filterError)
  const visible = useCapture((s) => s.visible)
  const packets = useCapture((s) => s.index?.packets)
  const total = packets?.length ?? 0
  const [draft, setDraft] = useState(filterText)
  // The applied filter changing (game, clear, examples) replaces whatever is being typed.
  const [appliedSeen, setAppliedSeen] = useState(filterText)
  if (filterText !== appliedSeen) {
    setAppliedSeen(filterText)
    setDraft(filterText)
  }
  const [settled, setSettled] = useState(filterText)
  const [showEx, setShowEx] = useState(false)
  const input = useRef<HTMLInputElement>(null)

  // "/" focuses the filter like many analyst tools.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && hotkeyAllowed(e)) {
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

  // Live preview of the match count (the list only changes on Enter): debounced, off for very large captures.
  const previewOn = total <= PREVIEW_MAX_PACKETS
  useEffect(() => {
    if (!previewOn) return
    const t = setTimeout(() => setSettled(draft), PREVIEW_DELAY_MS)
    return () => clearTimeout(t)
  }, [draft, previewOn])
  const preview = useMemo(() => {
    if (!previewOn || !packets || settled !== draft || draft === filterText || !draft.trim()) return null
    try {
      return `${packets.filter(compileFilter(draft)).length} would match`
    } catch (e) {
      return e instanceof FilterError ? 'incomplete' : null
    }
  }, [previewOn, packets, settled, draft, filterText])

  return (
    <div
      className="relative"
      // Keep the examples open while focus is anywhere in the bar or popover, so keyboard users can Tab into them.
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setShowEx(false)
      }}
      onKeyDown={(e) => {
        if (e.key === 'Escape' && showEx) {
          e.preventDefault()
          e.stopPropagation()
          setShowEx(false)
        }
      }}
    >
      <form
        className="flex items-stretch"
        onSubmit={(e) => {
          e.preventDefault()
          apply(draft)
          if (document.activeElement !== input.current) setShowEx(false)
        }}
      >
        <label
          className={`flex min-w-0 flex-1 items-center gap-2 border px-2 py-1 text-[13px] ${bad ? 'border-bad' : good ? 'border-good' : 'border-line-strong focus-within:border-accent'}`}
        >
          <span className={`shrink-0 ${bad ? 'text-bad' : good ? 'text-good' : 'text-accent'}`}>filter&gt;</span>
          <input
            ref={input}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onFocus={() => setShowEx(true)}
            placeholder="dns || tcp.flags.syn == 1"
            aria-label="Display filter"
            aria-invalid={bad}
            aria-describedby="filter-msg"
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            className="min-w-0 flex-1 bg-transparent outline-none placeholder:text-faint"
          />
          {preview && <span className="shrink-0 text-[11px] text-faint">{preview}</span>}
          {draft && (
            <button
              type="button"
              aria-label="Clear filter"
              onClick={() => {
                setDraft('')
                apply('')
                input.current?.focus() // this button unmounts; keep focus (and the examples) in the bar
              }}
              className="shrink-0 text-[11px] text-faint hover:text-fg"
            >
              clear
            </button>
          )}
        </label>
        <button type="submit" className="border border-l-0 border-accent bg-accent px-3 text-[11px] font-semibold uppercase tracking-[0.12em] text-accent-ink">
          apply ↵
        </button>
        <span className="hidden shrink-0 items-center pl-3 text-[11px] tabular-nums text-muted sm:flex" aria-live="polite">
          {visible ? `${visible.length}/${total}` : `${total}/${total}`}
        </span>
      </form>
      <p id="filter-msg" className="sr-only" aria-live="polite">
        {bad ? filterError : ''}
      </p>
      <AnimatePresence>
        {bad && (
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="mt-1 text-[11.5px] text-bad">
            error: {filterError}
          </motion.p>
        )}
        {showEx && !bad && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.08 }}
            className="absolute left-0 right-0 top-full z-30 mt-px border border-line-strong bg-panel p-2 text-[11.5px] shadow-[var(--shadow)]"
          >
            <p className="text-faint">fields: ip.addr ip.src ip.dst tcp.port udp.port tcp.flags.{'{syn,ack,fin,reset}'} dns.qry.name http.response.code frame.len … · ops: == != &gt; &lt; contains && || ! ()</p>
            <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
              {FILTER_EXAMPLES.map((ex) => (
                <button
                  key={ex}
                  type="button"
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => {
                    setDraft(ex)
                    apply(ex)
                    input.current?.focus()
                  }}
                  className="text-muted hover:text-accent"
                >
                  <span className="text-faint">$</span> {ex}
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
