// Single place that decides whether a global single-key shortcut may fire.

import { useProgress } from '../store/progress'

let consoleVisible = true

/** The mobile bottom sheet reports whether the game console is on screen. */
export function setConsoleVisible(v: boolean): void {
  consoleVisible = v
}

export function isTypingTarget(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false
  return t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || t.isContentEditable
}

/**
 * True when a plain-key shortcut should run: shortcuts are enabled in settings, no modifier is held, the key isn't
 * going into a form field, nothing else already handled it, and no modal dialog is open.
 */
export function hotkeyAllowed(e: KeyboardEvent): boolean {
  if (!useProgress.getState().settings.hotkeys) return false
  if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || e.repeat) return false
  if (isTypingTarget(e.target)) return false
  return !document.querySelector('[aria-modal="true"]')
}

/** Shortcuts owned by the game console additionally require the console to be visible. */
export function consoleHotkeyAllowed(e: KeyboardEvent): boolean {
  return consoleVisible && hotkeyAllowed(e)
}
