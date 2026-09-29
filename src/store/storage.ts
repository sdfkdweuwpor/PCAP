// localStorage wrapper: every access is guarded so the app works in private mode, sandboxed
// iframes, or when storage is full/disabled.

export function loadJSON<T>(key: string, fallback: T): T {
  try {
    const raw = globalThis.localStorage?.getItem(key)
    if (!raw) return fallback
    return { ...fallback, ...JSON.parse(raw) } as T
  } catch {
    return fallback
  }
}

export function saveJSON(key: string, value: unknown): boolean {
  try {
    globalThis.localStorage?.setItem(key, JSON.stringify(value))
    return true
  } catch {
    return false
  }
}

export function removeKey(key: string): void {
  try {
    globalThis.localStorage?.removeItem(key)
  } catch {
    /* storage unavailable */
  }
}
