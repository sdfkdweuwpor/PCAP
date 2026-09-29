# PacketQuest UI style guide — "analyst terminal"

The UI should look like a tool a senior engineer built for daily use: dense, text-first, keyboard-driven.
It must **not** look like generic AI-generated UI ("AI slop").

## Hard rules

- **Type:** IBM Plex Mono everywhere (`font-mono`/`font-sans` both map to it). VT323 (`font-display`) is only for the
  wordmark and rank-up headline. Never add Inter or another sans.
- **Colour:** use the tokens only (`bg-bg bg-panel bg-panel2 bg-panel3 border-line border-line-strong text-fg text-muted
  text-faint text-accent text-good text-bad text-warn`, protocol vars `var(--p-*)`). One accent per screen. No gradients,
  no purple/cyan "AI" palette, no glassmorphism, no `backdrop-blur`, no drop-shadow glows except `.glow` on the wordmark.
- **Shape:** hard edges. Radii are 0 via the theme (`rounded-*` renders square); don't fake roundness. 1px borders.
- **Structure:** panes use `<Frame title meta>` from `src/ui/term.tsx`. Buttons use `<Btn>` (`[ LABEL ]`), keys use `<Kbd>`,
  progress uses `<Meter>` (`█████░░░`). Prefer tables and aligned `dl` lists over cards. No grids of identical icon cards.
- **Icons:** don't use the SVG icon set for new work. Use text glyphs: `✓ ✗ ▸ ▾ + - ! ! [ ] [x] ▮ ▯ ↵ ← → ↑ ↓ ·`.
- **Copy:** terse, lowercase labels, factual. Say what a thing does and its numbers ("15 frames · 2 streams"), never
  aspirational slogans. No emoji. Errors are `error: …` / `ERR …` lines, successes `[ ok ]`.
- **Density:** 11–13px text, tight rows (22px packet rows), `tabular-nums` for numbers, uppercase + letter-spaced micro
  labels (`text-[11px] uppercase tracking-[0.12em] text-faint`).
- **Motion:** purposeful only (packet travel, answer feedback, highlight sweeps). Short, stepped or linear; no bouncy
  hover lifts, no scale-on-hover. Everything must degrade under `useReduced()` / `prefers-reduced-motion`.
- **Accessibility:** keep roles/aria labels, visible focus (`outline` from global CSS), never colour alone (pair with
  `✓/✗` or words), keyboard paths for every action.

## Themes

`data-screen` on `<html>`: `amber` (default phosphor), `green` (phosphor), `paper` (light line-printer). `data-crt="on"`
adds static scanlines on the phosphor screens. Test every change in all three.

Contrast floors (checked with WCAG relative luminance): `text-faint` is at least 4.5:1 on `bg`/`panel`/`panel2` and 4:1 on
`panel3`; `border-line-strong` (input borders) is at least 3:1 on `panel`; on paper, `--p-*` protocol colours are at least
4.5:1 on their 15% row tint and `--accent` is at least 4.5:1 on `bg`. Re-check these when editing tokens in `src/index.css`.

## Keyboard shortcuts

Single-key shortcuts (`o`, `1`-`8`, `n`, `/` and similar) must go through `hotkeyAllowed(e)` (or `consoleHotkeyAllowed(e)`
for shortcuts owned by the game console) in `src/ui/hotkeys.ts`. It honours the "single-key shortcuts" setting, ignores
modified keys and typing targets, and stands down while a modal dialog is open. Never add a bare `window` keydown
listener that reacts to a plain key without it.
