# PacketQuest — working notes for Claude

- Stack: React 19 + TypeScript (erasableSyntaxOnly: no enums/parameter properties) + Vite 8 + Tailwind v4 + framer-motion + zustand. Tests: `npx vitest run`. Types: `npx tsc -b`. Lint: `npx oxlint src`.
- UI must follow docs/STYLE.md (analyst-terminal look, no generic AI styling). Primitives live in src/ui/term.tsx.
- Pipeline: src/core (container → dissect → indexer, runs in src/worker) → src/game (knowledge, generators, engine) → src/store → src/ui.

## Model routing (use the project subagents in .claude/agents)

| Work | Agent | Model |
| --- | --- | --- |
| Architecture, parser/dissector logic, question-engine design, core game UI, reviewing agent output | main session | Opus |
| Restyling or building a self-contained component from a written brief | `ui-reskin` | Sonnet |
| Writing/updating Vitest tests | `test-writer` | Sonnet |
| Browser smoke tests and screenshots | `browser-check` | Haiku |
| README / docs edits from a fact list | `docs-writer` | Haiku |

Give each agent a disjoint set of files so they can run in parallel, and review their diffs before committing.
