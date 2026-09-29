// Packs dist/ into a single self-contained page for hosted-artifact viewers:
// CSS and JS inlined, Latin font subsets embedded as woff2 data URIs, the parser worker kept as a sibling file.
// Usage: npm run build && node scripts/build-artifact.mjs  →  dist-artifact/packetquest.html + worker
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const dist = 'dist'
const out = 'dist-artifact'
const assets = join(dist, 'assets')
const files = readdirSync(assets)
const js = files.find((f) => /^index-.*\.js$/.test(f))
const css = files.find((f) => /^index-.*\.css$/.test(f))
const worker = files.find((f) => /^parser\.worker-.*\.js$/.test(f))
if (!js || !css || !worker) throw new Error('run `npm run build` first')

let style = readFileSync(join(assets, css), 'utf8')
style = style.replace(/@font-face\{[^}]*\}/g, (block) => {
  const woff2 = /url\(\.\/([^)]+\.woff2)\)/.exec(block)?.[1]
  // Keep only Latin and Latin Extended subsets; everything else falls back to the system mono.
  if (!woff2 || !/-latin-(ext-)?\d{3}-/.test(woff2)) return ''
  const data = readFileSync(join(assets, woff2)).toString('base64')
  return block.replace(/src:[^;}]+/, `src:url(data:font/woff2;base64,${data}) format("woff2")`)
})

const script = readFileSync(join(assets, js), 'utf8').replace(/<\/script/gi, '<\\/script')
const page = `<title>PacketQuest</title>
<meta name="description" content="Packet-capture reading drills. Load a .pcap/.pcapng; it is parsed in this tab and never uploaded.">
<style>${style}</style>
<div id="root"></div>
<script type="module">${script}</script>
`
rmSync(out, { recursive: true, force: true })
mkdirSync(out, { recursive: true })
writeFileSync(join(out, 'packetquest.html'), page)
writeFileSync(join(out, worker), readFileSync(join(assets, worker)))
console.log(`${out}/packetquest.html ${(page.length / 1024).toFixed(0)} KB · worker ${worker}`)
