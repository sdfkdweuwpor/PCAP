// Prints a Wireshark-like packet list for each sample (dev aid).
import { buildIndex } from '../src/core/index/indexer'
import { SAMPLES } from '../src/samples/samples'

const only = process.argv[2]
for (const s of SAMPLES) {
  if (only && s.id !== only) continue
  const idx = buildIndex(s.build(), s.fileName)
  console.log(`\n=== ${s.title} (${idx.format}) ${idx.packets.length} pkts, ${idx.conversations.length} convs`)
  for (const p of idx.packets.slice(0, only ? 400 : 14)) {
    console.log(`${String(p.no).padStart(3)} ${p.relTime.toFixed(4).padStart(8)} ${p.src.padEnd(18)} ${p.dst.padEnd(18)} ${p.protocol.padEnd(8)} ${String(p.origLen).padStart(5)} ${p.info}  [${p.color}]${p.facts.malformed ? ' MALFORMED ' + p.facts.malformed : ''}`)
  }
  for (const a of idx.anomalies) console.log(`  ! ${a.kind}: ${a.detail}`)
  if (idx.warnings.length) console.log('  warnings', idx.warnings)
}
