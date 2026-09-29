// Writes the built-in synthetic captures to /samples so they can be opened in Wireshark too.
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { SAMPLES } from '../src/samples/samples'

const dir = join(import.meta.dirname, '..', 'samples')
mkdirSync(dir, { recursive: true })
for (const s of SAMPLES) {
  const bytes = s.build()
  writeFileSync(join(dir, s.fileName), bytes)
  console.log(`${s.fileName.padEnd(24)} ${String(bytes.length).padStart(7)} bytes  ${s.title}`)
}
