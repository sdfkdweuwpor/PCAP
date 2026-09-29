import { describe, expect, it } from 'vitest'
import { compileFilter, FilterError } from '../src/core/filter/filter'
import { SAMPLES } from '../src/samples/samples'
import { indexOf } from './helpers'

const web = indexOf(SAMPLES.find((s) => s.id === 'web-basic')!.build()).index
const nos = (f: string) => web.packets.filter(compileFilter(f)).map((p) => p.no)

describe('display filters', () => {
  it('protocol names', () => {
    expect(nos('dns')).toEqual([1, 2])
    expect(nos('http').length).toBe(4)
    expect(nos('udp')).toEqual([1, 2])
    expect(nos('tls')).toEqual([])
    expect(nos('')).toHaveLength(web.packets.length)
  })

  it('address and port comparisons', () => {
    expect(nos('ip.addr == 192.168.1.1')).toEqual([1, 2])
    expect(nos('ip.dst == 93.184.216.34').length).toBeGreaterThan(3)
    expect(nos('tcp.port == 80')).toEqual(nos('tcp'))
    expect(nos('ip.addr == 192.168.1.0/24')).toHaveLength(web.packets.length)
    expect(nos('ip.src == 93.184.216.0/24')).toEqual(nos('ip.src == 93.184.216.34'))
  })

  it('flags and boolean logic', () => {
    expect(nos('tcp.flags.syn == 1')).toEqual([3, 4])
    expect(nos('tcp.flags.syn == 1 && tcp.flags.ack == 0')).toEqual([3])
    expect(nos('tcp.flags.syn == 1 and !tcp.flags.ack == 1')).toEqual([3])
    expect(nos('dns || tcp.flags.fin == 1')).toEqual([1, 2, 13, 14])
    expect(nos('!(tcp || udp)')).toEqual([])
    expect(nos('not tcp')).toEqual([1, 2])
  })

  it('string and numeric operators', () => {
    expect(nos('http.response.code >= 400')).toEqual([11])
    expect(nos('http.request.method == "GET"')).toEqual([6, 10])
    expect(nos('dns.qry.name contains "example"')).toEqual([1, 2])
    expect(nos('frame.len > 300')).toEqual([8])
    expect(nos('tcp.dstport eq 80 && tcp.len gt 0')).toEqual([6, 10])
  })

  it('gives friendly errors for unsupported syntax', () => {
    const err = (f: string) => {
      try {
        compileFilter(f)
      } catch (e) {
        expect(e).toBeInstanceOf(FilterError)
        return (e as Error).message
      }
      throw new Error('expected an error for ' + f)
    }
    expect(err('ip.adr == 1.2.3.4')).toMatch(/ip\.addr/)
    expect(err('ip.addr = 1.2.3.4')).toMatch(/==/)
    expect(err('tcp.port ==')).toMatch(/needs a value/)
    expect(err('(dns')).toMatch(/parenthesis/)
    expect(err('dns http')).toMatch(/forget && or \|\|/)
    expect(err('tcp.flags.syn == 5')).toMatch(/1 or 0/)
    expect(err('http.host matches "x"')).toMatch(/isn't supported/)
  })
})
