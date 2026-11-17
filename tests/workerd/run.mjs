// The single-use stores' conformance kit on workerd's D1, fully local.
// Miniflare runs the test Worker (src/lib.rs) with two local D1 bindings:
// CLAIMS (the claims table) and BROKEN (no table: every statement faults).
//   1. /kit: every law of D1PrefixStore and D1ClaimStore, in the isolate
//      (every N from 2 to 33, under every schedule of the kit), the
//      re-takes after a release among them.
//   2. /kit-wrong: a store that reads, awaits, then writes on the same D1
//      breaks both concurrent prefix laws at every N from 2 to 33.
//   3. N = 2, 8, 32 simultaneous requests: one prefix and one txid (one Won,
//      the rest SameTransaction); one prefix and N txids (one Won, the rest
//      OtherTransaction, then the winner bound for every later claim); one
//      idempotency key (one true).
// Nothing leaves this process; Miniflare is disposed on every exit path.
//
//   worker-build --release        (worker-build 0.8.4; writes build/)
//   npm ci && node run.mjs
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import assert from 'node:assert/strict'

const { Miniflare } = await import(process.env.MINIFLARE_MODULE ?? 'miniflare')

const here = dirname(fileURLToPath(import.meta.url))
const SIZES = [2, 8, 32]
const KIT_SIZES = Array.from({ length: 32 }, (_, i) => i + 2)
const ns = `run-${Date.now()}-${randomBytes(4).toString('hex')}`
const hex64 = () => randomBytes(32).toString('hex')

const mf = new Miniflare({
  modules: true,
  scriptPath: resolve(here, 'build/worker/shim.mjs'),
  modulesRules: [
    { type: 'ESModule', include: ['**/*.js', '**/*.mjs'] },
    { type: 'CompiledWasm', include: ['**/*.wasm'] },
  ],
  compatibilityDate: '2024-01-01',
  d1Databases: ['CLAIMS', 'BROKEN'],
})

const lines = []
try {
  const call = async (method, path) => {
    const response = await mf.dispatchFetch(`http://kit.local${path}`, { method })
    const text = await response.text()
    assert.equal(response.status, 200, `${path}: ${text}`)
    return JSON.parse(text)
  }

  // 1. The kit in the isolate.
  const kit = await call('GET', `/kit?ns=${ns}`)
  assert.equal(kit.prefix.pass, true, JSON.stringify(kit.prefix))
  assert.deepEqual(kit.prefix.skipped, [])
  assert.equal(kit.prefix.checked.length, 4 * KIT_SIZES.length + 2)
  assert.equal(kit.claim.pass, true, JSON.stringify(kit.claim))
  assert.deepEqual(kit.claim.skipped, [])
  assert.equal(kit.claim.checked.length, 3 * KIT_SIZES.length + 1)
  for (const [side, law] of [['prefix', 'prefix: N re-takes after a release'], ['claim', 'claim: N re-takes after a release']]) {
    assert.equal(kit[side].checked.filter(([l]) => l === law).length, KIT_SIZES.length, law)
  }
  lines.push(`kit: D1PrefixStore ${kit.prefix.checked.length} laws pass, D1ClaimStore ${kit.claim.checked.length} laws pass`)

  // 2. The read-await-write store on the same D1.
  const wrong = await call('GET', `/kit-wrong?ns=${ns}-wrong`)
  assert.equal(wrong.laws.length, KIT_SIZES.length * 2)
  for (const law of wrong.laws) {
    assert.equal(law.pass, false, JSON.stringify(law))
    assert.match(law.detail, new RegExp(`^the number of Won: answered ${law.n},`), JSON.stringify(law))
  }
  lines.push(`kit-wrong: ${wrong.laws.map(l => `N=${l.n} ${l.detail.split(',')[0].replace('the number of Won: answered', 'Won x')}`).join('; ')}`)

  // 3. Simultaneous requests.
  const claim = (prefix, txid) => call('POST', `/claim?prefix=${encodeURIComponent(prefix)}&txid=${txid}`)
  for (const n of SIZES) {
    const prefix = `${ns}/one/${n}`
    const txid = hex64()
    const words = (await Promise.all(Array.from({ length: n }, () => claim(prefix, txid)))).map(a => a.word ?? `fault ${a.fault}`)
    assert.equal(words.filter(w => w === 'Won').length, 1, words.join(','))
    assert.equal(words.filter(w => w === 'SameTransaction').length, n - 1, words.join(','))

    const many = `${ns}/many/${n}`
    const txids = Array.from({ length: n }, hex64)
    const answers = (await Promise.all(txids.map(t => claim(many, t)))).map(a => a.word ?? `fault ${a.fault}`)
    const winners = answers.flatMap((w, i) => (w === 'Won' ? [i] : []))
    assert.equal(winners.length, 1, answers.join(','))
    assert.equal(answers.filter(w => w === 'OtherTransaction').length, n - 1, answers.join(','))
    const later = (await Promise.all(txids.map(t => claim(many, t)))).map(a => a.word)
    later.forEach((w, i) => assert.equal(w, i === winners[0] ? 'SameTransaction' : 'OtherTransaction'))

    const key = `${ns}/key/${n}`
    const keys = await Promise.all(Array.from({ length: n }, () => call('POST', `/claim-key?key=${encodeURIComponent(key)}`)))
    assert.equal(keys.filter(a => a.won === true).length, 1, JSON.stringify(keys))
    assert.equal(keys.filter(a => a.won === false).length, n - 1, JSON.stringify(keys))
    lines.push(`N=${n} requests: one txid 1 Won + ${n - 1} SameTransaction; ${n} txids 1 Won + ${n - 1} OtherTransaction, winner bound after; one key 1 true + ${n - 1} false`)
  }
} catch (e) {
  console.error('FAIL', e?.message ?? e)
  process.exitCode = 1
} finally {
  await mf.dispose()
}
for (const line of lines) console.log(line)
if (!process.exitCode) console.log('workerd D1 conformance: ok')
