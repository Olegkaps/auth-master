import assert from 'node:assert/strict'
import test from 'node:test'
import { singleFlightByKey } from './single-flight.js'

test('coalesces concurrent work for one key and clears after settlement', async () => {
  let calls = 0
  let release
  const gate = new Promise((resolve) => { release = resolve })
  const run = singleFlightByKey(async (key) => {
    calls += 1
    await gate
    return `${key}-${calls}`
  })

  const first = run('account-a')
  const second = run('account-a')
  assert.strictEqual(first, second)
  assert.equal(calls, 0)
  release()
  assert.deepEqual(await Promise.all([first, second]), ['account-a-1', 'account-a-1'])
  assert.equal(calls, 1)

  await run('account-a')
  assert.equal(calls, 2)
})

test('does not coalesce work for different keys', async () => {
  let calls = 0
  const run = singleFlightByKey(async (key) => {
    calls += 1
    return key
  })
  assert.deepEqual(await Promise.all([run('a'), run('b')]), ['a', 'b'])
  assert.equal(calls, 2)
})
