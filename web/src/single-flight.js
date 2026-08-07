/**
 * Coalesce concurrent work for the same key. A settled operation is removed so
 * a later call starts fresh, while different keys remain independent.
 *
 * @template K, V
 * @param {(key: K) => Promise<V>} run
 * @returns {(key: K) => Promise<V>}
 */
export function singleFlightByKey(run) {
  const pending = new Map()
  return (key) => {
    const existing = pending.get(key)
    if (existing) return existing
    const operation = Promise.resolve().then(() => run(key))
    pending.set(key, operation)
    void operation.finally(() => {
      if (pending.get(key) === operation) pending.delete(key)
    }).catch(() => {})
    return operation
  }
}
