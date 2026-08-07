export function singleFlightByKey<K, V>(run: (key: K) => Promise<V>): (key: K) => Promise<V>
