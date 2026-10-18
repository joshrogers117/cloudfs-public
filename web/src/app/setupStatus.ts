/*
 * Setup-status gate — fresh-deploy detection (auth-spec §1.1 step 1 / §2.5).
 *
 * `GET /v1/setup/status` is public and server-cached (10s); we additionally
 * memoize the resolved value per page load so the boot path (root redirect +
 * sign-in banner + the wizard itself) costs ONE request. Fails open to the
 * normal sign-in flow: a transient status failure must never lock a working
 * deployment out of /signin.
 */
import { useEffect, useState } from 'react'
import { getApi } from '../api'

let cached: boolean | null = null
let inflight: Promise<boolean> | null = null

/** Resolve (and memoize) whether the first-run wizard is needed. */
export function fetchSetupNeeded(): Promise<boolean> {
  if (cached !== null) return Promise.resolve(cached)
  if (!inflight) {
    inflight = getApi()
      .getSetupStatus()
      .then((s) => {
        cached = s.needed
        return cached
      })
      .catch(() => {
        cached = false // fail open — see header comment
        return false
      })
      .finally(() => {
        inflight = null
      })
  }
  return inflight
}

/**
 * Mark setup locally complete (called when the wizard finishes) so the root /
 * sign-in gates stop redirecting without a refetch.
 */
export function markSetupComplete(): void {
  cached = false
}

/** `null` while resolving, then whether the first-run wizard is needed. */
export function useSetupNeeded(): boolean | null {
  const [needed, setNeeded] = useState<boolean | null>(cached)
  useEffect(() => {
    if (needed !== null) return
    let alive = true
    void fetchSetupNeeded().then((n) => {
      if (alive) setNeeded(n)
    })
    return () => {
      alive = false
    }
  }, [needed])
  return needed
}
