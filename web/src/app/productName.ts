// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * productName — the deployment's configured product display name.
 *
 * Read from the public auth config (GET /v1/auth/config/public → `productName`, backend
 * PRODUCT_NAME). The backend's built-in default is the lowercase slug "cloud-fs"; for
 * user-visible copy we show "CloudFS" in that case (and while the config is loading or if it
 * cannot be fetched).
 */
import { useEffect, useState } from 'react'
import { getApi } from '../api'

export const DEFAULT_PRODUCT_NAME = 'CloudFS'

/** Normalise the wire value to a display name. */
export function displayProductName(raw: string | undefined | null): string {
  const v = (raw ?? '').trim()
  if (!v || v.toLowerCase() === 'cloud-fs') return DEFAULT_PRODUCT_NAME
  return v
}

let cached: string | null = null
let inflight: Promise<string> | null = null

function load(): Promise<string> {
  if (cached) return Promise.resolve(cached)
  inflight ??= getApi()
    .getPublicAuthConfig()
    .then((c) => (cached = displayProductName(c.productName)))
    .catch(() => DEFAULT_PRODUCT_NAME)
    .finally(() => {
      inflight = null
    })
  return inflight
}

/** The product name to render; starts at the default and updates once the config resolves. */
export function useProductName(): string {
  const [name, setName] = useState(cached ?? DEFAULT_PRODUCT_NAME)
  useEffect(() => {
    let alive = true
    load().then((n) => alive && setName(n))
    return () => {
      alive = false
    }
  }, [])
  return name
}

/** Shared tagline for the sign-in and setup heroes. */
export const PRODUCT_TAGLINE = 'Your team’s files, ready where you work.'
