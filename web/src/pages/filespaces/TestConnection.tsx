/*
 * TestConnection — verify a storage config before creating/saving a filespace.
 *
 * Calls testStorage(org, …) with the chosen config and renders a result panel:
 *   - reachable / writable / readable / deletable confirmation
 *   - a PROMINENT warning when prefixEmpty is false (the bucket/prefix already
 *     holds objects — likely another filespace; use a dedicated empty bucket)
 *   - clear surfacing of probe errors
 *
 * The latest result is lifted to the parent (onResult) so it can recommend a
 * passing test and gate Create on an explicit acknowledgement when non-empty.
 * Owned by the Filespaces screen lane.
 */
import { useState } from 'react'
import { Banner, Button, Spinner } from '../../design'
import { IconCheck } from '../../design/icons'
import { getApi, type StorageTestResult } from '../../api'
import { hasErrors, toTestInput, validateStorage, type StorageConfig } from './storage'

export function TestConnection({
  org,
  config,
  result,
  onResult,
  onTestingChange,
}: {
  org: string
  config: StorageConfig
  result: StorageTestResult | null
  onResult: (result: StorageTestResult | null) => void
  onTestingChange?: (testing: boolean) => void
}) {
  const [testing, setTesting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Can't probe until the config is structurally valid (endpoint/region/bucket/cred).
  const ready = !hasErrors(validateStorage(config))

  async function run() {
    setError(null)
    setTesting(true)
    onTestingChange?.(true)
    onResult(null)
    try {
      const res = await getApi().testStorage(org, toTestInput(config))
      onResult(res)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The connection test failed to run.')
    } finally {
      setTesting(false)
      onTestingChange?.(false)
    }
  }

  return (
    <div className="cfs-test">
      <div className="cfs-test__bar">
        <Button
          type="button"
          variant="secondary"
          onClick={() => void run()}
          disabled={testing || !ready}
        >
          {testing ? (
            <>
              <Spinner size={14} /> Testing…
            </>
          ) : (
            'Test connection'
          )}
        </Button>
        {!ready && (
          <span className="cfs-test__hint">
            Fill in the endpoint, region, bucket, and credential to test.
          </span>
        )}
      </div>

      {error && <Banner kind="error" title="Couldn’t run the test" detail={error} />}

      {result && <TestResultPanel result={result} />}
    </div>
  )
}

export function TestResultPanel({ result, sharedBucket = false }: { result: StorageTestResult; sharedBucket?: boolean }) {
  const verified = result.reachable && result.canWrite && result.canRead && result.canDelete
  if (!result.reachable) {
    return (
      <Banner
        kind="error"
        title="Couldn’t reach the bucket"
        detail={result.error ?? 'The storage endpoint did not respond. Check the endpoint, region, bucket, and credential.'}
      />
    )
  }

  return (
    <div className="cfs-test__result">
      <Banner
        kind={verified ? 'success' : 'error'}
        title={verified ? 'Connection verified' : 'Storage needs attention'}
        detail={verified ? 'CloudFS can read, write, and protect your files in this bucket.' : result.error ?? 'Some required storage permissions are missing. Check the results below.'}
      />
      <ul className="cfs-test__checks">
        <CheckRow ok={result.canWrite} label="Write objects" />
        <CheckRow ok={result.canRead} label="Read objects" />
        <CheckRow ok={result.canDelete} label="Delete objects" />
      </ul>

      {sharedBucket ? null : result.prefixEmpty ? (
        <Banner
          kind="info"
          title="Bucket/prefix is empty"
          detail="No existing objects found — this bucket is safe to dedicate to a new filespace."
        />
      ) : (
        <Banner
          kind="warning"
          title="This bucket/prefix already contains objects"
          detail="It may belong to another filespace. Use a dedicated, empty bucket unless you’re certain. Sharing a bucket risks key collisions, lifecycle-rule deletion, and data loss."
        />
      )}

      {!sharedBucket && !result.prefixEmpty && result.sampleKeys && result.sampleKeys.length > 0 && (
        <div className="cfs-test__samples">
          <span className="cfs-test__samples-label">Existing keys found, for example:</span>
          <ul className="cfs-test__keys">
            {result.sampleKeys.map((k) => (
              <li key={k}>
                <code>{k}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function CheckRow({ ok, label }: { ok: boolean; label: string }) {
  return (
    <li className={`cfs-test__check ${ok ? 'is-ok' : 'is-no'}`}>
      <span className="cfs-test__check-mark">{ok ? <IconCheck /> : '—'}</span>
      {label}
      {!ok && <span className="cfs-test__check-note"> (not permitted)</span>}
    </li>
  )
}
