// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useMemo, useState } from 'react'
import { getApi, type DeploymentStorage, type Filespace, type StorageTestResult } from '../../api'
import { Banner, Button, Card, Spinner } from '../../design'
import { useAuth } from '../../app/auth'
import { LabeledInput } from './fields'
import { StorageForm } from './StorageForm'
import { TestConnection, TestResultPanel } from './TestConnection'
import { blankConfig, hasErrors, presetFor, toCreateInput, validateStorage, type StorageConfig, type StorageProvider } from './storage'
import './filespaces.css'

export function FilespaceCreateForm({ onCreated, onCancel, cancelLabel = 'Cancel', submitLabel = 'Create filespace' }: {
  onCreated: (filespace: Filespace) => void
  onCancel: () => void
  cancelLabel?: string
  submitLabel?: string
}) {
  const { session } = useAuth()
  const org = session?.org.slug ?? ''
  const [step, setStep] = useState(0)
  const [name, setName] = useState('')
  const [config, setConfig] = useState<StorageConfig>(() => blankConfig('r2'))
  const [storage, setStorage] = useState<DeploymentStorage | null>(null)
  const [storageLoading, setStorageLoading] = useState(true)
  const [storageError, setStorageError] = useState<string | null>(null)
  const [custom, setCustom] = useState(false)
  const [locationHelp, setLocationHelp] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [showErrors, setShowErrors] = useState(false)
  const [testResult, setTestResult] = useState<StorageTestResult | null>(null)
  const [testing, setTesting] = useState(false)
  const [ackNonEmpty, setAckNonEmpty] = useState(false)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let alive = true
    getApi().getDefaultStorage(org).then((result) => {
      if (!alive) return
      setStorage(result)
      setStorageLoading(false)
    }).catch((err: unknown) => {
      if (!alive) return
      setStorageError(err instanceof Error ? err.message : 'Could not check your workspace storage.')
      setStorageLoading(false)
    })
    return () => { alive = false }
  }, [org, reload])

  const storageErrors = useMemo(() => validateStorage(config), [config])
  const nameError = name.trim() ? undefined : 'Give this filespace a name.'
  const invalid = Boolean(nameError) || (custom ? hasErrors(storageErrors) : !storage?.configured)
  const nonEmptyConfirmed = custom && testResult?.reachable === true && testResult.prefixEmpty === false
  const failedTest = testResult !== null && !(testResult.reachable && testResult.canWrite && testResult.canRead && testResult.canDelete)
  const blocked = invalid || failedTest || (nonEmptyConfirmed && !ackNonEmpty) || submitting || storageLoading || testing

  function changeMode(value: boolean) {
    setCustom(value)
    setTestResult(null)
    setSubmitError(null)
    setAckNonEmpty(false)
  }

  async function testDefault() {
    setTesting(true)
    setTestResult(null)
    setSubmitError(null)
    try { setTestResult(await getApi().validateDefaultStorage(org)) }
    catch (err) { setSubmitError(err instanceof Error ? err.message : 'Could not test storage. Try again.') }
    finally { setTesting(false) }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setShowErrors(true)
    if (step < 2) {
      if (step === 0 && nameError) return
      if (step > 0 && blocked) return
      setShowErrors(false)
      setStep((current) => current + 1)
      return
    }
    if (blocked) return
    setSubmitting(true)
    setSubmitError(null)
    try {
      const input = custom ? toCreateInput(name, config) : {
        name: name.trim(), storageMode: 'deployment' as const,
        region: storage!.region, storageBackend: presetFor(storage!.provider as StorageProvider).label,
      }
      onCreated(await getApi().createFilespace(input))
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : 'Could not create the filespace.')
      setSubmitting(false)
    }
  }

  return (
    <form className="cfs-fs-form cfs-create-wizard" onSubmit={handleSubmit} noValidate>
      <ol className="cfs-wizard-steps" aria-label="Create filespace progress">{['Name', 'Storage', 'Review'].map((label, index) =>
        <li key={label} aria-current={index === step ? 'step' : undefined} className={index < step ? 'is-complete' : ''}><span>{index < step ? '✓' : index + 1}</span>{label}</li>)}</ol>
      <header className="cfs-wizard-heading"><h1>{['Name your filespace', 'Choose storage', 'Review your filespace'][step]}</h1>
        <p>{['A filespace is a shared drive your team opens in Finder.', 'Use the connected bucket or connect another one.', 'Check the name and storage before creating your shared drive.'][step]}</p></header>
      {submitError && <Banner kind="error" title="Something needs attention" detail={submitError} />}
      <fieldset disabled={submitting || testing} className="cfs-form-fields">
        {step === 0 && <Card title="Filespace name">
          <LabeledInput label="Name" id="fs-name" placeholder="Production" hint="Your team will see this name in the app and in Finder."
            error={showErrors ? nameError : undefined} value={name} autoFocus maxLength={100} onChange={(e) => setName(e.target.value)} />
        </Card>}
        {step === 1 && <Card title="Storage">
          <div className="cfs-storage-options">
            <label className={`cfs-storage-option${!custom ? ' is-selected' : ''}`}><input type="radio" name="storage-type" checked={!custom} onChange={() => changeMode(false)} /><span><strong>{storage ? presetFor(storage.provider as StorageProvider).label : 'Connected storage'}</strong><small>Already connected for {session?.org.name || 'your team'} during server setup.</small></span></label>
            <label className={`cfs-storage-option${custom ? ' is-selected' : ''}`}><input type="radio" name="storage-type" checked={custom} onChange={() => changeMode(true)} /><span><strong>Connect another bucket</strong><small>Use a different R2 bucket or another storage provider.</small></span></label>
          </div>
          {storageLoading && <div className="cfs-inline-status"><Spinner size={16} /> Checking connected storage…</div>}
          {storageError && <Banner kind="warning" title="Connected storage could not be checked" detail={storageError}
            actionTitle="Try again" onAction={() => { setStorageLoading(true); setStorageError(null); setReload((n) => n + 1) }} />}
          {!storageLoading && !custom && storage?.configured && <details className="cfs-storage-connection"><summary>Connection details</summary>
            <div className="cfs-default-storage">
              <span className="cfs-storage-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0" /></svg></span>
              <div><strong>{presetFor(storage.provider as StorageProvider).label}</strong><p>{storage.bucket}</p></div>
              <span className="cfs-fs-rolepill">Connected during setup</span>
            </div>
            <p className="cfs-fs-card__lead">Each filespace keeps its files separate in this bucket.</p>
            <Button variant="secondary" type="button" onClick={() => void testDefault()} disabled={testing}>
              {testing ? 'Checking connection…' : 'Test connection'}
            </Button>
            {testResult && <TestResultPanel result={testResult} sharedBucket />}
          </details>}
          {!storageLoading && !custom && storage && !storage.configured && <Banner kind="warning" title="Connect storage to continue"
            detail="Your deployment does not have a complete storage connection yet. Configure it during deployment, or connect a bucket below." />}
          <details className="cfs-storage-location" open={locationHelp} onToggle={e => setLocationHelp(e.currentTarget.open)}>
            <summary>Need a different storage location?</summary>
            <p>Location belongs to the bucket. Connecting a filespace does not move it.</p>
            <ol>
              <li>For R2, create a bucket in Cloudflare and choose a location preference, or a jurisdiction if you need a data-residency boundary.</li>
              <li>Select “Connect another bucket” here and enter that bucket’s connection details.</li>
            </ol>
            <p>R2 location preferences are best-effort. The connection value “auto” is not a physical region, so CloudFS cannot show the bucket’s location from it.</p>
            <a href="https://developers.cloudflare.com/r2/reference/data-location/" target="_blank" rel="noopener noreferrer">How to choose an R2 location ↗</a>
            {!custom && <Button type="button" variant="subtle" onClick={() => changeMode(true)}>Connect a bucket in another location</Button>}
          </details>
          {custom && <StorageForm org={org} config={config} errors={showErrors ? storageErrors : {}} onChange={(next) => {
            setConfig(next); setTestResult(null); setAckNonEmpty(false)
          }} />}
        </Card>}
        {step === 1 && custom && <Card title="Check your connection">
          <TestConnection key={JSON.stringify(config)} org={org} config={config} result={testResult} onResult={setTestResult} onTestingChange={setTesting} />
          {nonEmptyConfirmed && <label className="cfs-ack"><input type="checkbox" checked={ackNonEmpty} onChange={(e) => setAckNonEmpty(e.target.checked)} />
            <span>I recognize the existing objects in this bucket and want to use it.</span></label>}
        </Card>}
        {step === 2 && <Card title="Filespace summary"><dl className="cfs-wizard-summary"><div><dt>Name</dt><dd>{name.trim()}</dd></div><div><dt>Storage</dt><dd>{custom ? presetFor(config.provider).label : storage ? presetFor(storage.provider as StorageProvider).label : 'Unavailable'}</dd></div><div><dt>Bucket</dt><dd>{custom ? config.bucket : storage?.bucket}</dd></div><div><dt>Location</dt><dd>{(custom ? config.provider : storage?.provider) === 'r2' ? 'Set on the R2 bucket' : (custom ? config.region : storage?.region)}</dd></div></dl></Card>}
      </fieldset>
      <div className="cfs-fs-form__actions">
        <Button type="submit" size="large" block disabled={step === 0 ? !name.trim() : blocked}>{submitting ? 'Creating filespace…' : step === 2 ? submitLabel : 'Continue'}</Button>
        <div className="cfs-wizard-back">{step > 0 && <Button type="button" variant="subtle" disabled={submitting || testing} onClick={() => { setStep((current) => current - 1); setShowErrors(false) }}>Back</Button>}<Button type="button" variant="subtle" disabled={submitting || testing} onClick={onCancel}>{cancelLabel}</Button></div>
      </div>
    </form>
  )
}
