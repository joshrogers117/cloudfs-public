import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, getApi, type DoctorReport } from '../api'
import { Button, Spinner } from '../design'
import { healthOutcome } from './setupHealth'
import './healthCheck.css'

/** Shared by initial setup and the owner/admin-only troubleshooting section. */
export function HealthCheckPanel({ org, onContinue }: { org: string; onContinue?: () => void }) {
  const [report, setReport] = useState<DoctorReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [run, setRun] = useState(0)
  const [copyState, setCopyState] = useState('Copy diagnostic report')
  const loading = !report && !error
  const outcome = report ? healthOutcome(report) : null

  useEffect(() => {
    let alive = true
    // A stalled request must offer a recovery path rather than spin indefinitely.
    const timeout = window.setTimeout(() => {
      if (!alive) return
      alive = false
      setError('The server took too long to respond. Check your connection, then try again. If it continues, ask the server operator to check the Worker logs.')
    }, 30_000)
    getApi().doctor(org).then(result => {
      if (!alive) return
      window.clearTimeout(timeout)
      const next = healthOutcome(result)
      if (onContinue && next.autoContinue) onContinue()
      else setReport(result)
    }).catch((err: unknown) => {
      if (!alive) return
      window.clearTimeout(timeout)
      setError(err instanceof ApiError && (err.status === 401 || err.status === 403)
        ? 'Sign in with a workspace owner or admin account, then return to Workspace settings → Troubleshooting to run the checks.'
        : 'Check your internet connection and try again. If the server still cannot run the checks, ask the person who deployed it to review the Worker logs in Cloudflare.')
    })
    return () => { alive = false; window.clearTimeout(timeout) }
  }, [org, run, onContinue])

  function retry() {
    setReport(null)
    setError(null)
    setCopyState('Copy diagnostic report')
    setRun(n => n + 1)
  }

  async function copyReport() {
    if (!report) return
    const text = [`CloudFS readiness report · ${new Date().toISOString()}`,
      ...report.checks.map(check => `${check.name}: ${check.status}\n${check.detail}`)].join('\n\n')
    try {
      await navigator.clipboard.writeText(text)
      setCopyState('Copied')
    } catch {
      setCopyState('Copy unavailable; select the technical details below')
    }
  }

  return <div className="cfs-health">
    {loading ? <div className="cfs-health__loading" role="status"><Spinner size={20} />Checking your workspace…</div> : <>
      {error ? <div role="alert">
        <h2 className="cfs-health__heading">Couldn’t run the checks</h2>
        <p>{error}</p>
        <a href="/signin?next=%2Fworkspace" target="_blank" rel="noopener noreferrer">Open sign-in in a new tab</a>
      </div> : outcome && outcome.issues.length > 0 ? <>
        <div role="alert">
          <h2 className="cfs-health__heading">{outcome.canContinue ? 'A few things to review' : 'Your workspace needs attention'}</h2>
          <p>{outcome.canContinue ? 'You can continue setup while you resolve these warnings.' : 'Fix the issues below, then check again.'}</p>
        </div>
        <ul className="cfs-health__issues">
          {outcome.issues.map(issue => <li key={issue.key}>
            <div className="cfs-health__issue-title"><h3>{issue.title}</h3><span className={`cfs-health__severity cfs-health__severity--${issue.warning ? 'warn' : 'error'}`}>{issue.warning ? 'Warning' : 'Needs fixing'}</span></div>
            <p>{issue.impact}</p>
            <details>
              <summary>How to fix {issue.title.toLowerCase()}</summary>
              {issue.problems.map(problem => <div key={problem.name} className="cfs-health__repair">
                {issue.problems.length > 1 && <code>{problem.name}</code>}
                <ol>{problem.steps.map((step, i) => <li key={i}>{step}</li>)}</ol>
              </div>)}
              {issue.key === 'email_provider' && <Link to="/workspace#email" target="_blank" rel="noopener noreferrer">Open email settings ↗</Link>}
              <p className="cfs-health__next">After saving your changes, return here and select Check again.</p>
            </details>
            <details>
              <summary>Technical details for {issue.title.toLowerCase()}</summary>
              {issue.problems.map(problem => <p className="cfs-health__technical" key={problem.name}><code>{problem.name}</code><br />{problem.detail}</p>)}
            </details>
          </li>)}
        </ul>
        <details className="cfs-health__operator-help">
          <summary>Need help from your server operator?</summary>
          <p>Share the diagnostic report with the person who deployed this server. They can check the Worker’s configuration and logs, apply the repair steps above, and ask you to check again.</p>
          <nav aria-label="Server troubleshooting resources">
            <a href="https://dash.cloudflare.com/" target="_blank" rel="noopener noreferrer">Cloudflare dashboard ↗</a>
            <a href="https://developers.cloudflare.com/workers/configuration/secrets/" target="_blank" rel="noopener noreferrer">Manage Worker secrets ↗</a>
            <a href="https://developers.cloudflare.com/workers/observability/logs/workers-logs/" target="_blank" rel="noopener noreferrer">Find Worker logs ↗</a>
          </nav>
          <Button variant="subtle" onClick={() => void copyReport()}>{copyState}</Button>
        </details>
      </> : <p role="status">No issues found.</p>}
      <div className="cfs-health__actions">
        <Button variant="primary" onClick={retry}>Check again</Button>
        {onContinue && outcome?.canContinue && <Button variant="secondary" onClick={onContinue}>Continue with warnings</Button>}
      </div>
      {error && <a href="https://developers.cloudflare.com/workers/observability/logs/workers-logs/" target="_blank" rel="noopener noreferrer">How to find Worker logs ↗</a>}
    </>}
  </div>
}
