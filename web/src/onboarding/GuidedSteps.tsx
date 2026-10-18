/*
 * GuidedSteps — the collapsible "How to get these" panel shared by the storage
 * and email wizards. Renders a catalog entry's ordered steps as a numbered list,
 * each with its deep link to the right console page, plus any DNS records the
 * provider needs and a link to the official docs.
 *
 * Pure presentation, token-driven, design-system aware. The panel starts open the
 * first time a provider is picked so self-hosters see the guidance up front, but
 * can be collapsed once they're comfortable.
 */
import { useState } from 'react'
import { IconInfo } from '../design/icons'
import type { CatalogEntry } from './catalog'
import './onboarding.css'

/** A monospaced value with a copy button — e.g. the OIDC redirect URI to register. */
export function CopyableCode({ value, label = 'value' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard?.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      /* clipboard may be unavailable; the value is selectable inline */
    }
  }
  return (
    <span className="cfs-ob-copy">
      <code className="cfs-ob-copy__value">{value}</code>
      <button
        type="button"
        className="cfs-ob-copy__btn"
        onClick={() => void copy()}
        aria-label={`Copy ${label}`}
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
    </span>
  )
}

export function ProviderLogo({ entry, size = 28 }: { entry: CatalogEntry; size?: number }) {
  return (
    <span
      className="cfs-ob-logo"
      aria-hidden
      style={{
        width: size,
        height: size,
        // Tint the tile faintly with the provider color; fall back to the accent.
        background: entry.tint ? `${entry.tint}22` : 'var(--cfs-accent-soft)',
        color: entry.tint ?? 'var(--cfs-accent)',
        fontSize: Math.round(size * 0.5),
      }}
    >
      {entry.initial}
    </span>
  )
}

/** An external deep-link, opening in a new tab with safe rel. */
export function DeepLink({ href, label }: { href: string; label: string }) {
  return (
    <a className="cfs-ob-link" href={href} target="_blank" rel="noreferrer noopener">
      {label}
      <svg width="11" height="11" viewBox="0 0 16 16" fill="none" aria-hidden>
        <path
          d="M6 3h7v7M13 3 6.5 9.5M11 9.5V13H3V5h3.5"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </a>
  )
}

export function GuidedSteps({
  entry,
  defaultOpen = true,
  title = 'How to get these',
}: {
  entry: CatalogEntry
  defaultOpen?: boolean
  title?: string
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <section className={`cfs-ob-guide ${open ? 'is-open' : ''}`}>
      <button
        type="button"
        className="cfs-ob-guide__head"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <ProviderLogo entry={entry} size={24} />
        <span className="cfs-ob-guide__title">
          {title} — {entry.name}
        </span>
        <svg
          className="cfs-ob-guide__chevron"
          width="12"
          height="12"
          viewBox="0 0 16 16"
          fill="none"
          aria-hidden
        >
          <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {open && (
        <div className="cfs-ob-guide__body">
          <ol className="cfs-ob-steps">
            {entry.steps.map((step, i) => (
              <li key={i} className="cfs-ob-step">
                <span className="cfs-ob-step__num">{i + 1}</span>
                <div className="cfs-ob-step__text">
                  <span className="cfs-ob-step__title">{step.title}</span>
                  <p className="cfs-ob-step__body">{step.body}</p>
                  {step.code && <CopyableCode value={step.code} label="redirect URI" />}
                  {step.link && <DeepLink href={step.link.href} label={step.link.label} />}
                </div>
              </li>
            ))}
          </ol>

          {entry.dns && entry.dns.length > 0 && <DnsRecords entry={entry} />}

          <p className="cfs-ob-guide__docs">
            <IconInfo />
            <span>
              Need more detail? Read the official{' '}
              <DeepLink href={entry.docsUrl} label={`${entry.name} docs`} />.
            </span>
          </p>
        </div>
      )}
    </section>
  )
}

function DnsRecords({ entry }: { entry: CatalogEntry }) {
  return (
    <div className="cfs-ob-dns">
      <span className="cfs-ob-dns__label">DNS records to publish</span>
      <p className="cfs-ob-dns__lead">
        Add these at your DNS host to verify your domain. Exact values marked “…” are generated
        in the provider’s dashboard — copy them from there.
      </p>
      <div className="cfs-ob-dns__table" role="table">
        <div className="cfs-ob-dns__row cfs-ob-dns__row--head" role="row">
          <span role="columnheader">Type</span>
          <span role="columnheader">Host</span>
          <span role="columnheader">Value</span>
        </div>
        {entry.dns!.map((rec, i) => (
          <div key={i} className="cfs-ob-dns__row" role="row">
            <span role="cell">
              <code className="cfs-ob-dns__type">{rec.type}</code>
            </span>
            <span role="cell">
              <code>{rec.host}</code>
            </span>
            <span role="cell">
              <code className="cfs-ob-dns__value">{rec.value}</code>
              {rec.note && <span className="cfs-ob-dns__note">{rec.note}</span>}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
