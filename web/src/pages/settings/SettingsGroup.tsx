/*
 * Grouped-settings primitives — the web twin of the Mac app's Preferences /
 * Cache panes (docs/walkthrough/img/09-preferences.png, 08-cache.png).
 *
 * A SettingsGroup is a surface card with an ALL-CAPS section header and a stack
 * of hairline-separated SettingsRows. Each row pairs a leading title + optional
 * sublabel with a trailing control, exactly like the Mac grouped settings. Owned
 * by the Account-Settings lane; kept presentational + token-driven.
 */
import type { ReactNode } from 'react'
import './settings.css'

export function SettingsGroup({
  label,
  description,
  children,
}: {
  label: string
  description?: string
  children: ReactNode
}) {
  return (
    <section className="cfs-set-group">
      <header className="cfs-set-group__head">
        <span className="cfs-set-group__label">{label}</span>
        {description && <p className="cfs-set-group__desc">{description}</p>}
      </header>
      <div className="cfs-set-group__rows">{children}</div>
    </section>
  )
}

export function SettingsRow({
  title,
  sublabel,
  leading,
  trailing,
  children,
  align = 'center',
}: {
  title?: ReactNode
  sublabel?: ReactNode
  leading?: ReactNode
  trailing?: ReactNode
  /** Body content rendered below the title/trailing line (e.g. a form). */
  children?: ReactNode
  /** Vertical alignment of the title/trailing line. */
  align?: 'center' | 'top'
}) {
  return (
    <div className="cfs-set-row">
      <div className={`cfs-set-row__line cfs-set-row__line--${align}`}>
        {leading && <span className="cfs-set-row__leading">{leading}</span>}
        {(title || sublabel) && (
          <div className="cfs-set-row__text">
            {title && <span className="cfs-set-row__title">{title}</span>}
            {sublabel && <span className="cfs-set-row__sublabel">{sublabel}</span>}
          </div>
        )}
        {trailing && <div className="cfs-set-row__trailing">{trailing}</div>}
      </div>
      {children && <div className={`cfs-set-row__body${title || sublabel || leading || trailing ? '' : ' cfs-set-row__body--only'}`}>{children}</div>}
    </div>
  )
}
