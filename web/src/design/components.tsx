/*
 * cloud-fs design-system components — the web twin of the Mac app's
 * Components.swift / PaneChrome.swift. Pure presentation, token-driven styling.
 *
 * Exports: Button, TextField, LabeledField, Card, Banner, StatusDot,
 *          PaneHeader, SegmentedControl, Spinner, StatePane, SectionLabel.
 * BrandMark lives in BrandMark.tsx.
 */
import {
  forwardRef,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from 'react'
import './components.css'
import { IconInfo, IconCheck, IconWarn, IconError } from './icons'

/* ===== Button =========================================================== */
export type ButtonVariant = 'primary' | 'secondary' | 'subtle' | 'destructive'
export type ButtonSize = 'regular' | 'large' | 'small'

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: ButtonSize
  block?: boolean
  leading?: ReactNode
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'primary', size = 'regular', block, leading, className, children, ...rest },
  ref,
) {
  const cls = [
    'cfs-btn',
    `cfs-btn--${variant}`,
    size !== 'regular' ? `cfs-btn--${size}` : '',
    block ? 'cfs-btn--block' : '',
    className ?? '',
  ]
    .filter(Boolean)
    .join(' ')
  return (
    <button ref={ref} className={cls} {...rest}>
      {leading}
      {children}
    </button>
  )
})

/* ===== TextField ======================================================== */
type TextFieldProps = InputHTMLAttributes<HTMLInputElement>

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(function TextField(
  { className, ...rest },
  ref,
) {
  return <input ref={ref} className={['cfs-input', className ?? ''].join(' ').trim()} {...rest} />
})

/* ===== LabeledField ===================================================== */
type LabeledFieldProps = TextFieldProps & {
  label: string
  icon?: ReactNode
  hint?: string
}

export const LabeledField = forwardRef<HTMLInputElement, LabeledFieldProps>(function LabeledField(
  { label, icon, hint, id, ...rest },
  ref,
) {
  const fieldId = id ?? `cfs-field-${label.replace(/\s+/g, '-').toLowerCase()}`
  return (
    <div className="cfs-field">
      <label className="cfs-field__label" htmlFor={fieldId}>
        {icon}
        {label}
      </label>
      <TextField id={fieldId} ref={ref} {...rest} />
      {hint && (
        <span className="cfs-field__hint">
          <IconWarn />
          {hint}
        </span>
      )}
    </div>
  )
})

/* ===== Card ============================================================= */
type CardProps = {
  title?: string
  className?: string
  children: ReactNode
}

export function Card({ title, className, children }: CardProps) {
  return (
    <div className={['cfs-card', className ?? ''].join(' ').trim()}>
      {title && <div className="cfs-card__title">{title}</div>}
      {children}
    </div>
  )
}

/* ===== Banner =========================================================== */
export type BannerKind = 'info' | 'success' | 'warning' | 'error'

type BannerProps = {
  kind?: BannerKind
  title: string
  detail?: string
  actionTitle?: string
  onAction?: () => void
}

const BANNER_ICON: Record<BannerKind, ReactNode> = {
  info: <IconInfo />,
  success: <IconCheck />,
  warning: <IconWarn />,
  error: <IconError />,
}

export function Banner({ kind = 'info', title, detail, actionTitle, onAction }: BannerProps) {
  return (
    <div className={`cfs-banner cfs-banner--${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <span className="cfs-banner__icon">{BANNER_ICON[kind]}</span>
      <div className="cfs-banner__body">
        <span className="cfs-banner__title">{title}</span>
        {detail && <span className="cfs-banner__detail">{detail}</span>}
      </div>
      {actionTitle && onAction && (
        <Button className="cfs-banner__action" variant="subtle" size="small" onClick={onAction}>
          {actionTitle}
        </Button>
      )}
    </div>
  )
}

/* ===== StatusDot ======================================================== */
export type StatusColor =
  | 'ok'
  | 'busy'
  | 'paused'
  | 'warn'
  | 'error'
  | 'idle'
  | 'accent'

const STATUS_VAR: Record<StatusColor, string> = {
  ok: 'var(--cfs-status-ok)',
  busy: 'var(--cfs-status-busy)',
  paused: 'var(--cfs-status-paused)',
  warn: 'var(--cfs-status-warn)',
  error: 'var(--cfs-status-error)',
  idle: 'var(--cfs-status-idle)',
  accent: 'var(--cfs-accent)',
}

export function StatusDot({
  color,
  size = 8,
  label,
}: {
  color: StatusColor
  size?: number
  label?: string
}) {
  return (
    <span
      className="cfs-dot"
      style={{ width: size, height: size, background: STATUS_VAR[color] }}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  )
}

/* ===== PaneHeader ======================================================= */
export function PaneHeader({
  title,
  subtitle,
  trailing,
}: {
  title: string
  subtitle?: string
  trailing?: ReactNode
}) {
  return (
    <header className="cfs-pane-header">
      <div className="cfs-pane-header__titles">
        <h1 className="cfs-pane-header__title">{title}</h1>
        {subtitle && (
          <span className="cfs-pane-header__subtitle" title={subtitle}>
            {subtitle}
          </span>
        )}
      </div>
      {trailing && <div className="cfs-pane-header__trailing">{trailing}</div>}
    </header>
  )
}

/* ===== SegmentedControl ================================================= */
export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  block,
}: {
  options: { value: T; label: string }[]
  value: T
  onChange: (value: T) => void
  block?: boolean
}) {
  return (
    <div
      className={['cfs-segmented', block ? 'cfs-segmented--block' : ''].join(' ').trim()}
      role="group"
    >
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          className="cfs-segmented__seg"
          aria-pressed={opt.value === value}
          onClick={() => onChange(opt.value)}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

/* ===== Spinner ========================================================== */
export function Spinner({ size = 18 }: { size?: number }) {
  return (
    <span
      className="cfs-spinner"
      style={{ width: size, height: size }}
      role="progressbar"
      aria-label="Loading"
    />
  )
}

/* ===== StatePane ======================================================== */
export function StatePane({
  state,
  loadingText = 'Loading…',
  glyph = '☁',
  title,
  hint,
  message,
  onRetry,
}: {
  state: 'loading' | 'empty' | 'error'
  loadingText?: string
  glyph?: ReactNode
  title?: string
  hint?: string
  message?: string
  onRetry?: () => void
}) {
  if (state === 'loading') {
    return (
      <div className="cfs-statepane">
        <Spinner size={26} />
        <span className="cfs-statepane__hint">{loadingText}</span>
      </div>
    )
  }
  if (state === 'error') {
    return (
      <div className="cfs-statepane cfs-statepane--error">
        <span className="cfs-statepane__glyph">
          <IconWarn size={40} />
        </span>
        <span className="cfs-statepane__title">{title ?? 'Couldn’t load'}</span>
        {message && <span className="cfs-statepane__hint">{message}</span>}
        {onRetry && (
          <Button variant="secondary" onClick={onRetry}>
            Try Again
          </Button>
        )}
      </div>
    )
  }
  return (
    <div className="cfs-statepane">
      <span className="cfs-statepane__glyph">{glyph}</span>
      {title && <span className="cfs-statepane__title">{title}</span>}
      {hint && <span className="cfs-statepane__hint">{hint}</span>}
    </div>
  )
}

/* ===== SectionLabel ===================================================== */
export function SectionLabel({ children }: { children: ReactNode }) {
  return <span className="cfs-section-label">{children}</span>
}
