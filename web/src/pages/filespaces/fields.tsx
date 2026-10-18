/*
 * Small form-field building blocks shared by Create + Settings, styled to match
 * the frozen design-system LabeledField/TextField but adding a labeled <select>
 * and an inline error slot. Owned by the Filespaces screen lane.
 */
import type { ReactNode, SelectHTMLAttributes } from 'react'
import { TextField } from '../../design'
import { IconWarn } from '../../design/icons'

/** A label + control wrapper with an optional hint and an inline error. */
export function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string
  htmlFor?: string
  hint?: string
  error?: string
  children: ReactNode
}) {
  return (
    <div className="cfs-fs-field">
      <label className="cfs-fs-field__label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <span className="cfs-fs-field__error">
          <IconWarn />
          {error}
        </span>
      ) : (
        hint && <span className="cfs-fs-field__hint">{hint}</span>
      )}
    </div>
  )
}

/** A labeled text input using the design TextField, with an inline error. */
export function LabeledInput({
  label,
  id,
  hint,
  error,
  ...rest
}: {
  label: string
  id: string
  hint?: string
  error?: string
} & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <Field label={label} htmlFor={id} hint={hint} error={error}>
      <TextField id={id} aria-invalid={error ? true : undefined} {...rest} />
    </Field>
  )
}

/** A labeled native select styled like the design TextField. */
export function LabeledSelect({
  label,
  id,
  hint,
  error,
  children,
  ...rest
}: {
  label: string
  id: string
  hint?: string
  error?: string
} & SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <Field label={label} htmlFor={id} hint={hint} error={error}>
      <select id={id} className="cfs-fs-select" aria-invalid={error ? true : undefined} {...rest}>
        {children}
      </select>
    </Field>
  )
}
