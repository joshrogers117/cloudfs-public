import { useId, useRef, useState, type ClipboardEvent, type KeyboardEvent } from 'react'
import './EmailChipsInput.css'
import { formatEmailTokens, mergeUniqueEmails, parseEmailTokens } from './emailChips'

export interface EmailChipsInputProps {
  /** Accepted addresses, controlled by the parent. */
  values: string[]
  onChange: (values: string[]) => void
  disabled?: boolean
  id?: string
  label?: string
  placeholder?: string
  /** Called with false while a non-empty draft is not a valid email address. */
  onDraftValidityChange?: (isValid: boolean) => void
  /** Current uncommitted input, including valid addresses awaiting a delimiter or blur. */
  onDraftChange?: (draft: string) => void
}

export function EmailChipsInput({
  values,
  onChange,
  disabled = false,
  id,
  label = 'Invite by email',
  placeholder = 'name@example.com',
  onDraftValidityChange,
  onDraftChange,
}: EmailChipsInputProps) {
  const generatedId = useId()
  const inputId = id ?? `cfs-email-chips-${generatedId}`
  const helpId = `${inputId}-help`
  const errorId = `${inputId}-error`
  const inputRef = useRef<HTMLInputElement>(null)
  const [draft, setDraft] = useState('')
  const [showError, setShowError] = useState(false)

  function updateDraft(next: string) {
    setDraft(next)
    setShowError(false)
    onDraftChange?.(next)
    onDraftValidityChange?.(parseEmailTokens(next).invalid.length === 0)
  }

  function addEmails(candidates: string[]) {
    if (candidates.length) onChange(mergeUniqueEmails(values, candidates))
  }

  function commitDraft() {
    const parsed = parseEmailTokens(draft)
    if (parsed.valid.length) addEmails(parsed.valid)
    const nextDraft = formatEmailTokens(parsed.invalid)
    if (nextDraft === '') {
      setDraft('')
      setShowError(false)
      onDraftChange?.('')
      onDraftValidityChange?.(true)
      return true
    }
    setDraft(nextDraft)
    setShowError(true)
    onDraftChange?.(nextDraft)
    onDraftValidityChange?.(false)
    return false
  }

  function removeEmail(index: number) {
    onChange(values.filter((_, current) => current !== index))
    inputRef.current?.focus()
  }

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.nativeEvent.isComposing) return

    if (event.key === 'Enter' || event.key === ',' || event.key === ';') {
      event.preventDefault()
      commitDraft()
      return
    }

    if (event.key === 'Backspace' && draft === '' && values.length > 0) {
      event.preventDefault()
      removeEmail(values.length - 1)
    }
  }

  function handlePaste(event: ClipboardEvent<HTMLInputElement>) {
    const pasted = event.clipboardData.getData('text')
    if (!/[,;\n\r]/.test(pasted)) return

    event.preventDefault()
    const parsed = parseEmailTokens(draft.trim() ? `${draft},${pasted}` : pasted)
    addEmails(parsed.valid)
    const nextDraft = formatEmailTokens(parsed.invalid)
    setDraft(nextDraft)
    setShowError(parsed.invalid.length > 0)
    onDraftChange?.(nextDraft)
    onDraftValidityChange?.(parsed.invalid.length === 0)
  }

  const hasError = showError && parseEmailTokens(draft).invalid.length > 0

  return (
    <div className="cfs-email-chips">
      {label && <label className="cfs-email-chips__label" htmlFor={inputId}>{label}</label>}
      <div
        className={[
          'cfs-email-chips__control',
          hasError ? 'cfs-email-chips__control--error' : '',
          disabled ? 'cfs-email-chips__control--disabled' : '',
        ].filter(Boolean).join(' ')}
        onClick={() => inputRef.current?.focus()}
      >
        {values.map((email, index) => (
          <span className="cfs-email-chips__chip" key={`${email.toLocaleLowerCase()}-${index}`}>
            <span className="cfs-email-chips__value">{email}</span>
            <button
              type="button"
              className="cfs-email-chips__remove"
              aria-label={`Remove ${email}`}
              disabled={disabled}
              onMouseDown={(event) => event.preventDefault()}
              onClick={(event) => {
                event.stopPropagation()
                removeEmail(index)
              }}
            >
              <span aria-hidden="true">×</span>
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          id={inputId}
          className="cfs-email-chips__input"
          type="text"
          inputMode="email"
          autoComplete="off"
          spellCheck={false}
          value={draft}
          placeholder={values.length === 0 ? placeholder : ''}
          disabled={disabled}
          aria-invalid={hasError}
          aria-describedby={hasError ? `${helpId} ${errorId}` : helpId}
          onChange={(event) => updateDraft(event.target.value)}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          onBlur={commitDraft}
        />
      </div>
      <span className="cfs-email-chips__hint" id={helpId}>Press Enter, comma, or semicolon after each address.</span>
      {hasError && <span className="cfs-email-chips__error" id={errorId} role="alert">Enter a valid email address to add it.</span>}
    </div>
  )
}
