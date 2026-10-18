/*
 * passwordStrength — a tiny, dependency-free strength estimator for the SignUp
 * strength hint. Pure + deterministic so it's trivial to reason about; this is a
 * UX nicety (the real policy lives server-side in the Wire phase), not a gate.
 *
 * Owned by the Auth screen lane (small helper created under src/pages/auth/).
 */
import { MIN_PASSWORD_LENGTH } from '../../api'

export type StrengthLevel = 'empty' | 'weak' | 'fair' | 'good' | 'strong'

export interface PasswordStrength {
  level: StrengthLevel
  /** 0–4, drives the segmented meter fill. */
  score: number
  label: string
  /** StatusDot/meter color token name. */
  tone: 'idle' | 'error' | 'warn' | 'accent' | 'ok'
}

const META: Record<StrengthLevel, Omit<PasswordStrength, 'score'>> = {
  empty: { level: 'empty', label: `At least ${MIN_PASSWORD_LENGTH} characters`, tone: 'idle' },
  weak: { level: 'weak', label: 'Weak — add length or variety', tone: 'error' },
  fair: { level: 'fair', label: 'Fair — keep going', tone: 'warn' },
  // 'good' wears the brand gold so the meter keeps its warm→green ramp
  // (status-busy is now a cool in-progress blue, wrong for a strength scale).
  good: { level: 'good', label: 'Good password', tone: 'accent' },
  strong: { level: 'strong', label: 'Strong password', tone: 'ok' },
}

/**
 * Score = points for length + character-class variety, clamped to 0–4.
 * Intentionally simple; mirrors what users expect from a four-segment meter.
 */
export function estimatePassword(pw: string): PasswordStrength {
  if (!pw) return { ...META.empty, score: 0 }

  let points = 0
  if (pw.length >= MIN_PASSWORD_LENGTH) points += 1
  if (pw.length >= 12) points += 1
  const classes =
    Number(/[a-z]/.test(pw)) +
    Number(/[A-Z]/.test(pw)) +
    Number(/[0-9]/.test(pw)) +
    Number(/[^A-Za-z0-9]/.test(pw))
  if (classes >= 2) points += 1
  if (classes >= 3) points += 1
  // Passwords below the server minimum can never read as more than "weak".
  if (pw.length < MIN_PASSWORD_LENGTH) points = Math.min(points, 1)

  const score = Math.max(1, Math.min(points, 4))
  const level: StrengthLevel =
    score <= 1 ? 'weak' : score === 2 ? 'fair' : score === 3 ? 'good' : 'strong'
  return { ...META[level], score }
}
